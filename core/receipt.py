#!/usr/bin/env python3
"""titan-gate plugin — change-attestation receipts for AI-assisted commits.

Profile: schema_version "change-attestation/v1"
  - Canonicalization: TRS-1 sorted-keys (vendored canonical.py, byte-
    compatible with titan-gate's), exclusions {signature, receipt_hash, ...}.
  - Signing: hmac-sha256-v1 over sha256(canonical_bytes).
  - Chain: vendored chain_state rules — single GENESIS, forks/dangling
    prevs/tampered hashes are hard errors, never guesses.
  - Tree: .titan/attestations/ (its OWN tree; never mixed with a judge-
    receipt chain — mixed profiles in one tree are a hard error upstream).

WHAT A RECEIPT PROVES (and does not — say it exactly like this):
  Proves: this commit's recorded content hashes, in this order, under this
  shared key, have not been altered since the receipt was written.
  Does NOT prove: who held the key (HMAC is a shared secret — anyone with
  the key can re-sign; third-party non-repudiation needs the upstream
  titan-gate Ed25519/TSA profiles), that the change was reviewed, or that
  the attribution trailer is truthful — attribution is copied from the
  commit message, an ATTESTATION by whoever wrote the commit.

Subcommands:
  init                generate .titan/key (hex), gitignore it, refuse if
                      the key would be tracked by git
  create [--auto]     receipt for HEAD; --auto exits 0 silently when the
                      repo has no key (hook mode: never break a commit)
  hook                PostToolUse entry point: reads the Claude Code hook
                      JSON from stdin (hook matchers match TOOL NAMES only,
                      so hooks.json matches "Bash" and THIS filters), no-ops
                      unless the command was a git commit, then = create
                      --auto. Exits 0 on any unparseable input.
  verify              walk .titan/attestations/: chain structure + every
                      signature; exit 0 only if ALL verify. Without a key
                      (a fresh clone): structure is still checked and
                      reported, signatures are declared UNCHECKED, exit 2.
                      Always ends with an ANCHOR line: how many receipts are
                      committed AND pushed — distribution is the only defence
                      against a key-holder rewrite, so verify measures it.

Exit codes: 0 ok · 1 verification/chain failure · 2 usage/config error.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from canonical import canonical_bytes           # noqa: E402
from chain_state import (                       # noqa: E402
    GENESIS, ChainStateError, latest_receipt_hash,
)

SCHEMA = "change-attestation/v1"
SIGNING = "hmac-sha256-v1"
KEY_PATH = Path(".titan/key")
TREE = Path(".titan/attestations")


def die(msg: str, code: int = 2) -> "int":
    print(f"FAIL: {msg}", file=sys.stderr)
    return code


def git(*args: str) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def repo_root() -> Path | None:
    try:
        return Path(git("rev-parse", "--show-toplevel").strip())
    except RuntimeError:
        return None


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(65536), b""):
            h.update(blk)
    return h.hexdigest()


def load_key() -> bytes | None:
    """Read and validate .titan/key. A corrupt or too-short key must never
    sign anything — an empty key would HMAC 'successfully' and produce
    receipts that prove nothing. Returns None after printing FAIL."""
    try:
        key = bytes.fromhex(KEY_PATH.read_text().strip())
    except (ValueError, OSError):
        print(f"FAIL: {KEY_PATH} is not valid hex — corrupt key; restore it "
              f"or rotate (init --force) and disclose the break", file=sys.stderr)
        return None
    if len(key) < 16:
        print(f"FAIL: {KEY_PATH} is too short ({len(key)} bytes) — refusing "
              f"to sign with a weak/empty key", file=sys.stderr)
        return None
    return key


def changed_files(sha: str) -> tuple[list[dict], str, int]:
    """(files, patch, n_parents) for a commit.

    - NUL-separated name-status (-z): git C-quotes non-ASCII/special paths
      in line mode, which turned 'café.py' into '"caf\\303\\251.py"' — a path
      that matches no file, so its content hash was silently DROPPED. An
      attestation tool must never silently skip content.
    - Merge commits diff against the FIRST parent: 'git show' prints the
      combined diff for merges, which is usually empty — a receipt with
      files=[] attests nothing without saying so.
    """
    parents = git("rev-list", "--parents", "-n", "1", sha).split()[1:]
    if len(parents) >= 2:
        raw = git("diff", "--name-status", "-z", f"{sha}^1", sha)
        patch = git("diff", f"{sha}^1", sha)
    else:
        raw = git("show", "--name-status", "-z", "--format=", sha)
        patch = git("show", "--format=", sha)
    files: list[dict] = []
    toks = raw.split("\0")
    i = 0
    while i < len(toks):
        status = toks[i].strip()
        if not status:
            i += 1
            continue
        n_paths = 2 if status[:1] in ("R", "C") else 1  # rename/copy: old, new
        paths = [t for t in toks[i + 1:i + 1 + n_paths]]
        i += 1 + n_paths
        if not paths or not paths[-1]:
            continue
        entry: dict = {"path": paths[-1], "status": status[:1]}
        fp = Path(paths[-1])
        if fp.is_file():
            entry["sha256"] = sha256_file(fp)
        files.append(entry)
    return files, patch, len(parents)


# ---------------------------------------------------------------- init
def cmd_init(args: argparse.Namespace) -> int:
    root = repo_root()
    if root is None:
        return die("not inside a git repository")
    os.chdir(root)
    if KEY_PATH.exists() and not args.force:
        print(f"key exists: {KEY_PATH} (use --force to rotate — old receipts "
              f"then verify only with the OLD key; keep it somewhere safe)")
        return 0
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_text(secrets.token_hex(32) + "\n")
    try:
        KEY_PATH.chmod(0o600)
    except OSError:
        pass  # windows
    gi = Path(".gitignore")
    line = ".titan/key"
    text = gi.read_text() if gi.exists() else ""
    if line not in text.splitlines():
        gi.write_text((text.rstrip("\n") + "\n" if text else "") + line + "\n")
        print(f"gitignore: added {line}")
    # fail-closed: a tracked key is a published key
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", str(KEY_PATH)],
                             capture_output=True)
    if tracked.returncode == 0:
        KEY_PATH.unlink()
        return die(".titan/key is TRACKED by git — untrack it "
                   "(git rm --cached .titan/key) before generating a key", 1)
    print(f"key written: {KEY_PATH} (never commit it; receipts are only as "
          f"private as this key)")
    return 0


# ---------------------------------------------------------------- create
def _attribution(subject_body: str) -> dict:
    """Copy attribution trailers from the commit message — an ATTESTATION
    by the commit author, recorded verbatim, never invented here."""
    co = re.findall(r"^Co-Authored-By:\s*(.+)$", subject_body, re.M)
    ses = re.findall(r"^Claude-Session:\s*(\S+)$", subject_body, re.M)
    out: dict = {"source": "commit-trailers"}
    if co:
        out["co_authored_by"] = co
    if ses:
        out["session"] = ses[0]
    for env in ("CLAUDE_SESSION_ID",):
        if os.environ.get(env):
            out.setdefault("session", os.environ[env])
            out["source"] = "commit-trailers+env"
    return out


def cmd_create(args: argparse.Namespace) -> int:
    root = repo_root()
    if root is None:
        return 0 if args.auto else die("not inside a git repository")
    os.chdir(root)
    if not KEY_PATH.exists():
        if args.auto:
            return 0  # hook mode: repo not initialized — silently do nothing
        return die("no .titan/key — run receipt.py init first")
    key = load_key()
    if key is None:
        return 1  # a corrupt key is a loud failure even in --auto (|| true
                  # protects the commit; silence would hide a broken setup)

    try:
        sha = git("rev-parse", "HEAD").strip()
        branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
        msg = git("log", "-1", "--format=%B", "HEAD")
        subject = msg.splitlines()[0] if msg.splitlines() else ""
        files, patch, n_parents = changed_files(sha)
    except RuntimeError as exc:
        return 0 if args.auto else die(str(exc))

    # skip duplicates (hook may fire twice; amend re-fires): one receipt per sha
    if TREE.exists():
        for p in TREE.rglob("*.json"):
            try:
                if json.loads(p.read_text()).get("commit", {}).get("sha") == sha:
                    if not args.auto:
                        print(f"receipt already exists for {sha[:12]} ({p})")
                    return 0
            except (json.JSONDecodeError, OSError):
                return die(f"unreadable receipt in tree: {p}", 1)

    try:
        prev = latest_receipt_hash(TREE)
    except ChainStateError as exc:
        return die(f"refusing to extend a broken chain: {exc}", 1)

    now = datetime.now(timezone.utc)
    receipt: dict = {
        "schema_version": SCHEMA,
        "signing_version": SIGNING,
        "receipt_id": str(uuid.uuid4()),
        "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root_date": now.strftime("%Y-%m-%d"),
        "repo": Path(root).name,
        "commit": {"sha": sha, "branch": branch, "subject": subject[:200],
                   "parents": n_parents},
        "files": files,
        "diff_sha256": hashlib.sha256(patch.encode()).hexdigest(),
        "attribution": _attribution(msg),
        "prev_receipt_hash": prev,
    }
    receipt["receipt_hash"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    receipt["signature"] = hmac.new(
        key, receipt["receipt_hash"].encode(), hashlib.sha256).hexdigest()

    out = TREE / receipt["root_date"] / f"{receipt['receipt_id']}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"receipt: {out}  commit {sha[:12]}  prev {prev[:12] if prev != GENESIS else GENESIS}")
    return 0


# ---------------------------------------------------------------- hook
GIT_COMMIT_RE = re.compile(r"\bgit\b.*\bcommit\b", re.S)


def cmd_hook(args: argparse.Namespace) -> int:
    """Claude Code PostToolUse entry point. Hook matchers match TOOL NAMES
    only (docs: hooks reference) — a matcher like 'Bash\\(.*commit' NEVER
    fires because the tool name is just 'Bash'. So hooks.json matches every
    Bash call and this reads the hook JSON from stdin to act only on git
    commits. False positives are harmless (create --auto dedupes per sha);
    false negatives lose receipts — so the filter is deliberately loose."""
    try:
        payload = json.load(sys.stdin)
        cmd = (payload.get("tool_input") or {}).get("command") or ""
    except (json.JSONDecodeError, AttributeError, ValueError):
        return 0  # unparseable hook input: never break anything
    if not isinstance(cmd, str) or not GIT_COMMIT_RE.search(cmd):
        return 0
    args.auto = True
    return cmd_create(args)


# ---------------------------------------------------------------- verify
def cmd_verify(args: argparse.Namespace) -> int:
    root = repo_root()
    if root is not None:
        os.chdir(root)
    if not TREE.exists() or not any(TREE.rglob("*.json")):
        return die("no attestations at .titan/attestations/ — nothing to verify")

    # Structure first: it needs no key, so a clone that has the attestations
    # but not the (correctly gitignored) key still gets a real answer.
    try:
        head = latest_receipt_hash(TREE)  # full structural walk, fail-closed
    except ChainStateError as exc:
        print(f"CHAIN FAIL: {exc}", file=sys.stderr)
        return 1
    n = sum(1 for _ in TREE.rglob("*.json"))

    if not KEY_PATH.exists():
        # F-T3: say exactly what was and wasn't checked, then fail closed —
        # structure-only is useful information, not a PASS.
        print(f"chain structure OK: {n} receipt(s), one unbroken line from "
              f"GENESIS, every stored receipt_hash matches its content, head {head[:12]}…")
        print("SIGNATURES NOT CHECKED: no .titan/key in this checkout (it is "
              "gitignored by design). Structure alone proves the files are "
              "internally consistent, not that they were signed under the "
              "team's key. Obtain the key out-of-band to verify signatures.",
              file=sys.stderr)
        _report_anchor()
        return 2
    key = load_key()
    if key is None:
        return 2

    bad = 0
    for p in sorted(TREE.rglob("*.json")):
        r = json.loads(p.read_text())
        want = hmac.new(key, r["receipt_hash"].encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, r.get("signature", "")):
            print(f"SIG FAIL: {p}", file=sys.stderr)
            bad += 1
    if bad:
        print(f"VERDICT: FAIL — {bad}/{n} bad signatures", file=sys.stderr)
        return 1
    print(f"chain OK: {n} receipt(s), head {head[:12]}…")
    print("PASS means: contents unchanged since signing, under this shared "
          "key. It does not identify the signer.")
    _report_anchor()
    return 0


# ---------------------------------------------------------------- anchor
def anchor_status() -> dict:
    """How much of .titan/attestations/ exists outside this working tree.

    HMAC is a shared secret, so the key-holder can rewrite and re-sign the
    whole chain locally and `verify` cannot tell. The defence the README
    promises is DISTRIBUTION: once receipts are committed and pushed, every
    clone holds an independent copy a rewrite would have to chase down.
    This measures whether that defence is actually in place.

    Returns counts: total, untracked, modified (tracked but dirty), unpushed
    (committed locally, not on the upstream), plus `upstream` (name or None).
    Never raises — a repo with no remote just reports unpushed=unknown.
    """
    files = sorted(str(p) for p in TREE.rglob("*.json"))
    out = {"total": len(files), "untracked": 0, "modified": 0,
           "unpushed": None, "upstream": None}
    if not files:
        return out
    st = subprocess.run(["git", "status", "--porcelain", "--", str(TREE)],
                        capture_output=True, text=True)
    for line in st.stdout.splitlines():
        code = line[:2]
        if code == "??":
            out["untracked"] += 1
        elif code.strip():
            out["modified"] += 1
    up = subprocess.run(["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
                        capture_output=True, text=True)
    if up.returncode != 0:
        return out  # no upstream configured: cannot know what is pushed
    out["upstream"] = up.stdout.strip()
    # receipt files touched by commits that are ahead of upstream
    ahead = subprocess.run(["git", "diff", "--name-only", f"{out['upstream']}...HEAD",
                            "--", str(TREE)], capture_output=True, text=True)
    out["unpushed"] = len([l for l in ahead.stdout.splitlines() if l.strip()])
    return out


def _report_anchor() -> None:
    a = anchor_status()
    if a["total"] == 0:
        return
    loose = a["untracked"] + a["modified"] + (a["unpushed"] or 0)
    if a["upstream"] is None:
        print(f"ANCHOR: no upstream remote — {a['total']} receipt(s) exist only in "
              f"this working tree. Against the key-holder, a local-only chain is a "
              f"claim, not evidence: commit and push .titan/attestations/.",
              file=sys.stderr)
    elif loose == 0:
        print(f"ANCHOR: all {a['total']} receipt(s) committed and pushed to "
              f"{a['upstream']} — every clone holds an independent copy.")
    else:
        parts = []
        if a["untracked"]:
            parts.append(f"{a['untracked']} untracked")
        if a["modified"]:
            parts.append(f"{a['modified']} modified-uncommitted")
        if a["unpushed"]:
            parts.append(f"{a['unpushed']} committed-not-pushed")
        print(f"ANCHOR: {', '.join(parts)} of {a['total']} receipt(s) are not on "
              f"{a['upstream']}. Until pushed they are only as trustworthy as this "
              f"machine: `git add .titan/attestations && git commit && git push`.",
              file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init"); p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("create"); p.add_argument("--auto", action="store_true")
    p.set_defaults(fn=cmd_create)
    p = sub.add_parser("hook"); p.set_defaults(fn=cmd_hook, auto=True)
    p = sub.add_parser("verify"); p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
