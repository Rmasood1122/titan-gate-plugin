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
  verify              walk .titan/attestations/: chain structure + every
                      signature; exit 0 only if ALL verify

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
    key = bytes.fromhex(KEY_PATH.read_text().strip())

    try:
        sha = git("rev-parse", "HEAD").strip()
        branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
        msg = git("log", "-1", "--format=%B", "HEAD")
        subject = msg.splitlines()[0] if msg.splitlines() else ""
        names = [ln for ln in git("show", "--name-status", "--format=", "HEAD")
                 .splitlines() if ln.strip()]
        patch = git("show", "--format=", "HEAD")
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

    files = []
    for ln in names:
        parts = ln.split("\t")
        status, path = parts[0], parts[-1]
        entry: dict = {"path": path, "status": status[:1]}
        fp = Path(path)
        if fp.is_file():
            entry["sha256"] = sha256_file(fp)
        files.append(entry)

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
        "commit": {"sha": sha, "branch": branch, "subject": subject[:200]},
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


# ---------------------------------------------------------------- verify
def cmd_verify(args: argparse.Namespace) -> int:
    root = repo_root()
    if root is not None:
        os.chdir(root)
    if not TREE.exists() or not any(TREE.rglob("*.json")):
        return die("no attestations at .titan/attestations/ — nothing to verify")
    if not KEY_PATH.exists():
        return die("no .titan/key — signatures cannot be checked without it")
    key = bytes.fromhex(KEY_PATH.read_text().strip())

    try:
        head = latest_receipt_hash(TREE)  # full structural walk, fail-closed
    except ChainStateError as exc:
        print(f"CHAIN FAIL: {exc}", file=sys.stderr)
        return 1

    n, bad = 0, 0
    for p in sorted(TREE.rglob("*.json")):
        r = json.loads(p.read_text())
        n += 1
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
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init"); p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("create"); p.add_argument("--auto", action="store_true")
    p.set_defaults(fn=cmd_create)
    p = sub.add_parser("verify"); p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
