"""End-to-end: init -> create -> chain -> verify, plus every tamper path,
in a real throwaway git repo. A receipt system whose tamper cases were
never seen failing is decoration."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[1]
RECEIPT = PLUGIN / "core" / "receipt.py"


def run(args, cwd, env=None):
    return subprocess.run([sys.executable, str(RECEIPT), *args],
                          cwd=cwd, capture_output=True, text=True, env=env)


def sh(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


@pytest.fixture()
def repo(tmp_path):
    sh("git init -q -b main && git config user.email t@t && git config user.name T",
       tmp_path)
    (tmp_path / "a.py").write_text("print('hi')\n")
    sh("git add -A && git commit -qm 'first change\n\nCo-Authored-By: "
       "Claude <noreply@anthropic.com>\nClaude-Session: https://claude.ai/s/123'",
       tmp_path)
    return tmp_path


def receipts(repo):
    return sorted((repo / ".titan/attestations").rglob("*.json"))


def test_init_creates_gitignored_key(repo):
    r = run(["init"], repo)
    assert r.returncode == 0, r.stderr
    assert (repo / ".titan/key").exists()
    assert ".titan/key" in (repo / ".gitignore").read_text()
    tracked = subprocess.run(["git", "ls-files", ".titan/key"],
                             cwd=repo, capture_output=True, text=True)
    assert tracked.stdout.strip() == ""


def test_init_is_idempotent(repo):
    assert run(["init"], repo).returncode == 0
    key1 = (repo / ".titan/key").read_text()
    assert run(["init"], repo).returncode == 0
    assert (repo / ".titan/key").read_text() == key1  # not rotated silently


def test_create_chain_and_verify_roundtrip(repo):
    run(["init"], repo)
    assert run(["create"], repo).returncode == 0
    r1 = json.loads(receipts(repo)[0].read_text())
    assert r1["schema_version"] == "change-attestation/v1"
    assert r1["prev_receipt_hash"] == "GENESIS"
    assert r1["commit"]["subject"] == "first change"
    assert r1["files"][0]["path"] == "a.py" and "sha256" in r1["files"][0]
    assert r1["attribution"]["session"] == "https://claude.ai/s/123"
    assert r1["attribution"]["co_authored_by"] == ["Claude <noreply@anthropic.com>"]

    (repo / "a.py").write_text("print('bye')\n")
    sh("git add -A && git commit -qm second", repo)
    assert run(["create"], repo).returncode == 0
    rs = [json.loads(p.read_text()) for p in receipts(repo)]
    assert len(rs) == 2
    prevs = {r["prev_receipt_hash"] for r in rs}
    assert "GENESIS" in prevs and r1["receipt_hash"] in prevs  # chained

    v = run(["verify"], repo)
    assert v.returncode == 0, v.stderr
    assert "chain OK: 2" in v.stdout
    assert "does not identify the signer" in v.stdout  # honest limit printed


def test_duplicate_sha_not_rereceipted(repo):
    run(["init"], repo)
    run(["create"], repo)
    assert run(["create"], repo).returncode == 0
    assert len(receipts(repo)) == 1


def test_tampered_content_fails_chain(repo):
    run(["init"], repo)
    run(["create"], repo)
    p = receipts(repo)[0]
    r = json.loads(p.read_text())
    r["files"][0]["sha256"] = "0" * 64  # rewrite history
    p.write_text(json.dumps(r))
    v = run(["verify"], repo)
    assert v.returncode == 1
    assert "does not match recomputed" in v.stderr


def test_tampered_signature_fails(repo):
    run(["init"], repo)
    run(["create"], repo)
    p = receipts(repo)[0]
    r = json.loads(p.read_text())
    r["signature"] = "ab" * 32
    p.write_text(json.dumps(r))
    v = run(["verify"], repo)
    assert v.returncode == 1 and "SIG FAIL" in v.stderr


def test_broken_chain_refuses_extension(repo):
    run(["init"], repo)
    run(["create"], repo)
    p = receipts(repo)[0]
    r = json.loads(p.read_text())
    r["prev_receipt_hash"] = "f" * 64  # dangling prev
    # keep receipt_hash consistent so ONLY the linkage is broken
    import hashlib
    sys.path.insert(0, str(PLUGIN / "core"))
    from canonical import canonical_bytes
    r["receipt_hash"] = hashlib.sha256(canonical_bytes(r)).hexdigest()
    key = bytes.fromhex((repo / ".titan/key").read_text().strip())
    import hmac as _h
    r["signature"] = _h.new(key, r["receipt_hash"].encode(), hashlib.sha256).hexdigest()
    p.write_text(json.dumps(r))
    (repo / "a.py").write_text("x\n")
    sh("git add -A && git commit -qm third", repo)
    c = run(["create"], repo)
    assert c.returncode == 1 and "broken chain" in c.stderr
    v = run(["verify"], repo)
    assert v.returncode == 1


def test_auto_mode_never_breaks_commits(repo, tmp_path):
    # no key -> --auto exits 0 with no output, writes nothing
    r = run(["create", "--auto"], repo)
    assert r.returncode == 0 and r.stdout == "" and not receipts(repo)
    # not even a git repo -> still exit 0
    outside = tmp_path / "not_a_repo"
    outside.mkdir()
    assert run(["create", "--auto"], outside).returncode == 0


def test_create_without_key_fails_loud_when_not_auto(repo):
    r = run(["create"], repo)
    assert r.returncode == 2 and "init first" in r.stderr


def test_verify_without_receipts_fails_loud(repo):
    run(["init"], repo)
    assert run(["verify"], repo).returncode == 2
