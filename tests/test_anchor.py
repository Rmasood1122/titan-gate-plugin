"""Push-anchor report + key-less verify (F-T3). Real throwaway git repos.

Runs under pytest (fixtures via tmp_path) and standalone (python tests/test_anchor.py).
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
RECEIPT = PLUGIN / "core" / "receipt.py"


def run(args, cwd):
    return subprocess.run([sys.executable, str(RECEIPT), *args],
                          cwd=cwd, capture_output=True, text=True)


def sh(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def make_repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    repo.mkdir()
    sh("git init -q -b main && git config user.email t@t && git config user.name T", repo)
    (repo / "a.py").write_text("print('hi')\n")
    sh("git add -A && git commit -qm first", repo)
    assert run(["init"], repo).returncode == 0
    assert run(["create"], repo).returncode == 0
    return repo


def make_remote(tmp: Path, repo: Path) -> None:
    bare = tmp / "origin.git"
    sh(f"git init -q --bare -b main {bare}", tmp)
    sh(f"git remote add origin {bare} && git push -q -u origin main", repo)


# ---- anchor states ---------------------------------------------------------
def test_no_upstream_reports_local_only(tmp_path):
    repo = make_repo(tmp_path)
    v = run(["verify"], repo)
    assert v.returncode == 0, v.stderr
    assert "ANCHOR: no upstream remote" in v.stderr
    assert "claim, not evidence" in v.stderr


def test_untracked_receipts_reported(tmp_path):
    repo = make_repo(tmp_path)
    make_remote(tmp_path, repo)          # pushed BEFORE receipts were committed
    v = run(["verify"], repo)
    assert v.returncode == 0, v.stderr
    assert "1 untracked" in v.stderr and "not on origin/main" in v.stderr


def test_committed_not_pushed_reported(tmp_path):
    repo = make_repo(tmp_path)
    make_remote(tmp_path, repo)
    sh("git add .titan/attestations && git commit -qm receipts", repo)
    v = run(["verify"], repo)
    assert v.returncode == 0, v.stderr
    assert "1 committed-not-pushed" in v.stderr


def test_fully_pushed_is_the_only_clean_anchor(tmp_path):
    repo = make_repo(tmp_path)
    make_remote(tmp_path, repo)
    sh("git add .titan/attestations && git commit -qm receipts && git push -q", repo)
    v = run(["verify"], repo)
    assert v.returncode == 0, v.stderr
    assert "ANCHOR: all 1 receipt(s) committed and pushed" in v.stdout
    assert "ANCHOR" not in v.stderr


# ---- F-T3: verify in a clone that has attestations but no key -------------
def test_keyless_verify_checks_structure_and_says_so(tmp_path):
    repo = make_repo(tmp_path)
    make_remote(tmp_path, repo)
    sh("git add .titan/attestations && git commit -qm receipts && git push -q", repo)
    clone = tmp_path / "clone"
    sh(f"git clone -q {tmp_path / 'origin.git'} {clone}", tmp_path)
    assert not (clone / ".titan/key").exists()            # key never travels
    v = run(["verify"], clone)
    assert v.returncode == 2                               # NOT a pass
    assert "chain structure OK: 1 receipt(s)" in v.stdout
    assert "SIGNATURES NOT CHECKED" in v.stderr
    assert "ANCHOR" in v.stdout or "ANCHOR" in v.stderr


def test_keyless_verify_still_fails_closed_on_tamper(tmp_path):
    repo = make_repo(tmp_path)
    p = next((repo / ".titan/attestations").rglob("*.json"))
    r = json.loads(p.read_text()); r["files"][0]["sha256"] = "0" * 64
    p.write_text(json.dumps(r))
    (repo / ".titan/key").unlink()
    v = run(["verify"], repo)
    assert v.returncode == 1 and "CHAIN FAIL" in v.stderr   # structure catches it


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        with tempfile.TemporaryDirectory() as td:
            try:
                fn(Path(td)); print(f"  PASS {fn.__name__}")
            except AssertionError as e:
                failed += 1; print(f"  FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
