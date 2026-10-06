"""Run the tests' shell one-liners under a POSIX shell on every platform.

The git-backed tests are written in POSIX form: single quotes, `&&`,
`VAR=x cmd` env prefixes. `subprocess.run(cmd, shell=True)` honors that on
Linux/macOS (/bin/sh) but on Windows invokes cmd.exe, which ignores
single-quote grouping and env-prefix syntax — so every git-backed test died
at fixture setup with `pathspec 'change'' did not match any file(s)` and
the maintainer could not run the suite on a Windows machine. Resolve a real
POSIX shell (Git for Windows ships one) and exec the command through it.
"""
import os
import shlex
import shutil
import sys
from pathlib import Path

import pytest


def _find_posix_shell() -> str | None:
    if sys.platform != "win32":
        return shutil.which("sh") or shutil.which("bash") or "/bin/sh"
    # Git for Windows' bash in its usual homes first.
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"),
                 os.environ.get("ProgramFiles(x86)")):
        if base:
            for rel in ("Git/bin/bash.exe", "Git/usr/bin/bash.exe"):
                p = Path(base) / rel
                if p.exists():
                    return str(p)
    # Any bash/sh on PATH (MSYS2, Cygwin) — EXCEPT System32's bash.exe, which
    # is the WSL launcher and would run the command inside a Linux VM where
    # tmp_path does not exist.
    for name in ("bash", "sh"):
        found = shutil.which(name)
        if found and "system32" not in found.lower():
            return found
    return None


POSIX_SHELL = _find_posix_shell()


def shell_argv(cmd: str) -> list[str]:
    """argv that runs `cmd` under a POSIX shell. Skips the test (rather than
    failing with a misleading git error) when no POSIX shell is available."""
    if POSIX_SHELL is None:
        pytest.skip("these tests need a POSIX shell (on Windows: install Git for Windows)")
    return [POSIX_SHELL, "-c", cmd]


def posix(p: Path) -> str:
    """A path safe to interpolate into a shell command string. A Windows path
    (C:\\Users\\...) loses its backslashes inside `bash -c` — they are escape
    characters there — so use forward slashes, which Git for Windows accepts,
    and quote in case the path contains spaces."""
    return shlex.quote(p.as_posix())
