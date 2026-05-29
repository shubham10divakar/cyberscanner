#!/usr/bin/env python3
"""
Standalone smoke test runner with colored output and timing.

Usage:
    python smoke_tests/run_smoke_tests.py              # all non-live tests
    python smoke_tests/run_smoke_tests.py --live       # include live OSV API tests
    python smoke_tests/run_smoke_tests.py --only live  # live tests only
    python smoke_tests/run_smoke_tests.py --only cli   # CLI tests only
    python smoke_tests/run_smoke_tests.py --only api   # API tests only
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent

# ANSI colours (work on modern Windows terminals and all Unix)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _color(text: str, *codes: str) -> str:
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(  # type: ignore[attr-defined]
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
        except Exception:
            pass
    return "".join(codes) + text + RESET


def main() -> int:
    args = sys.argv[1:]

    # Parse flags
    include_live = "--live" in args
    only_mark = None
    if "--only" in args:
        idx = args.index("--only")
        only_mark = args[idx + 1] if idx + 1 < len(args) else None

    print(_color("\n  cyberscanner smoke test runner\n", BOLD, CYAN))

    # Build pytest command
    cmd = [sys.executable, "-m", "pytest", str(HERE), "-v", "--tb=short", "--no-header"]

    if only_mark:
        cmd += ["-m", only_mark]
    elif not include_live:
        cmd += ["-m", "smoke and not live"]
    else:
        cmd += ["-m", "smoke"]

    cmd += ["--color=yes"]

    print(_color(f"  Running: {' '.join(cmd[2:])}\n", DIM))

    start = time.time()
    result = subprocess.run(cmd, cwd=str(ROOT))
    elapsed = time.time() - start

    print()
    if result.returncode == 0:
        print(_color(f"  All smoke tests passed in {elapsed:.1f}s\n", GREEN, BOLD))
    else:
        print(_color(f"  Some smoke tests failed (exit {result.returncode}) in {elapsed:.1f}s\n", RED, BOLD))

    print(_color("  Tip: run with --live to include real OSV API calls\n", DIM))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
