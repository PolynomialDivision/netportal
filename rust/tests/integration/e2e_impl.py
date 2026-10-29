#!/usr/bin/env python3
"""Runs the whole-path integration test against either implementation (by path, as __main__).

    e2e_impl.py <run dir>         IMPL=python (default) or IMPL=rust NETPORTAL_BIN=<binary>

IMPL=python: tests/integration/e2e.py, unchanged; exactly `python3 tests/integration/e2e.py <run dir>`.
IMPL=rust:   rust/tests/integration/e2e_rust.py: e2e.py with the Rust registry's schema, the
             schema radius of the FreeRADIUS contract and the binary's CLI (`$NETPORTAL_BIN
             offboard`, `init-db`); its header lists every difference.
"""

import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
E2E = {"python": ROOT / "tests" / "integration" / "e2e.py",
       "rust": ROOT / "rust" / "tests" / "integration" / "e2e_rust.py"}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: e2e_impl.py <run dir>")
    impl = os.environ.get("IMPL", "python")
    if impl == "rust" and not os.environ.get("NETPORTAL_BIN"):
        sys.exit("IMPL=rust needs NETPORTAL_BIN")
    script = E2E[impl]
    sys.argv = [str(script), sys.argv[1]]
    runpy.run_path(str(script), run_name="__main__")


if __name__ == "__main__":
    main()
