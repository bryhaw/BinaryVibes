#!/usr/bin/env python3
"""Run all BinaryVibes example scripts (01-10) and print a summary."""

import subprocess
import sys
from pathlib import Path

EXAMPLES_DIR = Path(__file__).parent

SCRIPTS = sorted(EXAMPLES_DIR.glob("[0-9][0-9]_*.py"))


def main():
    results = []

    for script in SCRIPTS:
        name = script.stem
        print(f"\n{'=' * 60}")
        print(f"Running {script.name}")
        print("=" * 60)

        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=EXAMPLES_DIR,
        )
        passed = result.returncode == 0
        results.append((name, passed))

    # Summary
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    for name, passed in results:
        status = "\u2713 PASS" if passed else "\u2717 FAIL"
        print(f"  {status}  {name}")

    total = len(results)
    passed_count = sum(1 for _, p in results if p)
    print(f"\n{passed_count}/{total} passed")

    if passed_count < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
