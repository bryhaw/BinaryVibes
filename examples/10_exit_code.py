#!/usr/bin/env python3
"""Build a binary that exits with code 42, then verify the exit code is correct."""

import subprocess
import sys
from pathlib import Path

OUTPUT = Path("exit42.exe")
DESCRIPTION = "exit with code 42"


def main():
    print(f"Building {OUTPUT.name}...")
    result = subprocess.run(
        ["bv", "build", DESCRIPTION, "-O", str(OUTPUT)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"\u2717 Build failed\n{result.stderr.strip()}")
        sys.exit(1)

    size_kb = OUTPUT.stat().st_size / 1024
    print(f"\u2713 Built {OUTPUT.name} ({size_kb:.1f} KB)")

    # Verify exit code
    print(f"Running {OUTPUT.name} to verify exit code...")
    verify = subprocess.run([str(OUTPUT)], capture_output=True)
    if verify.returncode == 42:
        print("\u2713 PASS — exit code is 42")
    else:
        print(f"\u2717 FAIL — expected exit code 42, got {verify.returncode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
