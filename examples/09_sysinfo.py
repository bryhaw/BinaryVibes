#!/usr/bin/env python3
"""Build a binary that prints computer name and PID, using --run-verify for self-correction."""

import subprocess
import sys
from pathlib import Path

OUTPUT = Path("sysinfo.exe")
DESCRIPTION = "print the computer name and current process ID"


def main():
    print(f"Building {OUTPUT.name} (with --run-verify)...")
    result = subprocess.run(
        ["bv", "build", DESCRIPTION, "-O", str(OUTPUT), "--run-verify"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"\u2717 Build failed\n{result.stderr.strip()}")
        sys.exit(1)

    size_kb = OUTPUT.stat().st_size / 1024
    print(f"\u2713 Built {OUTPUT.name} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
