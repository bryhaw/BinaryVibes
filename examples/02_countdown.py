#!/usr/bin/env python3
"""Build a countdown timer that prints 5..4..3..2..1 with pauses."""

import subprocess
import sys
from pathlib import Path

OUTPUT = Path("countdown.exe")
DESCRIPTION = "count down from 5 to 1, printing each number with a 1 second pause"


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


if __name__ == "__main__":
    main()
