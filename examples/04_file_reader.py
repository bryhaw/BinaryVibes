#!/usr/bin/env python3
"""Build a binary that reads input.txt and prints its contents.

Creates a sample input.txt so the demo works out of the box.
"""

import subprocess
import sys
from pathlib import Path

OUTPUT = Path("readfile.exe")
SAMPLE_FILE = Path("input.txt")
DESCRIPTION = "open a file called input.txt and print its contents to the console"


def main():
    # Create sample input file
    SAMPLE_FILE.write_text("Hello from input.txt!\nThis file was read by a BinaryVibes-generated executable.\n")
    print(f"Created {SAMPLE_FILE.name}")

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
