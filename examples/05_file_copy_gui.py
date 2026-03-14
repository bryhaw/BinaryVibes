#!/usr/bin/env python3
"""Build a binary that copies source.txt to dest.txt and shows a MessageBox.

Creates a sample source.txt so the demo works out of the box.
"""

import subprocess
import sys
from pathlib import Path

OUTPUT = Path("copy_with_dialog.exe")
SAMPLE_FILE = Path("source.txt")
DESCRIPTION = (
    "copy a file called source.txt to dest.txt, "
    "then show a Windows MessageBox saying 'Done!'"
)


def main():
    # Create sample source file
    SAMPLE_FILE.write_text("This is the source file content.\nIt will be copied to dest.txt.\n")
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
