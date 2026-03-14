#!/usr/bin/env python3
"""Build a binary that fetches weather, renders an HTML dashboard, and opens it in the browser."""

import subprocess
import sys
from pathlib import Path

OUTPUT = Path("weather_dashboard.exe")
DESCRIPTION = (
    "fetch weather for Seattle from wttr.in, format it as a styled HTML dashboard page "
    "with a dark background, write to a temp file, and open it in the default browser"
)


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
