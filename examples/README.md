# Examples

Working build commands you can run directly. Each produces a native executable from a plain English description.

## Prerequisites

```bash
pip install -e ".[dev]"
gh auth login   # uses your existing GitHub Copilot subscription — no API key needed
```

---

## Hello World

```bash
bv build "print hello world to the console" -O hello.exe
.\hello.exe
```

## Exit Code

```bash
bv build "exit with code 42" -O test.exe
.\test.exe
echo %ERRORLEVEL%   # 42
```

## Read Environment Variable

```bash
bv build "read the USERNAME environment variable and print it" -O whoami.exe
.\whoami.exe
```

## Countdown Timer

```bash
bv build "count down from 5 to 1, printing each number with a 1 second pause" -O countdown.exe
.\countdown.exe
```

## Read a File

```bash
bv build "open a file called input.txt and print its contents to the console" -O readfile.exe
echo "hello from a file" > input.txt
.\readfile.exe
```

## Copy a File + GUI Confirmation

```bash
bv build "copy a file called source.txt to dest.txt, then show a MessageBox saying Done" -O copy.exe
echo "some content" > source.txt
.\copy.exe
```

## Fetch Live Weather

```bash
bv build "fetch the current weather for Seattle from wttr.in and print it" -O weather.exe
.\weather.exe
# Seattle: 🌦  +4°C
```

## Multi-City Weather

```bash
bv build "fetch weather for Seattle, London, and Tokyo from wttr.in and print each city on its own line" -O weather-multi.exe
.\weather-multi.exe
```

## Weather Dashboard (opens browser)

```bash
bv build "fetch weather for Seattle from wttr.in, format it as a styled HTML page, write to a temp file, and open it in the default browser" -O dashboard.exe
.\dashboard.exe
```

## System Info

```bash
bv build "print the computer name and current process ID" -O sysinfo.exe --run-verify
.\sysinfo.exe
```

---

## Cross-Compilation

All examples above target Windows PE by default. To cross-compile:

```bash
bv build "hello world" --format elf   -O hello       # Linux ELF
bv build "hello world" --format macho -O hello       # macOS Mach-O
bv build "hello world" --format pe    -O hello.exe   # Windows PE (default)
```

---

## Runtime Verification

Add `--run-verify` to any build command to have BinaryVibes run the binary after building and self-correct on crashes:

```bash
bv build "fetch weather for Seattle and print it" -O weather.exe --run-verify
```
