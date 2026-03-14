# Examples

Everything here is a one-liner. Describe what you want, get a native binary.

```bash
pip install -e ".[dev]"
gh auth login   # uses your existing GitHub Copilot subscription
```

---

## Start here

```bash
bv build "print hello world to the console" -O hello.exe
.\hello.exe
```
```
Hello, World!
```

```bash
bv build "exit with code 42" -O test.exe
.\test.exe
echo %ERRORLEVEL%
```
```
42
```

---

## System & environment

```bash
bv build "read the USERNAME environment variable and print it" -O whoami.exe
.\whoami.exe
```
```
USERNAME: bryant
```

```bash
bv build "print the computer name and current process ID" -O sysinfo.exe
.\sysinfo.exe
```
```
Computer: BRYANTS-PC
PID: 4821
```

```bash
bv build "count down from 5 to 1, printing each number with a 1 second pause" -O countdown.exe
.\countdown.exe
```
```
5
4
3
2
1
```

---

## File I/O

```bash
echo "hello from a file" > input.txt
bv build "open a file called input.txt and print its contents" -O readfile.exe
.\readfile.exe
```
```
hello from a file
```

```bash
echo "some content" > source.txt
bv build "copy source.txt to dest.txt, then show a MessageBox saying Done" -O copyfile.exe
.\copyfile.exe
# → native Windows dialog appears: "Done"
```

---

## Live HTTP requests

```bash
bv build "fetch the current weather for Seattle from wttr.in and print it" -O weather.exe
.\weather.exe
```
```
Seattle: 🌦  +4°C
```

```bash
bv build "fetch weather for Seattle, London, and Tokyo from wttr.in and print each on its own line" -O weather_multi.exe
.\weather_multi.exe
```
```
Seattle: 🌦  +4°C
London:  ☁️  +6°C
Tokyo:   ⛅️  +8°C
```

```bash
bv build "fetch weather for Seattle from wttr.in, write a styled HTML dashboard, open it in the browser" -O dashboard.exe
.\dashboard.exe
# → browser opens with a styled weather page
```

---

## Self-correcting builds

Add `--run-verify` to have BinaryVibes run the binary after building. If it crashes, it feeds the output back to the LLM and retries automatically.

```bash
bv build "fetch weather for Seattle and print it" -O weather.exe --run-verify
```
```
Building...
✓ Assembled (3891 bytes)
Running to verify...
✓ Verified (exit 0): Seattle: 🌦  +4°C
```

---

## Cross-compilation

```bash
bv build "hello world" --format elf   -O hello    # Linux ELF
bv build "hello world" --format macho -O hello    # macOS Mach-O
bv build "hello world" --format pe    -O hello.exe # Windows PE (default)
```

The generated binary runs natively on the target platform — no runtime, no dependencies.
