# BinaryVibes

**Natural language to native binary — no compiler, no source code, no build system.**

An AI-native framework that generates working Windows/Linux/macOS executables directly from English descriptions. Describe what you want, get a binary that runs.

```bash
bv build "fetch weather for Seattle, London, and Tokyo and print each"
```
```
Seattle: 🌦  +4°C
London: ☁️  +6°C
Tokyo: ⛅️  +8°C
```

That's a **4KB native executable** that makes HTTP requests over the internet. No compiler was involved.

## The Thesis

Programming languages exist for human comprehension. LLMs don't need them. The end state is going from intent directly to binary — removing every intermediate layer (source code, preprocessor, compiler, linker) between what you want and what the machine runs.

BinaryVibes proves this is viable. An LLM can reliably generate working native executables — including ones that do HTTP networking, GUI dialogs, and file I/O — without ever touching a programming language.

## What It Does

```
"fetch weather and display as an HTML dashboard"
  → GPT-4o (via GitHub Copilot auth — zero config)
  → x86_64 assembly with labels and data
  → Keystone assembler → machine code bytes
  → PE builder (4 DLLs, 35 APIs, import tables)
  → 4KB .exe → run → verify → open browser with styled dashboard
```

### Proven Capabilities

These all build on first attempt with zero retries:

| Program | What it does | Binary size |
|---------|-------------|-------------|
| Hello World | Print to console | 2 KB |
| Environment reader | Read and display USERNAME | 3 KB |
| Countdown timer | 5→1 with 1-second delays | 3 KB |
| File reader | Open, read, print a text file | 3 KB |
| File copier + GUI | Copy a file, show MessageBox confirmation | 3 KB |
| System info | Computer name + PID + live weather | 4 KB |
| Multi-city weather | 3 HTTP fetches (Seattle, London, Tokyo) | 4 KB |
| Weather dashboard | HTTP fetch → styled HTML → opens browser | 4 KB |

### Quick Start

```bash
# Install
pip install -e ".[dev]"

# Uses your GitHub Copilot auth — no API keys needed
gh auth login

# Build something
bv build "a program that exits with code 42" -O test.exe
.\test.exe
echo %ERRORLEVEL%   # 42

# Build something useful
bv build "fetch weather for Seattle from wttr.in and print it" -O weather.exe
.\weather.exe   # Seattle: 🌦  +4°C

# Build with runtime verification (re-runs and self-corrects if it crashes)
bv build "show computer name and PID" -O sysinfo.exe --run-verify

# HTML dashboard (opens in browser)
bv build "fetch weather and display as HTML dashboard" -O dashboard.exe

# Cross-compile
bv build "hello world" --format elf -O hello      # Linux
bv build "hello world" --format macho -O hello     # macOS
bv build "hello world" --format pe -O hello.exe    # Windows
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  "fetch weather for Seattle"                            │  Natural language
├─────────────────────────────────────────────────────────┤
│  LLM Provider (GitHub Models / OpenAI / Anthropic)      │  GPT-4o via gh auth
│  ↓ assembly + .asciz data                               │
│  Comment stripping + PE runtime auto-append             │
│  ↓ clean assembly text                                  │
│  Keystone assembler (line-level error → LLM feedback)   │  Syntax errors retried
│  ↓ machine code bytes                                   │
│  PE/ELF/Mach-O builder (headers + imports + code)       │  Native binary format
│  ↓ .exe / ELF / Mach-O                                 │
│  Runtime verification (run → check → feedback → retry)  │  Crash errors retried
├─────────────────────────────────────────────────────────┤
│  4KB native executable                                  │  Runs on bare metal
└─────────────────────────────────────────────────────────┘
```

### Self-Correcting Feedback Loop

The key innovation beyond basic code generation: **two-level error feedback**.

1. **Assembly errors** → Keystone identifies the failing line → LLM fixes the syntax
2. **Runtime crashes** → subprocess captures the exit code → LLM fixes the logic

The LLM doesn't just generate code — it generates, builds, runs, observes, and fixes. This is what makes complex programs (HTTP, GUI, file I/O) reliable on the first attempt.

## What's Inside

### Binary Generation (the novel part)
| Component | Purpose |
|-----------|---------|
| `llm/provider.py` | LLM backends — GitHub Models (zero config), OpenAI, Anthropic |
| `llm/prompts.py` | Architecture + OS-specific prompts, few-shot examples |
| `llm/agent.py` | Build agent with assembly + runtime feedback loops |
| `llm/pe_runtime.py` | 14 pre-baked assembly helpers (print, HTTP, file I/O, GUI, HTML) |
| `synthesis/pe.py` | PE (Windows) generator — 4 DLLs, 35 API imports |
| `synthesis/macho.py` | Mach-O (macOS) generator |
| `synthesis/generator.py` | ELF (Linux) generator + format dispatcher |

### Binary Analysis (the foundation)
| Component | Purpose |
|-----------|---------|
| `analysis/disassembler.py` | Capstone-based multi-arch disassembly |
| `analysis/cfg.py` | Control-flow graph with basic block decomposition |
| `analysis/symbols.py` | Symbol resolution across ELF/PE/Mach-O |
| `analysis/patterns.py` | Binary pattern matching DSL |
| `analysis/semantics.py` | Semantic lifting (instructions → effects) |
| `analysis/differ.py` | Binary diffing with similarity metrics |
| `synthesis/patcher.py` | Immutable, composable patch algebra |
| `synthesis/transplant.py` | Function extraction and cross-binary transplant |
| `verify/emulator.py` | Unicorn-based CPU emulation |
| `intent/engine.py` | High-level intent → concrete patches |
| `workflows/` | Audit, hardening, hooking, analysis workflows |

### PE Runtime Helpers
Pre-baked assembly routines auto-appended to LLM output. The LLM calls these by name — no need to implement common patterns:

| Helper | Purpose |
|--------|---------|
| `__bv_print_str` | Print null-terminated string to stdout |
| `__bv_print_num` | Print unsigned 64-bit decimal number |
| `__bv_print_newline` | Print CR+LF |
| `__bv_sleep` | Sleep N milliseconds (register-safe) |
| `__bv_http_get` | Fetch a URL via HTTP GET → buffer |
| `__bv_open_file_read` | Open file for reading |
| `__bv_read_file` | Read bytes from file handle |
| `__bv_write_file_helper` | Create and write a file |
| `__bv_close_handle` | Close a file/handle |
| `__bv_msgbox` | Show a Windows MessageBox |
| `__bv_open_url` | Open URL/file in default browser |
| `__bv_html_dashboard` | Wrap text in styled HTML, write to file, open in browser |
| `__bv_get_computer_name` | Get computer name into buffer |
| `__bv_get_pid` | Get current process ID |

## Key Learnings

### What worked
- **Pre-baked runtime helpers are essential.** The LLM can generate correct control flow and API call sequences, but struggles with low-level details (register preservation across Windows API calls, stack alignment). Wrapping common patterns in tested helpers dramatically improved reliability.
- **Two-level error feedback closes the loop.** Assembly syntax errors AND runtime crashes both feed back to the LLM. This is what makes complex programs work on the first attempt.
- **Comment stripping matters.** LLMs persistently add `;` comments despite being told not to. Stripping them automatically eliminated a whole class of assembly failures.
- **Few-shot examples are the most effective prompt engineering.** More context about APIs helped, but working examples of complete programs drove the biggest quality improvement.
- **Labels and .asciz directives were the string handling unlock.** Initially we banned directives for simplicity. Allowing them made string data trivial and was the single biggest capability unlock.
- **GitHub Models API for zero-config auth.** Using `gh auth token` means users don't need to manage separate API keys. This removes the biggest friction from the user experience.

### What's hard
- **String building in assembly is the LLM's ceiling.** Constructing strings dynamically (concatenation, number formatting, buffer management) is where the LLM consistently struggles. The solution was pre-baked helpers, not better prompts.
- **Windows x64 calling convention is unforgiving.** Shadow space, stack alignment, callee-saved vs caller-saved registers — one mistake and the binary crashes with no useful error message. The runtime helpers abstract this away.
- **JSON response format vs. assembly content.** HTML strings with quotes inside assembly inside JSON is a quoting nightmare. We solved this with the `__bv_html_dashboard` helper that bakes the template into the runtime.

## What's Next

### Near-term: Expand API surface
More DLLs (ws2_32.dll for raw sockets, advapi32.dll for registry/crypto), more helpers (`__bv_json_get_value`, `__bv_tcp_connect`), multi-pass generation where the agent builds functions separately and stitches them.

### Medium-term: Embedded C compilation
The real ceiling is that LLMs are mediocre at raw assembly for complex logic but excellent at C. Embedding [TinyCC](https://bellard.org/tcc/) (a C compiler that fits in 100KB) would let the LLM generate C for the logic while BinaryVibes handles everything else — PE headers, import tables, runtime linking. Still no external toolchain. Still a single `pip install`.

### Long-term: Binary-native AI
- Train on compiled binaries to learn machine code idioms directly
- Cross-binary function transplantation (the framework already supports this)
- AI-driven binary optimization (like [BOLT](https://github.com/llvm/llvm-project/tree/main/bolt) but learned)
- Decompile → modify → recompile workflows for closed-source software

## Development

```bash
pip install -e ".[dev]"    # Install with all dev + LLM dependencies
pytest tests/ -v           # 663 tests
ruff check src/ tests/     # Lint
bv --help                  # CLI reference
```

## Stack

| Layer | Library | Purpose |
|-------|---------|---------|
| Format parsing | [LIEF](https://lief.re) | Read/write ELF, PE, Mach-O |
| Binary output | BinaryBuilder | Generate ELF, PE, Mach-O from scratch |
| Disassembly | [Capstone](https://www.capstone-engine.org) | Multi-arch disassembler |
| Assembly | [Keystone](https://www.keystone-engine.org) | Multi-arch assembler |
| Emulation | [Unicorn](https://www.unicorn-engine.org) | CPU emulator for verification |
| LLM | GitHub Models / OpenAI / Anthropic | Natural language → assembly |
| HTTP (runtime) | WinInet (kernel32) | Baked into generated binaries |
| GUI (runtime) | user32 / shell32 | MessageBox, ShellExecute in generated binaries |
| CLI | [Click](https://click.palletsprojects.com) | Command-line interface |

## License

MIT
