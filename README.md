# BinaryVibes

**From natural language to native binary — skipping the high-level compiler.**

BinaryVibes is an LLM-driven synthesis framework that generates working native executables (Windows PE, Linux ELF, macOS Mach-O) directly from English descriptions — without writing C, Rust, Go, or any high-level language. The pipeline goes from intent to x86_64 assembly to machine code bytes to a runnable binary, with a self-correcting feedback loop that catches and fixes both assembly errors and runtime crashes.

```bash
bv build "fetch weather for Seattle, London, and Tokyo and print each"
```
```
Seattle: 🌦  +4°C
London: ☁️  +6°C
Tokyo: ⛅️  +8°C
```

That's a **4KB native PE executable** doing real HTTP requests. No C compiler touched it.

## What "No Compiler" Actually Means (and Doesn't)

This is worth being precise about, because the claim is easy to misread.

**What is skipped:** A high-level language compiler — no GCC, Clang, MSVC, Rust, or Go toolchain. The LLM outputs x86_64 assembly directly, bypassing the entire layer where you'd normally write source code in a human-readable language.

**What still happens:** The pipeline uses Keystone, an assembler library, to translate assembly mnemonics into machine code bytes. Assembling *is* a form of compilation (one-to-one translation of text to opcodes). The PE/ELF/Mach-O builder also does linker-adjacent work: constructing binary headers, import address tables, section layouts, and DLL references. That's not zero toolchain — it's a minimal, purpose-built one.

**The accurate headline:** "No high-level language compiler required" — which is still genuinely novel and interesting.

## The Pipeline

```
Natural language
  → LLM (GPT-4o via GitHub Copilot auth)
  → x86_64 assembly text (with labels, .asciz data, PE runtime helper calls)
  → Keystone assembler → machine code bytes
  → PE/ELF/Mach-O builder (headers, IAT, section layout)
  → native executable
  → [optional] subprocess run → verify exit code + stdout → LLM feedback if wrong
```

The key file is `src/binaryvibes/llm/agent.py` — the `BuildAgent` class orchestrates the full loop. The assembler wraps Keystone directly (`keystone.Ks`), and the PE builder in `synthesis/pe.py` constructs a minimal PE64 with a hardcoded IAT covering 35 Windows API functions across 4 DLLs.

## The Self-Correcting Feedback Loop

This is the genuinely novel part. Most LLM code generation is one-shot. BinaryVibes runs a two-level retry loop:

**Level 1 — Assembly errors:**  
`assemble_with_diagnostics()` tries to assemble the full output. On failure, it bisects line-by-line to find the failing instruction, formats a precise error message (`"Assembly error on line 14: 'mov rax, [rbx+rcx*8+]' — Error: invalid operand"`), and sends it back to the LLM with the original code and error context.

**Level 2 — Runtime crashes:**  
If `--run-verify` is set, the binary is written to a temp file and executed via `subprocess.run()`. If it crashes or returns a wrong exit code, the stdout + exit code are fed back to the LLM as a new recovery prompt. The LLM sees: "You generated this assembly. It ran but crashed with exit code -1 and output: [...]". It then fixes its own logic.

```python
# agent.py — the retry loop (simplified)
for attempt in range(max_retries):
    assembly = llm.generate(messages)
    try:
        code = assembler.assemble_with_diagnostics(assembly)
    except ValueError as asm_error:
        messages = build_error_recovery_messages(assembly, str(asm_error), ...)
        continue  # retry with error context

    binary = builder.build(code)

    if run_verify:
        exit_code, stdout = run_binary(binary)
        if exit_code != 0:
            messages = build_run_error_recovery_messages(assembly, exit_code, stdout)
            continue  # retry with runtime feedback
    break
```

## Pre-Baked Runtime Helpers

The LLM doesn't need to implement `WriteFile`, `WinHttpOpen`, or stack-aligned `MessageBoxA` calls from scratch every time. `pe_runtime.py` contains 14 pre-assembled helper routines that the LLM can call by label:

| Helper | Does |
|--------|------|
| `__bv_print_str` | `WriteFile` to stdout with handle bookkeeping |
| `__bv_http_get` | Full WinHTTP GET → buffer (handles session, connection, request lifecycle) |
| `__bv_msgbox` | `MessageBoxA` with correct stack alignment |
| `__bv_html_dashboard` | Write styled HTML to temp file, open in default browser |
| `__bv_sleep` | `Sleep` with register preservation |
| `__bv_print_num` | 64-bit decimal to stdout (no libc) |
| `__bv_open_url` | `ShellExecuteA` to open URL/file |
| `__bv_get_computer_name` | `GetComputerNameA` wrapper |
| `__bv_get_pid` | `GetCurrentProcessId` |
| `__bv_open_file_read` | `CreateFileA` for reading |
| `__bv_read_file` | `ReadFile` with handle |
| `__bv_write_file_helper` | `CreateFileA` + `WriteFile` |
| `__bv_close_handle` | `CloseHandle` |
| `__bv_print_newline` | CR+LF to stdout |

These are appended to every PE binary. The LLM's prompts explicitly tell it these exist and how to call them. The helpers solve the hardest part of bare-metal x86_64 on Windows: register preservation across Windows API calls, stack 16-byte alignment requirements, and the IAT calling convention.

## The PE Builder

`synthesis/pe.py` constructs a minimal but complete PE64 executable from scratch — no linker involved, but it does every job a linker normally does:

- PE/COFF headers (`IMAGE_NT_HEADERS64`, `IMAGE_OPTIONAL_HEADER64`)
- Two sections: `.text` (code) and `.idata` (import tables)
- Import Address Table (IAT) for 4 DLLs: `kernel32.dll`, `user32.dll`, `winhttp.dll`, `shell32.dll`
- 35 pre-wired API imports at fixed virtual addresses so the LLM can reference them as constants
- Section alignment to `0x1000` (virtual) and `0x200` (file)
- Entry point calculation at `PE_IMAGE_BASE + PE_CODE_RVA`

The IAT is hardcoded rather than dynamically linked — which is why cross-platform builds require generating different helpers for ELF (Linux syscalls) and Mach-O (macOS syscalls).

## Proven Capabilities

All of these build on first attempt with zero retries:

| Program | What it does | Binary size |
|---------|-------------|-------------|
| Hello World | Print to stdout | 2 KB |
| Environment reader | Read `USERNAME`, print | 3 KB |
| Countdown timer | 5→1 with 1s Sleep calls | 3 KB |
| File reader | `CreateFileA` + `ReadFile` + print | 3 KB |
| File copier + GUI | `CopyFileA` + `MessageBoxA` | 3 KB |
| System info | `GetComputerNameA` + `GetCurrentProcessId` + HTTP weather | 4 KB |
| Multi-city weather | 3 WinHTTP GET calls | 4 KB |
| Weather dashboard | HTTP fetch → styled HTML → `ShellExecuteA` | 4 KB |

## Architecture Overview

```
src/binaryvibes/
├── llm/
│   ├── agent.py          — BuildAgent: orchestrates the full LLM→binary→verify loop
│   ├── provider.py       — LLM backends: GitHub Models (Copilot auth), OpenAI, Anthropic
│   ├── prompts.py        — System prompts, error recovery messages, response parsing
│   └── pe_runtime.py     — 14 pre-baked x86_64 helper routines appended to PE output
├── synthesis/
│   ├── assembler.py      — Keystone wrapper with line-level diagnostic bisection
│   ├── pe.py             — PE64 builder: headers, IAT, section layout (Windows)
│   ├── macho.py          — Mach-O builder (macOS)
│   ├── generator.py      — ELF builder + format dispatcher
│   ├── patcher.py        — Immutable patch algebra for binary modification
│   └── transplant.py     — Function extraction + cross-binary transplant
├── analysis/
│   ├── disassembler.py   — Capstone-based multi-arch disassembly
│   ├── cfg.py            — Control-flow graph with basic block decomposition
│   ├── symbols.py        — Symbol resolution across ELF/PE/Mach-O
│   ├── patterns.py       — Binary pattern matching DSL
│   ├── semantics.py      — Semantic lifting (instructions → effects)
│   └── differ.py         — Binary diffing with similarity metrics
├── verify/
│   └── emulator.py       — Unicorn-based CPU emulation for pre-run verification
└── intent/
    └── engine.py         — High-level intent → concrete patch operations
```

## Quick Start

```bash
git clone https://github.com/bryhaw/BinaryVibes
cd BinaryVibes
pip install -e ".[dev]"

# Uses GitHub Copilot auth — no separate API key needed
gh auth login

# Build something simple
bv build "exit with code 42" -O test.exe
.\test.exe && echo %ERRORLEVEL%  # 42

# Build something with HTTP
bv build "fetch weather for Seattle from wttr.in and print it" -O weather.exe
.\weather.exe

# Build with runtime verification (re-runs and self-corrects on crash)
bv build "show computer name and process ID" -O sysinfo.exe --run-verify

# Cross-compile
bv build "hello world" --format elf   -O hello       # Linux
bv build "hello world" --format macho -O hello       # macOS
bv build "hello world" --format pe    -O hello.exe   # Windows
```

## Why This Is Interesting

The interesting claim isn't "no toolchain at all" — it's that an LLM can reliably generate *correct, working* x86_64 assembly for non-trivial programs (HTTP networking, GUI dialogs, file I/O) with no human-written source code and a self-correcting feedback loop that handles its own failures.

The pre-baked helpers solve a real problem: the LLM knows *what* to do (call `WinHttpOpen`, set up the connection, read the response) but consistently gets *how* wrong (wrong register clobbering, misaligned stack before API calls). Wrapping the hard parts in tested helpers and telling the LLM to call them by label is what makes complex programs work on the first attempt.

The result is a working binary in the 2–4KB range, running on bare metal, with no C source file, no Makefile, no `gcc` invocation, and no developer between the description and the executable.

## Security

BinaryVibes generates native machine code from LLM output. See
[SECURITY.md](SECURITY.md) for the full security policy. Key points:

- **`--run-verify` is dangerous.** It executes LLM-generated binaries without
  sandboxing. Only use in disposable environments (VMs, containers).
- **Use `BV_LLM_API_KEY` env var** instead of `--api-key` to avoid leaking
  keys in shell history.
- **Generated binaries have owner-only permissions** (0o700) to prevent
  unauthorized execution.
- **Dependencies are pinned to major version ranges** to limit supply chain risk.

[View on GitHub →](https://github.com/bryhaw/BinaryVibes)
