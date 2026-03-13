# BinaryVibes

**AI-native framework for direct binary manipulation** — bypassing programming languages to work at the machine level.

## Thesis

Programming languages exist for human comprehension. Now that LLMs interface with code, pattern-matching on high-level syntax is a transitional step. The end state is modifying binary directly — achieving results faster by removing the source code middleman.

BinaryVibes is the tooling that makes this possible: analyze, modify, synthesize, and verify binaries without ever touching a `.c`, `.rs`, or `.py` file.

## Quick Start

```bash
# Install in development mode
pip install -e ".[dev]"

# Show binary info
bv info ./some_binary

# Disassemble a region
bv disasm ./some_binary --offset 0x1000 --count 200

# Build a binary from natural language (requires LLM API key)
export BV_LLM_API_KEY=your-key-here
bv build "a program that exits with code 42" --verify

# Multi-OS: auto-detects native format, or specify explicitly
bv build "exit with code 42" --format pe --output test.exe    # Windows PE
bv build "exit with code 42" --format macho --output test      # macOS Mach-O
bv build "exit with code 42" --format elf --output test        # Linux ELF
```

## Architecture

```
Intent (natural language)
    ↓
┌─────────────┐    ┌───────────────┐    ┌────────────┐
│  Analysis    │ →  │  Synthesis    │ →  │  Verify    │
│  (capstone)  │    │  (keystone)   │    │  (unicorn) │
│  disassemble │    │  assemble     │    │  emulate   │
│  CFG / syms  │    │  patch / link │    │  validate  │
└─────────────┘    └───────────────┘    └────────────┘
    ↑                                        ↓
    └──────── BinaryFile (LIEF) ─────────────┘
```

## Stack

| Layer | Library | Purpose |
|-------|---------|---------|
| Format parsing | [LIEF](https://lief.re) | Read/write ELF, PE, Mach-O |
| Binary output | BinaryBuilder | Generate ELF (Linux), PE (Windows), Mach-O (macOS) |
| Disassembly | [Capstone](https://www.capstone-engine.org) | Multi-arch disassembler |
| Assembly | [Keystone](https://www.keystone-engine.org) | Multi-arch assembler |
| Emulation | [Unicorn](https://www.unicorn-engine.org) | CPU emulator for verification |
| LLM integration | [OpenAI](https://openai.com) / [Anthropic](https://anthropic.com) | Natural-language → binary synthesis |
| CLI | [Click](https://click.palletsprojects.com) | Command-line interface |
