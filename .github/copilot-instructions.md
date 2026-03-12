# Copilot Instructions for BinaryVibes

## Project Overview

BinaryVibes is an AI-native framework for direct binary manipulation. The thesis: programming languages are a human abstraction — LLMs should work at the binary/machine-code level. This project builds the tooling to analyze, modify, synthesize, and verify binaries without source code.

## Build & Run

```bash
# Install (dev mode with test/lint tools)
pip install -e ".[dev]"

# CLI entry point
bv info <binary>
bv disasm <binary> --offset 0x1000
```

## Test

```bash
# Full suite
pytest

# Single test file
pytest tests/test_analysis/test_disassembler.py

# Single test by name
pytest -k "test_disassemble_nop"

# With coverage
pytest --cov=binaryvibes
```

## Lint

```bash
# Check
ruff check src/ tests/

# Auto-fix
ruff check --fix src/ tests/

# Format
ruff format src/ tests/
```

## Architecture

The pipeline flows through four layers, all operating on `BinaryFile` (the central object wrapping LIEF-parsed binaries):

```
Analysis → Synthesis → Verify
```

- **`core/`** — Shared primitives: `BinaryFile` (LIEF wrapper), `Arch`/`ArchConfig` (ISA definitions for Capstone/Keystone/Unicorn). Every module depends on core; core depends on nothing internal.
- **`analysis/`** — Read-only inspection: disassembly (Capstone), control flow graphs, symbol resolution. Takes a `BinaryFile`, returns structured data.
- **`synthesis/`** — Write operations: `Assembler` (Keystone-backed mnemonic→bytes), `Patcher` (byte-level patch application). Produces modified binary content.
- **`verify/`** — `Emulator` (Unicorn-backed) runs patched code snippets and checks register/memory state. Used to validate that synthesis produced correct behavior.
- **`cli/`** — Click-based CLI. Thin layer that wires the other modules together. Entry point registered as `bv` in pyproject.toml.

## Key Libraries

| Library | Role | Import pattern |
|---------|------|---------------|
| **LIEF** | Parse/modify ELF, PE, Mach-O binaries | `import lief` — used only in `core/binary.py` |
| **Capstone** | Disassembly (bytes → instructions) | `import capstone` — used in `analysis/` and `core/arch.py` |
| **Keystone** | Assembly (mnemonics → bytes) | `import keystone` — used in `synthesis/` and `core/arch.py` |
| **Unicorn** | CPU emulation for verification | `import unicorn` — used only in `verify/` |

## Conventions

- **`BinaryFile` is the unit of work.** Always load via `BinaryFile.from_path()` or `BinaryFile.from_bytes()`. Don't pass raw `bytes` between modules — wrap them.
- **Architecture is explicit.** Pass `Arch` enum values, not strings. Use `ARCH_CONFIGS[arch]` to get the Capstone/Keystone/Unicorn constants for any architecture.
- **Analysis is read-only, synthesis is write.** Analysis functions never mutate the binary. Synthesis returns new bytes via `apply_patches()` rather than modifying in place.
- **Patches are data, not side effects.** Build a `list[Patch]` and apply them atomically. This makes patches composable and testable.
- **Emulation verifies synthesis.** After synthesizing a patch, run the result through `Emulator.run()` and assert register/memory state.
- **Type hints everywhere.** Use `from __future__ import annotations` in every module. Ruff enforces this.
- **`pyproject.toml` is the single config file.** No `setup.py`, `setup.cfg`, `tox.ini`, or `Makefile`. Ruff, pytest, and build config all live in `pyproject.toml`.
