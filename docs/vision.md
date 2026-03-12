# BinaryVibes — Vision & Research

## The Thesis

Programming languages exist for human comprehension. Now that LLMs interface with code, their pattern-matching on high-level syntax is a **transitional step**. The end state of "vibe coding" is modifying binary directly — computers talking to computers without the human-readable middleman.

BinaryVibes builds the technology to make this real: an AI-native framework where you describe what you want, and the system analyzes, patches, and synthesizes binaries directly to achieve it.

## Why This Matters

- **Languages are overhead.** Compilation, linking, build systems — all exist to bridge human intent and machine execution. Remove the human-readable layer and you remove entire categories of complexity.
- **LLMs already work with patterns.** Today they pattern-match on source code syntax. Binary has patterns too — calling conventions, instruction idioms, data layout — and an AI that learns those patterns can work at the level that actually runs.
- **Unlocks closed-source modification.** No source needed. Patch any binary, on any platform, for any purpose.

## Research Landscape (March 2026)

### Binary Rewriting Frameworks

| Framework | Type | Strengths | Limitations |
|-----------|------|-----------|-------------|
| **BOLT** (LLVM project) | Static post-link optimizer | Performance optimization, full binary rewrite mode (experimental `-rewrite` flag), section relocation | Traditionally focused on perf, not security/synthesis |
| **RetroWrite** | Static (reassemblable assembly) | Zero-overhead instrumentation, x86_64 + AArch64 | Struggles with stripped/non-PIE binaries |
| **e9patch** | Static rewriter | Highly scalable, programmable, multiple rewriting modes (classic, CFG-recovery, 100% coverage) | x86_64 Linux ELF only |
| **Janitizer** | Hybrid static+dynamic | Full coverage with near-static performance | Complex runtime dependency |
| **BinRec** | Dynamic lifting → LLVM IR | Lifts execution traces to LLVM IR for transformation, deobfuscation, hardening | Requires execution traces |
| **Instrew** | Dynamic → LLVM IR | High-performance runtime instrumentation with process isolation | Runtime overhead |
| **DynamoRIO / Pin** | Dynamic binary instrumentation | Flexible, works on black-box binaries | Higher runtime overhead |

### Core Libraries (What BinaryVibes Uses)

| Library | Role | Why chosen |
|---------|------|-----------|
| **LIEF** | Parse/modify ELF, PE, Mach-O | Best cross-format abstraction; can manipulate sections, imports, symbols, and write back |
| **Capstone** | Disassembly (bytes → instructions) | Multi-arch, battle-tested, Python bindings |
| **Keystone** | Assembly (mnemonics → bytes) | Capstone's sibling — enables round-trip binary↔assembly |
| **Unicorn** | CPU emulation | Verify patched code without executing on real hardware |

### AI + Binary (Emerging Research)

- **APPATCH** — LLM-driven adaptive prompting for binary vulnerability patching without source code. Reasons about vulnerable behaviors and proposes patches on disassembled representations.
- **Lares** — Uses LLMs to detect whether binaries have been patched for specific CVEs by matching patch source features to binary pseudocode.
- **LLM4Decompile** — Open-source LLM that decompiles x86_64 binaries into C. Not direct binary work, but shows LLMs can reason about compiled code.
- **BinMetric** — Benchmark for evaluating LLM understanding of binary code. Highlights that current models have limited but growing binary comprehension.

### Key Challenges

1. **Data/code separation** — Reliably distinguishing data from code in binaries is unsolved for stripped binaries.
2. **Relocation** — Patching code often requires adjusting addresses throughout the binary.
3. **Format complexity** — ELF, PE, and Mach-O all have different section layouts, relocation schemes, and loading semantics.
4. **Verification** — Proving a binary modification is correct (doesn't break functionality) is fundamentally hard. Emulation helps but doesn't cover everything.
5. **Architecture coverage** — Most mature tools only support x86_64. ARM64 support is growing but incomplete.

## Architecture Decision Records

### Python as primary language
Python has the richest ecosystem for binary analysis (Capstone, Keystone, LIEF, Unicorn all have first-class Python bindings). Performance-critical paths can later be extracted to Rust/C extensions. The priority is iteration speed and library access.

### Pipeline: Analysis → Synthesis → Verify
Inspired by compiler passes but operating on binaries instead of source. Each stage is independent and composable:
- **Analysis** reads a binary and produces structured data (instructions, CFG, symbols)
- **Synthesis** takes structured data + intent and produces patches
- **Verify** emulates patched code to validate correctness

### BinaryFile as the central abstraction
One object wraps the raw bytes, LIEF parse tree, detected architecture, and format metadata. Every module accepts and returns `BinaryFile` — this keeps the API surface small and predictable.

### Patches as data
Patches are immutable data objects (`Patch(offset, data, description)`) applied atomically via `apply_patches()`. This makes them composable, serializable, and testable — critical for an AI system that needs to reason about what it's doing.

## Roadmap Ideas

1. **Control flow graph (CFG) analysis** — Map basic blocks and edges from disassembly. Foundation for understanding program behavior.
2. **Symbol resolution** — Resolve imports, exports, and internal symbols across formats.
3. **Intent-to-patch translation** — The AI layer: take a natural language description of desired behavior and produce a `list[Patch]`.
4. **Binary diffing** — Compare two binaries to understand what changed. Essential for learning from examples.
5. **Multi-arch synthesis** — Generate equivalent patches for x86_64, ARM64, etc. from a single intent.
6. **Whole-binary generation** — Synthesize complete minimal binaries from scratch (not just patching existing ones).
