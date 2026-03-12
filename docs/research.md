# BinaryVibes — Deep Research Notes (July 2025)

Actionable findings across 8 topic areas for building an AI-native binary manipulation framework.

---

## 1. Binary Rewriting Frameworks (2025 State of the Art)

### BOLT (Binary Optimization and Layout Tool)
- **Status**: Part of LLVM; most mature post-link optimizer.
- **2025 update**: New `-rewrite` mode enables full binary rewriting — relocates all sections, improves compatibility with `strip`/`objcopy`. Enhanced AArch64 support, better PLT/GOT handling.
- **Strengths**: Production-grade (deployed at Meta), profile-guided layout optimization, works on large binaries.
- **Limitation**: Requires relocation info or profiling data; not designed for arbitrary patching.
- **Ref**: https://discourse.llvm.org/t/bolt-rfc-a-new-mode-to-rewrite-entire-binary/68674

### RetroWrite
- **Approach**: Lifts PIE binaries to reassembleable assembly → instrument → reassemble.
- **Strengths**: Enables binary-only AddressSanitizer, modular instrumentation passes.
- **Limitations**: x86-64 only, requires position-independent executables, struggles with C++ exceptions and stripped binaries.
- **Ref**: https://github.com/HexHive/retrowrite

### e9patch
- **Approach**: Static binary rewriting *without* control-flow recovery (CFR). Uses instruction-level patching and trampoline insertion.
- **Strengths**: Most robust for large/complex binaries. Supports Linux ELF + Windows PE, PIE and non-PIE. JSON-RPC API for programmatic control.
- **Ecosystem**: e9AFL (coverage-guided fuzzing), e9syscall (syscall monitoring).
- **Ref**: https://github.com/GJDuck/e9patch

### BinRec
- **Approach**: Dynamic binary lifting — runs the binary, records execution traces, lifts to LLVM IR, recompiles.
- **Strengths**: Produces compiler-level IR enabling standard LLVM optimizations/passes.
- **Limitations**: Coverage-dependent (only lifts executed paths), pointer analysis remains imprecise.
- **Ref**: https://github.com/JuliusNmwormo/binrec

### Instrew
- **Approach**: Instrumentation-based dynamic binary translation using LLVM.
- **Status**: Research prototype; demonstrates ISA-agnostic rewriting via lifting + recompilation.

### Emerging Trends
- **Hybrid static+dynamic**: Combine static rewriting with dynamic traces for correctness.
- **Cross-ISA**: Active research on ARM↔x86 binary translation (RISC-V growing).
- **LLM-assisted**: Early work on using LLMs to identify safe patch points and automate instrumentation.

### Actionable for BinaryVibes
- Use **LIEF** for parsing + section manipulation, **e9patch** techniques for robust patching without CFR.
- For IR-level analysis, consider lifting via **BinRec/revng** to LLVM IR.
- Don't depend on perfect disassembly — design for graceful degradation.

---

## 2. AI + Binary Analysis Research

### APPATCH (USENIX Security 2025)
- **What**: Automated vulnerability patching via LLM adaptive prompting.
- **Key innovation**: No fine-tuning needed — uses vulnerability-semantics reasoning + adaptive prompts to guide GPT-3/4 in generating patches.
- **Results**: 28% better F1, 182% better recall vs. prior methods on 97 zero-day + 20 known vulns.
- **Note**: Currently targets source-code patching; the prompting methodology is transferable to binary-level decompiled code.
- **Ref**: https://arxiv.org/abs/2408.13597

### Lares (ASE 2025)
- **What**: LLM-driven "Code Slice Semantic Search" for patch presence testing in binaries.
- **Approach**: Extracts features from patch source code → matches semantically equivalent slices in decompiled binary pseudocode using LLMs + SMT solvers.
- **First** to evaluate patch presence across optimization levels, architectures, and compilers.
- **Ref**: https://github.com/Siyuan-Li201/Lares

### LLM4Decompile
- **What**: Open-source LLM series (1.3B–22B params) for decompiling x86_64 → C.
- **Latest**: SK²Decompile (structure recovery + identifier naming pipeline). V2 models: +40% re-executability improvement.
- **Dataset**: Decompile-Bench — 2M binary-source function pairs from 100M candidates.
- **Ref**: https://github.com/albertan017/LLM4Decompile

### BinMetric (IJCAI 2025)
- **What**: First comprehensive benchmark for LLM binary analysis — 1,000 questions across 6 tasks (decompilation, summarization, assembly synthesis, binary lifting, etc.) from 20 real-world projects.
- **Finding**: LLMs promising but struggle with assembly synthesis and precise binary lifting.
- **Ref**: https://www.ijcai.org/proceedings/2025/0858.pdf

### Other Notable Work
- **Binary Diff Summarization via LLMs** (arXiv 2509.23970): Using LLMs to generate natural-language summaries of binary diffs.
- **BAR 2025 Workshop** (NDSS co-located): Latest papers on AI for binary analysis.
- **Binary Code Similarity Detection (BCSD)**: Comprehensive ScienceDirect survey covering LLM-driven approaches.

### Actionable for BinaryVibes
- Integrate **LLM4Decompile** models for decompilation-on-demand.
- Adopt **APPATCH**-style adaptive prompting for suggesting binary patches via decompiled pseudocode.
- Use **BinMetric** as evaluation harness for any LLM-based analysis features.
- **Lares**'s approach is directly applicable: "did this patch get applied to this binary?"

---

## 3. LIEF Library — Binary Parsing & Modification

### Installation
```bash
pip install lief  # Latest: supports ELF, PE, Mach-O, OAT, DEX, VDEX, ART
```

### Universal Parsing
```python
import lief

binary = lief.parse("/path/to/binary")  # Auto-detects format
print(type(binary))  # lief.ELF.Binary, lief.PE.Binary, or lief.MachO.Binary
```

### ELF Operations
```python
elf = lief.ELF.parse("/bin/ls")

# Header
print(f"Entry: {elf.header.entrypoint:#x}")
print(f"Machine: {elf.header.machine_type}")

# Sections
for s in elf.sections:
    print(f"  {s.name:20s}  addr={s.virtual_address:#x}  size={s.size}")

# Segments (program headers)
for seg in elf.segments:
    print(f"  {seg.type}  vaddr={seg.virtual_address:#x}  filesz={seg.physical_size}")

# Imports (dynamic symbols)
for sym in elf.imported_symbols:
    print(f"  import: {sym.name}")

# Exports
for fn in elf.exported_functions:
    print(f"  export: {fn.name} @ {fn.address:#x}")

# Modify entry point
elf.header.entrypoint = 0x401000

# Add a new section
new_sec = lief.ELF.Section(".injected")
new_sec.content = list(b"\xcc" * 0x100)  # INT3 sled
new_sec.type = lief.ELF.Section.TYPE.PROGBITS
new_sec.flags = lief.ELF.Section.FLAGS.EXECINSTR | lief.ELF.Section.FLAGS.ALLOC
elf.add(new_sec)

# Write modified binary
elf.write("ls.patched")
```

### PE Operations
```python
pe = lief.PE.parse("program.exe")

# Imports
for imp in pe.imports:
    print(f"Library: {imp.name}")
    for entry in imp.entries:
        print(f"  {entry.name or f'ordinal={entry.data}'}")

# Exports
if pe.has_exports:
    for exp in pe.get_export().entries:
        print(f"  export: {exp.name} @ {exp.address:#x}")

# Add section
sec = lief.PE.Section(".patch")
sec.content = [0x90] * 0x200  # NOP sled
sec.characteristics = (lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
                       lief.PE.Section.CHARACTERISTICS.MEM_READ)
pe.add_section(sec)
pe.write("program.patched.exe")
```

### Mach-O Operations
```python
fat = lief.MachO.parse("/usr/bin/ls")
macho = fat.at(0)  # First slice

for sym in macho.symbols:
    print(f"  {sym.name}  value={sym.value:#x}")

for sec in macho.sections:
    print(f"  {sec.name}  addr={sec.virtual_address:#x}")
```

### Actionable for BinaryVibes
- Use `lief.parse()` as the universal entry point — auto-detects format.
- LIEF handles write-back correctly (recalculates offsets, sizes, checksums).
- For BinaryVibes, wrap LIEF in a format-agnostic `BinaryView` abstraction.

---

## 4. Capstone + Keystone — Disassembly & Assembly

### Installation
```bash
pip install capstone keystone-engine
```

### Capstone — Disassembly
```python
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_ARM

# x86_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
code = b"\x55\x48\x89\xe5\x48\x83\xec\x10"
for insn in md.disasm(code, 0x1000):
    print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")
# Output:
#   0x1000: push     rbp
#   0x1001: mov      rbp, rsp
#   0x1004: sub      rsp, 0x10

# ARM64 (AArch64)
md64 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
arm_code = b"\xff\x43\x00\xd1\xfd\x7b\x01\xa9"
for insn in md64.disasm(arm_code, 0x0):
    print(f"  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}")

# Lite mode (faster, returns tuples)
for addr, size, mnemonic, op_str in md.disasm_lite(code, 0x1000):
    print(f"  {addr:#x}: {mnemonic} {op_str}")
```

### Keystone — Assembly
```python
from keystone import Ks, KS_ARCH_X86, KS_ARCH_ARM64, KS_MODE_64, KS_MODE_LITTLE_ENDIAN

# x86_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm("push rbp; mov rbp, rsp; sub rsp, 0x10")
print(f"Assembled {count} instructions: {bytes(encoding).hex()}")

# ARM64
ks64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
encoding, count = ks64.asm("mov x0, #42; ret")
print(f"Assembled {count} instructions: {bytes(encoding).hex()}")

# Assemble with base address (for relative references)
encoding, count = ks.asm("jmp 0x1020", addr=0x1000)
```

### Architecture Constants Reference
| Architecture | Capstone Arch | Capstone Mode | Keystone Arch | Keystone Mode |
|---|---|---|---|---|
| x86-64 | `CS_ARCH_X86` | `CS_MODE_64` | `KS_ARCH_X86` | `KS_MODE_64` |
| x86-32 | `CS_ARCH_X86` | `CS_MODE_32` | `KS_ARCH_X86` | `KS_MODE_32` |
| ARM64 | `CS_ARCH_ARM64` | `CS_MODE_ARM` | `KS_ARCH_ARM64` | `KS_MODE_LITTLE_ENDIAN` |
| ARM32 | `CS_ARCH_ARM` | `CS_MODE_ARM` | `KS_ARCH_ARM` | `KS_MODE_ARM` |

### Actionable for BinaryVibes
- Create `Disassembler(arch, mode)` and `Assembler(arch, mode)` wrappers.
- Use `disasm_lite()` for bulk processing, full `disasm()` for detailed analysis.
- Capstone is 3–5× faster than IDA for batch disassembly.

---

## 5. Unicorn Engine — CPU Emulation

### Installation
```bash
pip install unicorn
```

### Core Setup Pattern
```python
from unicorn import Uc, UC_ARCH_X86, UC_ARCH_ARM64, UC_MODE_64, UC_MODE_ARM
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INTR
from unicorn.x86_const import *
from unicorn.arm64_const import *

# === x86_64 Emulator ===
emu = Uc(UC_ARCH_X86, UC_MODE_64)

# Memory mapping (must be page-aligned, typically 0x1000)
CODE_ADDR = 0x10_0000
CODE_SIZE = 0x10_000  # 64KB
STACK_ADDR = 0x20_0000
STACK_SIZE = 0x10_000

emu.mem_map(CODE_ADDR, CODE_SIZE)    # Code segment
emu.mem_map(STACK_ADDR, STACK_SIZE)  # Stack

# Load code
code = b"\x48\xc7\xc0\x3c\x00\x00\x00"  # mov rax, 60 (sys_exit)
emu.mem_write(CODE_ADDR, code)

# Set registers
emu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 8)
emu.reg_write(UC_X86_REG_RBP, STACK_ADDR + STACK_SIZE - 8)

# Read registers
rax = emu.reg_read(UC_X86_REG_RAX)
```

### ARM64 Setup
```python
emu_arm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
emu_arm.mem_map(0x10000, 0x10000)
arm_code = b"\x40\x05\x80\xd2"  # mov x0, #42
emu_arm.mem_write(0x10000, arm_code)
emu_arm.emu_start(0x10000, 0x10000 + len(arm_code))
print(emu_arm.reg_read(UC_ARM64_REG_X0))  # 42
```

### Hook Callbacks
```python
# Instruction trace hook
def hook_code(uc, address, size, user_data):
    print(f"  exec {address:#x} ({size} bytes)")

# Memory access hook
def hook_mem_access(uc, access, address, size, value, user_data):
    if access == unicorn.UC_MEM_WRITE:
        print(f"  mem write {address:#x} = {value:#x} ({size}B)")
    else:
        print(f"  mem read  {address:#x} ({size}B)")

# Interrupt/syscall hook
def hook_intr(uc, intno, user_data):
    print(f"  interrupt {intno}")
    uc.emu_stop()

emu.hook_add(UC_HOOK_CODE, hook_code)
emu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)
emu.hook_add(UC_HOOK_INTR, hook_intr)

# Run emulation
emu.emu_start(CODE_ADDR, CODE_ADDR + len(code))
# Optional: limit by count or timeout
# emu.emu_start(CODE_ADDR, CODE_ADDR + len(code), timeout=5_000_000, count=100)
```

### Memory Read/Write
```python
# Read memory
data = emu.mem_read(CODE_ADDR, 16)

# Write memory
emu.mem_write(0x200000, b"\x00" * 0x100)
```

### Actionable for BinaryVibes
- Use Unicorn for snippet-level emulation (verify patches, test basic blocks).
- Combine: LIEF (parse) → Capstone (disasm) → modify → Keystone (asm) → Unicorn (verify) → LIEF (write).
- Hook syscalls/interrupts to stub OS interactions during emulation.
- Memory must be page-aligned (0x1000 boundary).

---

## 6. CFG Construction from Disassembly

### Basic Block Detection Algorithm
```
Input: list of (address, instruction) pairs from linear/recursive disassembly
Output: set of BasicBlocks, set of Edges

1. Identify LEADERS:
   a. First instruction of the function
   b. Target of any branch/jump instruction
   c. Instruction immediately after a branch/jump/call/return
   
2. Split instruction stream at leader boundaries → basic blocks

3. For each block, classify the TERMINATOR (last instruction):
   - Unconditional jump  → single edge to target
   - Conditional branch  → two edges: target + fall-through
   - Call instruction    → edge to callee + fall-through to next
   - Return instruction  → edge back to call sites (interprocedural)
   - Fall-through        → edge to next sequential block
```

### Edge Classification
| Edge Type | Condition | Example |
|---|---|---|
| **Fall-through** | Block doesn't end with unconditional jump | Sequential flow |
| **Direct branch** | Target address is immediate operand | `jmp 0x4010a0`, `b label` |
| **Conditional branch** | Two edges: taken + fall-through | `jz 0x4010a0` |
| **Indirect branch** | Target computed at runtime | `jmp rax`, `br x8` |
| **Call** | Direct or indirect function call | `call printf`, `blr x0` |
| **Return** | Returns to caller | `ret`, `retq` |

### Handling Indirect Jumps (Hardest Problem)
1. **Static heuristics**: Pattern-match jump tables (`jmp [rax*8 + table]`).
2. **Data-flow analysis**: Track register values backwards to resolve targets.
3. **Symbolic execution**: Use angr/Triton to symbolically determine possible targets.
4. **Dynamic feedback**: Instrument + run binary, record actual targets, merge into CFG.
5. **Iterative refinement**: Discover new blocks → re-analyze → expand CFG.

### Best Practices
- Start with **recursive descent** disassembly (follows control flow) rather than linear sweep.
- Use **angr** (`CFGFast` for speed, `CFGEmulated` for accuracy) as reference implementation.
- Represent CFG with **NetworkX** `DiGraph` — nodes are `(start_addr, end_addr)` tuples.
- Over-approximate cautiously: spurious edges bloat the graph and hurt analysis.
- For BinaryVibes: implement `CFGBuilder` that takes a `Disassembler` and produces a NetworkX graph.

### Reference Tools
- **angr**: `project.analyses.CFGFast()` — best open-source CFG recovery.
- **Ghidra**: Built-in CFG via PCode IR.
- **Turna**: Hybrid CFG reconstruction for RISC-V.

---

## 7. Binary Diffing Techniques

### Core Concept
Compare two binaries structurally by matching functions/basic-blocks across versions, independent of raw byte differences (which change with every recompilation).

### BinDiff (Google)
- **Approach**: Graph-based function matching using CFG/call-graph structure + instruction features.
- **Algorithm**: Multi-pass heuristic matching:
  1. Match functions by name/hash (trivial matches).
  2. Match by CFG structure (basic block count, edge count, graph topology).
  3. Match by instruction-mnemonic histograms and prime-product hashing.
  4. Match basic blocks within matched functions using the same structural approach.
- **Output**: SQLite database with match scores and confidence.
- **Integration**: IDA plugin, Ghidra plugin, standalone CLI.
- **Ref**: https://github.com/google/bindiff

### Diaphora
- **Approach**: Dozens of heuristics organized by confidence tier.
  - **Best**: Identical pseudocode hash, identical CFG hash.
  - **Partial**: Similar pseudocode, similar CFG structure, shared constants/strings.
  - **Unreliable**: Heuristic-only matches based on partial features.
- **Extras**: Pseudocode diffing, scripting via Python, parallel matching.
- **Ref**: https://diaphora.re/

### BinSlayer
- **Approach**: Reformulates diffing as weighted bipartite graph matching, solved via the Hungarian algorithm (O(n³)).
- **Advantage**: Handles "almost identical" functions better than greedy heuristics.

### AI-Assisted Diffing (2025)
- **Binary Diff Summarization** (arXiv 2509.23970): LLMs generate natural-language explanations of what changed between two binary versions.
- **Ghidra + AI plugins**: Automated triage of diff results by security relevance.

### Implementing a Basic Differ
```
1. Parse both binaries → extract function list (name, address, size)
2. For each function → build CFG → compute structural fingerprint:
   - (num_blocks, num_edges, cyclomatic_complexity)
   - Mnemonic histogram: Counter of instruction types
   - String/constant references
3. Match functions:
   a. Exact name match (if symbols present)
   b. Exact structural fingerprint match
   c. Fuzzy match using similarity score (Jaccard on mnemonic sets, etc.)
4. For matched functions, diff at basic-block level
5. Report: added, removed, modified functions + block-level changes
```

### Actionable for BinaryVibes
- Implement structural fingerprinting per-function (mnemonic histogram + CFG shape).
- Use bipartite matching (scipy `linear_sum_assignment`) for function alignment.
- Provide diff output as structured data (JSON) for LLM summarization.

---

## 8. Whole-Binary Synthesis

### Yes, It's Possible
Minimal ELF and PE binaries can be generated entirely from scratch. LIEF makes this practical.

### Minimal ELF (x86_64 Linux) — From Bytes
```python
import struct

# ELF header (64-bit, little-endian, x86_64)
elf_header = (
    b'\x7fELF'           # e_ident magic
    b'\x02'              # EI_CLASS: 64-bit
    b'\x01'              # EI_DATA: little-endian
    b'\x01'              # EI_VERSION
    b'\x00' * 9          # EI_OSABI + padding
    + struct.pack('<HHI', 2, 0x3E, 1)           # e_type=EXEC, e_machine=x86_64, e_version
    + struct.pack('<QQQI', 0x400078, 0x40, 0, 0) # e_entry, e_phoff, e_shoff, e_flags
    + struct.pack('<HHHHHH', 64, 56, 1, 0, 0, 0) # sizes and counts
)

# Program header (single PT_LOAD segment)
prog_header = struct.pack('<IIQQQQQQ',
    1,           # p_type = PT_LOAD
    5,           # p_flags = PF_X | PF_R
    0,           # p_offset
    0x400000,    # p_vaddr
    0x400000,    # p_paddr
    0x200,       # p_filesz (will adjust)
    0x200,       # p_memsz
    0x1000,      # p_align
)

# Code: mov rax, 60; xor rdi, rdi; syscall  (exit(0))
code = b'\x48\xc7\xc0\x3c\x00\x00\x00' \
       b'\x48\x31\xff' \
       b'\x0f\x05'

# Assemble binary
binary = elf_header + prog_header
binary += b'\x00' * (0x78 - len(binary))  # Pad to entry point offset
binary += code
binary += b'\x00' * (0x200 - len(binary)) # Pad to segment size

with open('minimal', 'wb') as f:
    f.write(binary)
# chmod +x minimal && ./minimal; echo $?  → 0
```

### Using LIEF (Recommended for Production)
```python
import lief

# Create ELF from scratch
elf = lief.ELF.Binary("synth", lief.ELF.ELF_CLASS.CLASS64)

# Add executable section with code
section = lief.ELF.Section(".text")
section.type = lief.ELF.Section.TYPE.PROGBITS
section.flags = lief.ELF.Section.FLAGS.EXECINSTR | lief.ELF.Section.FLAGS.ALLOC
section.content = list(b'\x48\xc7\xc0\x3c\x00\x00\x00\x48\x31\xff\x0f\x05')
elf.add(section, loaded=True)

# Set entry point
elf.header.entrypoint = section.virtual_address

elf.write("synth_elf")
```

### Minimal PE (Windows) via LIEF
```python
import lief

pe = lief.PE.Binary("synth", lief.PE.PE_TYPE.PE32_PLUS)  # 64-bit

# .text section with code
section = lief.PE.Section(".text")
section.content = list(b'\xb8\x00\x00\x00\x00\xc3')  # mov eax, 0; ret
section.virtual_address = 0x1000
section.characteristics = (
    lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
    lief.PE.Section.CHARACTERISTICS.MEM_READ |
    lief.PE.Section.CHARACTERISTICS.CNT_CODE
)
pe.add_section(section)
pe.optional_header.addressof_entrypoint = 0x1000

pe.write("synth.exe")
```

### What You Need for a Valid Binary
| Component | ELF | PE |
|---|---|---|
| **Magic/Signature** | `\x7fELF` | `MZ` + `PE\0\0` |
| **File header** | ELF header (64 bytes for ELF64) | COFF header (20 bytes) |
| **Optional header** | N/A | PE Optional Header (240 bytes for PE32+) |
| **Program/Section headers** | ≥1 PT_LOAD segment | ≥1 section (.text) |
| **Code at entry point** | Machine code at `e_entry` | Machine code at `AddressOfEntryPoint` |
| **Alignment** | Pages (0x1000) | File alignment (0x200), section alignment (0x1000) |

### Actionable for BinaryVibes
- Use LIEF for binary synthesis — it handles header calculation, alignment, and checksums.
- For maximum control, hand-craft bytes (useful for tiny payloads, shellcode containers).
- Validate output with `readelf -a` (ELF) or `dumpbin /headers` (PE).
- This enables BinaryVibes to *produce* binaries, not just analyze/modify them.

---

## Summary — Recommended Technology Stack for BinaryVibes

| Layer | Tool | Purpose |
|---|---|---|
| **Parsing** | LIEF | Read/write ELF, PE, Mach-O |
| **Disassembly** | Capstone | Bytes → instructions (multi-arch) |
| **Assembly** | Keystone | Mnemonics → bytes (multi-arch) |
| **Emulation** | Unicorn | CPU emulation for verification |
| **CFG** | Custom + NetworkX | Control flow graph construction |
| **Diffing** | Custom (structural fingerprints) | Binary comparison |
| **AI/LLM** | LLM4Decompile, GPT-4 | Decompilation, patch suggestion |
| **Rewriting** | e9patch techniques + LIEF | Robust binary modification |

### Python Dependencies
```toml
[project.optional-dependencies]
binary = [
    "lief>=0.15",
    "capstone>=5.0",
    "keystone-engine>=0.9",
    "unicorn>=2.0",
    "networkx>=3.0",
]
```

### Key Design Principles
1. **Format-agnostic core**: Abstract over ELF/PE/Mach-O via LIEF's unified API.
2. **Graceful degradation**: Don't require perfect disassembly — work with what you have.
3. **LLM as reasoning engine**: Use LLMs for semantic understanding (decompilation, patch reasoning, diff summarization), not just pattern matching.
4. **Verify via emulation**: Every patch should be emulatable before being written to disk.
5. **Structural over byte-level**: Compare and manipulate at the function/block/instruction level.
