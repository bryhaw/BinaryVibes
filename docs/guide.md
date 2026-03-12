# BinaryVibes v1.0.0 — Usage Guide

> **The thesis:** programming languages are a human abstraction — LLMs should work at the binary level.
> BinaryVibes gives you the tools to analyze, modify, synthesize, and verify binaries *without source code*.

---

## Quick Start

### Installation

```bash
# Clone and install in dev mode
git clone https://github.com/yourorg/BinaryVibes.git
cd BinaryVibes
pip install -e ".[dev]"
```

### Verify it works

```bash
# Show metadata for any binary
bv info /usr/bin/ls

# Output:
# Path:   /usr/bin/ls
# Size:   142144 bytes
# Format: ELF
# Arch:   x86_64
```

BinaryVibes operates through two interfaces:
- **CLI** (`bv`) — 13 commands for quick analysis and patching from your terminal
- **Python API** — full programmatic access for scripting, automation, and integration

---

## Use Case 1: Security Audit a Binary

**Scenario:** You've received a compiled binary from a vendor. Before deploying it to production, you want to check for dangerous functions, suspicious patterns, and complexity red flags — *without* access to source code.

### CLI

```bash
# Full audit with all checks enabled
bv audit /path/to/vendor_binary

# Audit only the .text section (offset 0x1000, size 0x5000)
bv audit /path/to/vendor_binary --offset 0x1000 --size 0x5000

# Skip slow CFG analysis, just check imports and patterns
bv audit /path/to/vendor_binary --no-cfg

# Only check for dangerous imports
bv audit /path/to/vendor_binary --no-patterns --no-cfg
```

### Python API

```python
from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.audit import audit_binary, Severity

bf = BinaryFile.from_path("/path/to/vendor_binary")

# Run the full audit
report = audit_binary(bf)

# Print the detailed report
print(report.detailed_report())
```

**Expected output:**
```
Audit of /path/to/vendor_binary (142144B, x86_64)
Total findings: 7
  critical: 1
  high: 2
  medium: 2
  low: 2

--- Findings ---

CRITICAL:
  [critical] 0x00004020 Dangerous import: gets — Buffer overflow — no bounds checking
    → Replace with fgets()

HIGH:
  [high    ] 0x00004030 Dangerous import: strcpy — Buffer overflow if src > dst
    → Use strncpy() or strlcpy()
  [high    ] 0x00004040 Dangerous import: sprintf — Buffer overflow — no length limit
    → Use snprintf()

MEDIUM:
  [medium  ] 0x00001200 NOP sled detected (8+ NOPs at 0x1200)
    → Investigate — may be padding or shellcode landing zone
  [medium  ] 0x00004050 Dangerous import: system — Command injection risk
    → Use execve() with validated args

LOW:
  [low     ] 0x00001100 Call at 0x1100 — return value not checked
    → Verify return value is intentionally ignored
  [low     ] 0x00004060 Dangerous import: rand — Weak PRNG — not suitable for crypto
    → Use getrandom() or /dev/urandom
```

### Drilling into findings

```python
# Filter by severity
criticals = report.by_severity(Severity.CRITICAL)
for f in criticals:
    print(f"🚨 {f.description} at 0x{f.offset:08x}")
    print(f"   Fix: {f.recommendation}")

# Filter by category
from binaryvibes.workflows.audit import FindingCategory

dangerous = report.by_category(FindingCategory.DANGEROUS_IMPORT)
print(f"\n{len(dangerous)} dangerous imports found")

# Summary stats
print(f"\nTotal: {report.finding_count} findings")
print(f"Critical: {report.critical_count}, High: {report.high_count}")
```

**What's happening:** The audit engine runs three independent checks:
1. **Import analysis** — resolves symbols and flags known-dangerous C library functions (`gets`, `strcpy`, `sprintf`, `system`, etc.) with severity-ranked recommendations
2. **Pattern analysis** — disassembles the code region and searches for NOP sleds (potential shellcode landing zones) and unchecked return values after `call` instructions
3. **CFG complexity** — builds a control flow graph and flags regions with high cyclomatic complexity (>20 edges), which may hide logic bugs

---

## Use Case 2: Patch a Binary Without Source Code

**Scenario:** You have a binary with an authentication check you need to bypass for testing, a license validation you need to disable, or a vulnerable code path you need to redirect. You don't have the source code.

### CLI — NOP out a license check

```bash
# NOP out 12 bytes starting at offset 0x1234 (the license check)
bv harden /path/to/app \
    --nop 0x1234:12 \
    --output patched_app

# Force a function to always return 0 (bypass auth)
bv harden /path/to/app \
    --force-return 0x5678:0 \
    --output patched_app

# Redirect execution: skip over a code region
bv harden /path/to/app \
    --redirect 0xA00:0xB00 \
    --output patched_app

# Combine multiple operations in one pass
bv harden /path/to/app \
    --nop 0x1234:12 \
    --force-return 0x5678:0 \
    --redirect 0xA00:0xB00 \
    --output patched_app
```

**Expected output:**
```
Hardening: 3 operations applied
  [nop_out] 0x1234 (12B): NOP 12B
  [force_return] 0x5678 (6B): force return 0
  [redirect] 0xa00 (5B): redirect to 0xb00
Output → patched_app
```

### Python API — BinaryHardener

```python
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.hardening import BinaryHardener

bf = BinaryFile.from_path("/path/to/app")

hardener = BinaryHardener(Arch.X86_64)

# Chain operations fluently
hardener.nop_out(0x1234, 12, reason="Disable license check")
hardener.force_return(0x5678, 0, reason="Bypass auth — always return SUCCESS")
hardener.redirect(0xA00, 0xB00, reason="Skip over vulnerable code path")

# Apply all at once
result = hardener.apply(bf)

# Inspect what was done
print(result.summary())
print(f"Operations applied: {result.op_count}")

# Save the patched binary
with open("patched_app", "wb") as f:
    f.write(result.patched_binary.raw)
```

### Low-level patching with raw hex

```bash
# Write raw bytes at an offset
bv patch /path/to/app --offset 0x1000 --hex "b83c000000bf2a0000000f05" --output patched
```

```python
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.patcher import Patch, apply_patches

bf = BinaryFile.from_path("/path/to/app")

patches = [
    Patch(offset=0x1000, data=b"\x90" * 5, description="NOP out call"),
    Patch(offset=0x2000, data=b"\xb8\x00\x00\x00\x00\xc3", description="mov eax, 0; ret"),
]

patched_bytes = apply_patches(bf, patches)
with open("patched_app", "wb") as f:
    f.write(patched_bytes)

print(f"Patched {len(patches)} locations")
```

**What's happening:** The `BinaryHardener` translates high-level operations into precise binary patches via the Intent Engine. `nop_out` fills a region with `0x90` (x86 NOP), `force_return` injects `mov eax, <value>; ret`, and `redirect` writes an unconditional `JMP rel32`. Under the hood, it uses `IntentCompiler` to generate architecture-appropriate machine code.

---

## Use Case 3: Hook Functions at Runtime

**Scenario:** You want to redirect function execution — intercept calls to `check_license()` and route them to your own `always_true()` stub, or inject logging code at function entry points.

### CLI — Insert a JMP trampoline

```bash
# Hook: redirect function at 0x1000 to code at 0x5000
bv hook /path/to/app \
    --target 0x1000 \
    --hook 0x5000 \
    --output hooked_app

# Output:
# Hooked 0x1000 → 0x5000 (1 hook(s)) → hooked_app
```

### Python API — hook_function

```python
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.hooking import hook_function, unhook_function

bf = BinaryFile.from_path("/path/to/app")

# Install the hook: overwrite the first 5 bytes of check_license()
# with a JMP to our replacement function at 0x5000
result = hook_function(bf, target_offset=0x1000, hook_offset=0x5000)

print(f"Installed {result.hook_count} hook(s)")
for hook in result.hooks:
    print(f"  {hook}")
    # Hook(0x1000 → 0x5000, saved 5B)

# Save hooked binary
with open("hooked_app", "wb") as f:
    f.write(result.patched_binary.raw)

# Later: restore original behavior
restored = unhook_function(result.patched_binary, result.hooks[0])
print("Original bytes restored!")
```

### Inject custom code at a hook point

```python
from binaryvibes.workflows.hooking import hook_with_code

bf = BinaryFile.from_path("/path/to/app")

# Inject custom assembly at 0x8000, then redirect 0x1000 → 0x8000
# The hook code increments a counter, then jumps back past the trampoline
hook_asm = "inc dword ptr [rip + 0x100]; jmp 0x1005"

result = hook_with_code(
    bf,
    target_offset=0x1000,
    hook_asm=hook_asm,
    hook_offset=0x8000,
)

print(f"Injected code + trampoline: {result.hook_count} hook(s)")
```

### Redirect an existing CALL instruction

```python
from binaryvibes.workflows.hooking import detour_call

bf = BinaryFile.from_path("/path/to/app")

# The binary has `call malloc` (E8 xx xx xx xx) at offset 0x2000.
# Redirect it to our custom allocator at 0x9000.
patched = detour_call(bf, call_offset=0x2000, new_target=0x9000)

with open("detoured_app", "wb") as f:
    f.write(patched.raw)
print("CALL instruction redirected!")
```

**What's happening:**
- `hook_function` writes a 5-byte `JMP rel32` (`E9 <displacement>`) at the target, saving the original bytes for later restoration
- `hook_with_code` does both: assembles your custom code, writes it at `hook_offset`, *and* installs the trampoline at `target_offset`
- `detour_call` rewrites the displacement of an existing `CALL rel32` (`E8`) instruction to point at a new target
- `unhook_function` restores the original bytes from the `Hook` metadata

---

## Use Case 4: Analyze Binary Behavior

**Scenario:** You have a function at a known offset and want to understand its behavior — control flow, complexity, register usage, memory access patterns, and semantic meaning of each instruction.

### CLI

```bash
# Deep analysis of a function at offset 0x1000
bv analyze /path/to/binary --offset 0x1000 --name "check_auth"

# Specify the code region size explicitly
bv analyze /path/to/binary --offset 0x1000 --size 0x80 --name "check_auth"

# Basic disassembly (lighter weight)
bv disasm /path/to/binary --offset 0x1000 --count 100

# Show control flow graph
bv cfg /path/to/binary --offset 0x1000 --count 200
```

**Expected output from `bv analyze`:**
```
Function: check_auth at 0x1000
  Size: 128 bytes, 24 instructions
  CFG: 5 blocks, 7 edges
  Cyclomatic complexity: 4
  Registers written: rax, rbp, rsp, rdi, rsi
  Memory writes: yes
  Memory reads: yes
  Call targets: 2
  Has loops: no
```

### Python API — Full analysis

```python
from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.analysis import analyze_function

bf = BinaryFile.from_path("/path/to/binary")

analysis = analyze_function(bf, offset=0x1000, name="check_auth")

# High-level summary
print(analysis.summary())

# Dig into specifics
print(f"Cyclomatic complexity: {analysis.cyclomatic_complexity}")
print(f"Registers written: {analysis.registers_written}")
print(f"Registers read: {analysis.registers_read}")
print(f"Has memory writes: {analysis.has_memory_writes}")
print(f"Has loops: {analysis.has_loops}")
print(f"Call targets: {analysis.call_targets}")

# Walk the CFG blocks
for addr in sorted(analysis.cfg.blocks):
    block = analysis.cfg.blocks[addr]
    print(
        f"  BB 0x{block.start_addr:x}-0x{block.end_addr:x} "
        f"({block.instruction_count} insns) → "
        f"{[f'0x{s:x}' for s in block.successor_addrs]}"
    )

# Inspect semantic effects — what does each instruction DO?
for sem in analysis.semantics:
    print(sem)
    # 0x1000: push rbp → [push rbp (8B); rsp := (rsp - 8); [rsp]:8 := rbp]
```

### Semantic lifting — understand behavior, not syntax

```python
from binaryvibes.analysis.disassembler import Disassembler
from binaryvibes.analysis.semantics import SemanticLifter
from binaryvibes.core.arch import Arch

dis = Disassembler(Arch.X86_64)
lifter = SemanticLifter()

# Disassemble raw bytes
code = b"\x55\x48\x89\xe5\x31\xc0\xc3"  # push rbp; mov rbp, rsp; xor eax, eax; ret
instructions = dis.disassemble(code, base_addr=0x1000)

# Lift to semantic effects
for instr in instructions:
    sem = lifter.lift(instr)
    print(f"  {instr}")
    for effect in sem.effects:
        print(f"    → {effect}")
```

**Expected output:**
```
  0x1000: push rbp
    → push rbp (8B)
    → rsp := (rsp - 8)
    → [rsp]:8 := rbp
  0x1001: mov rbp, rsp
    → rbp := rsp
  0x1003: xor eax, eax
    → flags(ZF, SF, CF, OF, PF)
    → eax := 0
  0x1005: ret
    → pop [rsp]:8 (8B)
    → ret → [rsp]:8
```

### Compare two versions of a function

```python
from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.analysis import compare_functions

old = BinaryFile.from_path("app_v1")
new = BinaryFile.from_path("app_v2")

result = compare_functions(
    old, offset_a=0x1000,
    new, offset_b=0x1000,
    size=128,
)

print(result.summary())
```

**Expected output:**
```
Comparison: function_a vs function_b
  Size: 128B → 142B (delta: +14)
  Instructions: 24 → 28 (delta: +4)
  Complexity: 4 → 6 (delta: +2)
  Byte diff: 3 regions, 87.5% similar
```

**What's happening:** `analyze_function` performs a full pipeline: disassemble → build CFG → compute reachable blocks → lift to semantic effects. The `SemanticLifter` translates instruction syntax into structured `Effect` objects (`RegisterWrite`, `MemoryWrite`, `ControlFlowEffect`, `StackEffect`, etc.) that describe *what the CPU actually does*, not just what the mnemonic says.

---

## Use Case 5: Find Code Patterns

**Scenario:** You want to search a binary for specific code idioms — function prologues, self-zeroing patterns, call-and-check sequences, NOP sleds — using a semantic pattern language instead of raw byte matching.

### The Binary Pattern Language

BinaryVibes includes a domain-specific pattern language that matches on disassembled instruction sequences:

| Syntax | Meaning |
|--------|---------|
| `mov ?dst, ?src` | Match `mov` with capture wildcards |
| `call ?func` | Match any `call`, bind target to `?func` |
| `*` | Match any single instruction |
| `...` | Match 0–10 instructions (wildcard gap) |
| `xor ?reg, ?reg` | Match `xor` where both operands are the same register (self-zeroing) |

Wildcards (`?name`) capture values. If the same `?name` appears twice, the actual operand must match both times (back-reference).

### Python API

```python
from binaryvibes.analysis.disassembler import Disassembler
from binaryvibes.analysis.patterns import Pattern, PatternMatcher, COMMON_PATTERNS
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile

bf = BinaryFile.from_path("/path/to/binary")
dis = Disassembler(Arch.X86_64)
matcher = PatternMatcher()

# Disassemble a code region
code = bf.raw[0x1000:0x2000]
instructions = dis.disassemble(code, base_addr=0x1000)

# --- Use built-in patterns ---

# Find function prologues: push rbp ; mov rbp, rsp
matches = matcher.search(instructions, COMMON_PATTERNS["function_prologue"])
print(f"Found {len(matches)} function prologues:")
for m in matches:
    print(f"  {m}")
    # Match(0x00001000-0x00001004, bindings={})

# Find self-zeroing: xor reg, reg (register clearing idiom)
matches = matcher.search(instructions, COMMON_PATTERNS["self_zero"])
for m in matches:
    print(f"  xor {m.bindings['reg']}, {m.bindings['reg']} at 0x{m.start_addr:x}")

# Find call-and-check: call ?f ; test eax, eax ; je ?label
matches = matcher.search(instructions, COMMON_PATTERNS["call_and_check"])
for m in matches:
    print(f"  Calls {m.bindings['func']}, jumps to {m.bindings['label']} on failure")

# --- Custom patterns ---

# Find any MOV into RAX followed (within 10 instrs) by a RET
custom = Pattern.parse("mov rax, ?val ; ... ; ret")
matches = matcher.search(instructions, custom)
for m in matches:
    print(f"  Returns {m.bindings['val']} at 0x{m.start_addr:x}")

# Find function epilogues: pop rbp ; ret
epilogue = COMMON_PATTERNS["function_epilogue"]
matches = matcher.search(instructions, epilogue)
print(f"Found {len(matches)} epilogues")

# Find NOP sleds (3+ consecutive NOPs)
nop_sled = COMMON_PATTERNS["nop_sled"]
matches = matcher.search(instructions, nop_sled)
for m in matches:
    print(f"  NOP sled at 0x{m.start_addr:x} ({m.end_index - m.start_index} instructions)")
```

### Available built-in patterns (`COMMON_PATTERNS`)

```python
from binaryvibes.analysis.patterns import COMMON_PATTERNS

for name, pattern in COMMON_PATTERNS.items():
    print(f"  {name:25s} → {pattern.source}")
```

```
  call_and_check            → call ?func ; test eax, eax ; je ?label
  function_prologue         → push rbp ; mov rbp, rsp
  function_epilogue         → pop rbp ; ret
  self_zero                 → xor ?reg, ?reg
  nop_sled                  → nop ; nop ; nop
  stack_canary_check        → mov ?reg, qword ptr fs:[0x28] ; ... ; xor ?reg, qword ptr fs:[0x28]
```

### First match only (faster)

```python
# Stop at the first match
first = matcher.search_first(instructions, COMMON_PATTERNS["function_prologue"])
if first:
    print(f"First prologue at 0x{first.start_addr:x}")
```

**What's happening:** The pattern matcher disassembles code into `Instruction` objects, then applies a recursive backtracking algorithm to match pattern elements against instruction sequences. Wildcard gaps (`...`) allow flexible matching across varying numbers of instructions. Back-references (`?reg` appearing twice) enforce that the same register is used in both positions.

---

## Use Case 6: Binary Diffing

**Scenario:** You have two versions of a binary (before and after a vendor patch) and need to understand exactly what changed — which bytes were modified, added, or removed.

### CLI

```bash
bv diff app_v1 app_v2
```

**Expected output:**
```
Diff: 3 regions, 42 bytes changed, 97.1% similar

0x00001000 [modified] 55 → 90
  context before: ...4831c04889e7
  context after:  4889e5488d3d...
0x00001050 [modified] e8a0ffffff → e8b0ffffff
  context before: ...488b45f8
  context after:  4885c074...
0x00002000 [added]  → 4831c0c3
```

### Python API

```python
from binaryvibes.analysis.differ import byte_diff, hex_dump_diff, DiffType
from binaryvibes.core.binary import BinaryFile

a = BinaryFile.from_path("app_v1")
b = BinaryFile.from_path("app_v2")

# Programmatic diff
report = byte_diff(a, b)

print(f"Regions changed: {report.total_differences}")
print(f"Bytes changed: {report.bytes_changed}")
print(f"Similarity: {report.similarity:.1%}")
print(f"Identical: {report.is_identical}")

# Iterate over differences
for diff in report.differences:
    print(f"  0x{diff.offset:08x} [{diff.diff_type.value}]")
    print(f"    Old: {diff.old_bytes.hex()}")
    print(f"    New: {diff.new_bytes.hex()}")
    print(f"    Size: {diff.length} bytes")

# Human-readable hex dump with context
print(hex_dump_diff(a, b, context=16))
```

**What's happening:** `byte_diff` compares two binaries byte-by-byte, grouping contiguous changed regions into `Difference` objects with types `MODIFIED`, `ADDED`, or `REMOVED`. The similarity ratio measures what fraction of the larger binary is unchanged.

---

## Use Case 7: Generate Binaries from Scratch

**Scenario:** You need to create a minimal ELF binary programmatically — for testing, as a payload, or as a host for transplanted code.

### CLI

```bash
# Generate a minimal x86_64 binary that exits with code 42
bv generate \
    --asm "mov eax, 60; mov edi, 42; syscall" \
    --output exit42

# Output: Generated 132 byte binary → exit42
chmod +x exit42 && ./exit42; echo $?
# 42
```

### Python API — BinaryBuilder

```python
from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.synthesis.generator import BinaryBuilder

# Assemble our code
asm = Assembler(Arch.X86_64)
code = asm.assemble("mov eax, 60; mov edi, 42; syscall")

# Build a minimal ELF64 binary
binary = (
    BinaryBuilder()
    .set_arch(Arch.X86_64)
    .set_base_address(0x400000)
    .add_code(code)
    .add_data(b"Hello, BinaryVibes!\x00")
    .build()
)

with open("exit42", "wb") as f:
    f.write(binary.raw)

print(f"Generated {len(binary.raw)} byte ELF64 binary")
print(f"Architecture: {binary.arch}")
print(f"Format: {binary.format_name}")
```

### Generate for different architectures

```python
# x86_32 binary
binary_32 = (
    BinaryBuilder()
    .set_arch(Arch.X86_32)
    .add_code(b"\xb8\x01\x00\x00\x00\xbb\x2a\x00\x00\x00\xcd\x80")
    .build()
)
print(f"ELF32: {len(binary_32.raw)} bytes")

# ARM64 binary
binary_arm = (
    BinaryBuilder()
    .set_arch(Arch.ARM64)
    .add_code(b"\x00\x00\x80\xd2")  # mov x0, #0
    .build()
)
print(f"ELF64 AArch64: {len(binary_arm.raw)} bytes")
```

**What's happening:** `BinaryBuilder` constructs minimal-but-valid ELF binaries with proper headers, a single `PT_LOAD` segment, and your code placed right after the program header. The entry point is automatically calculated. Supported formats: ELF64 (x86_64, AArch64) and ELF32 (x86_32).

---

## Use Case 8: Transplant Code Between Binaries

**Scenario:** Binary A has a great implementation of `fast_hash()`. Binary B needs it but doesn't have it. Extract the function from A and transplant it into B — with automatic relocation.

### Python API

```python
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.patcher import apply_patches
from binaryvibes.synthesis.transplant import FunctionExtractor, Transplanter

# Load both binaries
donor = BinaryFile.from_path("binary_a")
host = BinaryFile.from_path("binary_b")

# Step 1: Extract the function from the donor
extractor = FunctionExtractor(Arch.X86_64)
unit = extractor.extract_at(donor, offset=0x1000, name="fast_hash")

print(unit)
# TransplantUnit('fast_hash', 87B, 19 instrs, 2 relocs)
print(f"  Source address: 0x{unit.source_addr:x}")
print(f"  Needs relocation: {unit.needs_relocation}")

# Inspect relocations (external references that need fixing)
for reloc in unit.relocations:
    print(f"  Reloc at +0x{reloc.offset:x}: {reloc.rel_type} → {reloc.target_symbol}")

# Step 2: Transplant into the host at a free region
transplanter = Transplanter(Arch.X86_64)
patches = transplanter.transplant(unit, host, insert_offset=0x8000)

# Step 3: Add a trampoline so calls to old_hash() go to the transplanted code
trampoline = transplanter.create_trampoline(
    source_offset=0x2000,   # Where old_hash() lives in host
    target_offset=0x8000,   # Where we placed fast_hash()
)
patches.append(trampoline)

# Step 4: Apply all patches
patched_bytes = apply_patches(host, patches)
with open("binary_b_upgraded", "wb") as f:
    f.write(patched_bytes)

print(f"Transplanted {unit.name} ({unit.size}B) into host at 0x8000")
print(f"Trampoline: 0x2000 → 0x8000")
```

**What's happening:**
1. `FunctionExtractor` disassembles from the offset, builds a CFG, walks reachable blocks to find function boundaries, and detects external references (calls/jumps outside the function) as relocations
2. `Transplanter.transplant()` adjusts relative displacements for the new base address and generates `Patch` objects
3. `create_trampoline()` writes a `JMP rel32` at the old function location to redirect to the new one

---

## Use Case 9: Compose and Reason About Patches

**Scenario:** You have multiple patches from different sources (security fix, performance tweak, feature addition). You need to compose them safely, check for conflicts, and optimize the final patch set.

### Python API — Patch Algebra

```python
from binaryvibes.synthesis.patcher import Patch
from binaryvibes.synthesis.patch_algebra import (
    PatchSet,
    capture_effect,
    compose,
    conflicts,
    invert,
    optimize,
    overlaps,
    rebase,
)

# Define some patches
security_fix = Patch(offset=0x1000, data=b"\x90\x90\x90\x90\x90", description="NOP out vuln")
perf_tweak = Patch(offset=0x2000, data=b"\xeb\x10", description="Short-circuit hot path")
feature_add = Patch(offset=0x3000, data=b"\xe8\x00\x10\x00\x00", description="Add logging call")

# --- Check for conflicts ---
print(f"Security vs Perf conflict: {conflicts(security_fix, perf_tweak)}")
# False — they don't overlap

bad_patch = Patch(offset=0x1002, data=b"\xcc\xcc", description="Breakpoint in vuln area")
print(f"Security vs Bad conflict: {conflicts(security_fix, bad_patch)}")
# True — they write different bytes to the same region

print(f"Overlaps: {overlaps(security_fix, bad_patch)}")
# True

# --- Compose patches ---
# Merge overlapping/adjacent patches (later patch wins)
merged = compose(security_fix, perf_tweak)
print(merged)  # Returns list of 2 disjoint patches

# --- PatchSet — algebraic operations ---
pset_a = PatchSet([security_fix, perf_tweak])
pset_b = PatchSet([feature_add])

# Union (raises ValueError if conflicts)
combined = pset_a.union(pset_b)
print(f"Combined: {len(combined)} patches, {combined.total_bytes} bytes total")
print(f"Span: {combined.span}")  # (min_offset, max_end)

# Check for internal conflicts
print(f"Has conflicts: {combined.has_conflicts()}")

# Set operations
shared = pset_a.intersection(pset_b)
unique = pset_a.difference(pset_b)

# Add/remove patches immutably
extended = combined.with_patch(
    Patch(offset=0x4000, data=b"\xc3", description="Early return")
)
reduced = combined.without(perf_tweak)
```

### Invert a patch (undo it)

```python
# Capture what the patch would overwrite
binary_data = b"\x00" * 0x5000  # your binary's raw bytes
effect = capture_effect(security_fix, binary_data)

# Create the inverse patch (restores original bytes)
undo_patch = invert(effect)
print(f"Undo: write {undo_patch.data.hex()} at 0x{undo_patch.offset:x}")
```

### Rebase patches to a different offset

```python
# Relocate all patches by +0x1000 (binary was loaded at a different address)
relocated = pset_a.rebase(0x1000)
for p in relocated:
    print(f"  0x{p.offset:x}: {p.description}")
    # 0x2000: NOP out vuln (was 0x1000)
    # 0x3000: Short-circuit hot path (was 0x2000)
```

### Optimize: merge adjacent patches

```python
# Many small patches → minimal set
patches = [
    Patch(offset=0x100, data=b"\x90"),
    Patch(offset=0x101, data=b"\x90"),
    Patch(offset=0x102, data=b"\x90"),
    Patch(offset=0x200, data=b"\xcc"),
]

optimized = optimize(patches)
print(f"Before: {len(patches)} patches → After: {len(optimized)} patches")
# Before: 4 patches → After: 2 patches
# (first three merged into one contiguous NOP sled)
```

**What's happening:** The Patch Algebra treats patches as first-class algebraic objects. `compose` merges overlapping patches (later wins), `invert` creates an undo patch by capturing overwritten bytes, `rebase` shifts offsets for relocation, and `optimize` merges adjacent patches into a minimal set. `PatchSet` provides immutable set operations with automatic conflict detection.

---

## Use Case 10: Intent-Driven Modification

**Scenario:** Instead of thinking about bytes and offsets, you want to describe *what* you want to change ("make this function return 0", "NOP out this region", "redirect this call") and let the engine figure out the machine code.

### Python API — IntentCompiler

```python
from binaryvibes.core.binary import BinaryFile
from binaryvibes.intent.engine import (
    ChangeReturnValue,
    ForceJump,
    InjectCode,
    InsertCheck,
    IntentCompiler,
    Nop,
    ReplaceCall,
)
from binaryvibes.synthesis.patcher import apply_patches

bf = BinaryFile.from_path("/path/to/app")
compiler = IntentCompiler()

# Define WHAT you want, not HOW
intents = [
    # "Make the auth function always return 0 (success)"
    ChangeReturnValue(func_offset=0x1000, new_value=0),

    # "Remove the license check (12 bytes of dead code)"
    Nop(offset=0x2000, size=12),

    # "Redirect the call at 0x3000 to our handler at 0x8000"
    ReplaceCall(call_offset=0x3000, new_target=0x8000),

    # "Skip the integrity check — jump from 0x4000 to 0x4100"
    ForceJump(offset=0x4000, target=0x4100),

    # "Add a null-pointer check on rdi before the memcpy"
    InsertCheck(offset=0x5000, reg="rdi", condition="zero", fail_value=-1),

    # "Inject custom assembly at 0x6000"
    InjectCode(offset=0x6000, assembly="push rax; mov rax, 1; pop rax"),
]

# Preview what will happen (without compiling)
for desc in compiler.preview(intents):
    print(f"  → {desc}")
```

**Expected preview output:**
```
  → Change return value to 0 at 0x1000
  → NOP 12 bytes at 0x2000
  → Redirect call at 0x3000 → 0x8000
  → Force jump 0x4000 → 0x4100
  → Insert zero-check on rdi at 0x5000
  → Inject code at 0x6000: push rax; mov rax, 1; pop rax
```

### Compile and apply

```python
# Compile intents to low-level patches
patches = compiler.compile(bf, intents)

print(f"Generated {len(patches)} patches:")
for p in patches:
    print(f"  0x{p.offset:x}: {p.length}B — {p.description}")

# Apply to binary
patched_bytes = apply_patches(bf, patches)
with open("modified_app", "wb") as f:
    f.write(patched_bytes)
```

### Single intent compilation

```python
# Compile just one intent
patches = compiler.compile_one(bf, Nop(offset=0x1000, size=5))
```

### Architecture support

The Intent Engine generates architecture-appropriate code:

| Intent | x86_64 | ARM64 |
|--------|--------|-------|
| `Nop` | `0x90` bytes | `1f 20 03 d5` (4-byte NOP) |
| `ChangeReturnValue(value=0)` | `mov eax, 0; ret` | `mov x0, #0; ret` |
| `ForceJump` | `JMP rel32` (E9) | — |
| `ReplaceCall` | `CALL rel32` (E8) | — |

**What's happening:** The Intent Engine separates *what* from *how*. Each `Intent` subclass knows how to `compile()` itself given a `CompilationContext` (binary + architecture + assembler). The `IntentCompiler` creates the context and delegates. This is the key abstraction that makes BinaryVibes AI-friendly: an LLM describes intents in structured form, and the engine handles the machine code generation.

---

## Python API Reference (Quick)

```python
# --- Core ---
from binaryvibes.core.binary import BinaryFile        # Load/create binaries
from binaryvibes.core.arch import Arch                 # Arch.X86_64, X86_32, ARM64, ARM32

# --- Analysis ---
from binaryvibes.analysis.disassembler import Disassembler  # Disassemble bytes → instructions
from binaryvibes.analysis.cfg import CFGBuilder              # Build control flow graphs
from binaryvibes.analysis.semantics import SemanticLifter    # Instructions → semantic effects
from binaryvibes.analysis.patterns import (                  # Pattern matching
    Pattern, PatternMatcher, COMMON_PATTERNS
)
from binaryvibes.analysis.symbols import resolve_symbols     # ELF/PE symbol tables
from binaryvibes.analysis.differ import byte_diff, hex_dump_diff  # Binary diffing

# --- Synthesis ---
from binaryvibes.synthesis.patcher import Patch, apply_patches    # Low-level patching
from binaryvibes.synthesis.assembler import Assembler              # Mnemonics → bytes
from binaryvibes.synthesis.generator import BinaryBuilder          # Generate ELF from scratch
from binaryvibes.synthesis.transplant import (                     # Code transplant
    FunctionExtractor, Transplanter
)
from binaryvibes.synthesis.patch_algebra import (                  # Patch algebra
    PatchSet, compose, invert, rebase, optimize,
    overlaps, conflicts, capture_effect
)

# --- Intent ---
from binaryvibes.intent.engine import (                            # Intent-driven modification
    IntentCompiler, Nop, ChangeReturnValue,
    ReplaceCall, ForceJump, InjectCode, InsertCheck
)

# --- Workflows (high-level) ---
from binaryvibes.workflows.audit import audit_binary, AuditReport
from binaryvibes.workflows.analysis import analyze_function, compare_functions
from binaryvibes.workflows.hardening import BinaryHardener
from binaryvibes.workflows.hooking import (
    hook_function, unhook_function, hook_with_code, detour_call
)

# --- Verify ---
from binaryvibes.verify.emulator import Emulator                  # Emulate code regions
```

---

## CLI Reference

BinaryVibes ships with the `bv` command — 13 subcommands covering the full workflow:

### `bv info <path>`
Display metadata for a binary file (size, format, architecture).

```bash
bv info /usr/bin/ls
```

### `bv disasm <path>`
Disassemble a region of a binary.

```bash
bv disasm binary.elf --offset 0x1000 --count 100 --arch x86_64
```

| Option | Default | Description |
|--------|---------|-------------|
| `--offset, -o` | `0` | Start offset in the binary |
| `--count, -n` | `50` | Max number of bytes to disassemble |
| `--arch, -a` | `x86_64` | Architecture (`x86_64`, `x86_32`, `arm64`, `arm32`) |

### `bv assemble <asm>`
Assemble mnemonics to hex bytes.

```bash
bv assemble "mov eax, 60; mov edi, 42; syscall"
# b83c000000bf2a0000000f05
```

| Option | Default | Description |
|--------|---------|-------------|
| `--arch, -a` | `x86_64` | Target architecture |
| `--base-addr, -b` | `0` | Base address for assembly |

### `bv patch <path>`
Apply a hex patch to a binary at a specific offset.

```bash
bv patch app.elf --offset 0x1000 --hex "9090909090" --output patched.elf
```

| Option | Required | Description |
|--------|----------|-------------|
| `--offset, -o` | Yes | Offset to patch (hex or decimal) |
| `--hex` | Yes | Hex string of bytes to write |
| `--output, -O` | Yes | Output file path |

### `bv emulate <path>`
Run a code region through the built-in emulator.

```bash
bv emulate binary.elf --offset 0x1000 --count 100 --max-instructions 500
```

| Option | Default | Description |
|--------|---------|-------------|
| `--offset, -o` | `0` | Start offset |
| `--count, -n` | `100` | Number of bytes to emulate |
| `--arch, -a` | `x86_64` | Architecture |
| `--max-instructions, -m` | `1000` | Max instructions to execute |

### `bv cfg <path>`
Show basic blocks and edges for a code region.

```bash
bv cfg binary.elf --offset 0x1000 --count 200
```

| Option | Default | Description |
|--------|---------|-------------|
| `--offset, -o` | `0` | Start offset |
| `--count, -n` | `200` | Number of bytes to analyse |
| `--arch, -a` | `x86_64` | Architecture |

### `bv symbols <path>`
List symbols in a binary (ELF/PE).

```bash
bv symbols binary.elf
```

### `bv diff <path_a> <path_b>`
Compare two binaries byte-by-byte with context.

```bash
bv diff old_version new_version
```

### `bv generate`
Generate a minimal binary from assembly.

```bash
bv generate --asm "mov eax, 60; syscall" --output minimal.elf --arch x86_64
```

| Option | Required | Description |
|--------|----------|-------------|
| `--asm` | Yes | Assembly instructions |
| `--output, -O` | Yes | Output file path |
| `--arch, -a` | No | Architecture (default: `x86_64`) |

### `bv audit <path>`
Run a security audit on a binary.

```bash
bv audit binary.elf --offset 0x1000 --size 0x5000
```

| Option | Default | Description |
|--------|---------|-------------|
| `--offset, -o` | `0` | Code region offset |
| `--size, -s` | all | Code region size |
| `--no-imports` | off | Skip dangerous-import checks |
| `--no-patterns` | off | Skip suspicious-pattern checks |
| `--no-cfg` | off | Skip CFG complexity checks |

### `bv hook <path>`
Hook a function by inserting a JMP trampoline.

```bash
bv hook binary.elf --target 0x1000 --hook 0x5000 --output hooked.elf
```

| Option | Required | Description |
|--------|----------|-------------|
| `--target, -t` | Yes | Target function offset |
| `--hook, -k` | Yes | Hook code offset |
| `--output, -O` | Yes | Output file path |
| `--arch, -a` | No | Architecture (default: `x86_64`) |

### `bv harden <path>`
Apply hardening operations (NOP, force-return, redirect).

```bash
bv harden binary.elf \
    --nop 0x1000:10 \
    --force-return 0x2000:0 \
    --redirect 0x3000:0x4000 \
    --output hardened.elf
```

| Option | Repeatable | Description |
|--------|------------|-------------|
| `--nop` | Yes | NOP out a region (`offset:size`) |
| `--force-return` | Yes | Force return value (`offset:value`) |
| `--redirect` | Yes | Redirect jump (`offset:target`) |
| `--output, -O` | — | Output file path (required) |
| `--arch, -a` | — | Architecture (default: `x86_64`) |

### `bv analyze <path>`
Deep analysis of a function or code region.

```bash
bv analyze binary.elf --offset 0x1000 --size 0x80 --name "check_auth"
```

| Option | Default | Description |
|--------|---------|-------------|
| `--offset, -o` | required | Function offset |
| `--size, -s` | auto | Code region size |
| `--name, -n` | `""` | Function name label |
| `--arch, -a` | `x86_64` | Architecture |

---

*Built with ❤️ for the binary-curious. BinaryVibes v1.0.0.*
