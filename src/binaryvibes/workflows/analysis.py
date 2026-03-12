"""Deep analysis workflow — comprehensive function and binary analysis."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from binaryvibes.analysis.cfg import CFGBuilder, ControlFlowGraph
from binaryvibes.analysis.differ import DiffReport, byte_diff
from binaryvibes.analysis.disassembler import Disassembler, Instruction
from binaryvibes.analysis.semantics import (
    ControlFlowEffect,
    RegisterWrite,
    SemanticInstruction,
    SemanticLifter,
)
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile


@dataclass
class FunctionAnalysis:
    """Comprehensive analysis of a single function/code region."""

    name: str
    offset: int
    size: int
    arch: Arch
    instructions: list[Instruction]
    cfg: ControlFlowGraph
    semantics: list[SemanticInstruction]

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def block_count(self) -> int:
        return self.cfg.block_count

    @property
    def edge_count(self) -> int:
        return self.cfg.edge_count

    @property
    def cyclomatic_complexity(self) -> int:
        """McCabe cyclomatic complexity: E - N + 2."""
        return self.edge_count - self.block_count + 2

    @property
    def registers_written(self) -> set[str]:
        """All registers modified by this function."""
        regs: set[str] = set()
        for sem in self.semantics:
            regs.update(sem.writes_registers)
        return regs

    @property
    def registers_read(self) -> set[str]:
        """Registers read (appearing as sources in operations)."""
        regs: set[str] = set()
        for sem in self.semantics:
            for effect in sem.effects:
                if isinstance(effect, RegisterWrite) and hasattr(effect.value, "name"):
                    regs.add(effect.value.name)
        return regs

    @property
    def has_memory_writes(self) -> bool:
        return any(sem.writes_memory for sem in self.semantics)

    @property
    def has_memory_reads(self) -> bool:
        return any(sem.reads_memory for sem in self.semantics)

    @property
    def call_targets(self) -> list[int]:
        """Addresses called by this function."""
        targets: list[int] = []
        for sem in self.semantics:
            for effect in sem.effects:
                if (
                    isinstance(effect, ControlFlowEffect)
                    and effect.is_call
                    and hasattr(effect.target, "value")
                ):
                    targets.append(effect.target.value)
        return targets

    @property
    def has_loops(self) -> bool:
        """Check if any block jumps backward (simple loop detection)."""
        return any(edge.target < edge.source for edge in self.cfg.edges)

    def summary(self) -> str:
        lines = [
            f"Function: {self.name} at 0x{self.offset:x}",
            f"  Size: {self.size} bytes, {self.instruction_count} instructions",
            f"  CFG: {self.block_count} blocks, {self.edge_count} edges",
            f"  Cyclomatic complexity: {self.cyclomatic_complexity}",
            f"  Registers written: {', '.join(sorted(self.registers_written)) or 'none'}",
            f"  Memory writes: {'yes' if self.has_memory_writes else 'no'}",
            f"  Memory reads: {'yes' if self.has_memory_reads else 'no'}",
            f"  Call targets: {len(self.call_targets)}",
            f"  Has loops: {'yes' if self.has_loops else 'no'}",
        ]
        return "\n".join(lines)


@dataclass
class ComparisonResult:
    """Result of comparing two functions/binaries."""

    name_a: str
    name_b: str
    analysis_a: FunctionAnalysis | None
    analysis_b: FunctionAnalysis | None
    diff_report: DiffReport | None

    @property
    def size_delta(self) -> int:
        if self.analysis_a and self.analysis_b:
            return self.analysis_b.size - self.analysis_a.size
        return 0

    @property
    def complexity_delta(self) -> int:
        if self.analysis_a and self.analysis_b:
            return self.analysis_b.cyclomatic_complexity - self.analysis_a.cyclomatic_complexity
        return 0

    @property
    def instruction_delta(self) -> int:
        if self.analysis_a and self.analysis_b:
            return self.analysis_b.instruction_count - self.analysis_a.instruction_count
        return 0

    def summary(self) -> str:
        lines = [f"Comparison: {self.name_a} vs {self.name_b}"]
        if self.analysis_a and self.analysis_b:
            lines.append(
                f"  Size: {self.analysis_a.size}B → {self.analysis_b.size}B"
                f" (delta: {self.size_delta:+d})"
            )
            lines.append(
                f"  Instructions: {self.analysis_a.instruction_count}"
                f" → {self.analysis_b.instruction_count}"
                f" (delta: {self.instruction_delta:+d})"
            )
            lines.append(
                f"  Complexity: {self.analysis_a.cyclomatic_complexity}"
                f" → {self.analysis_b.cyclomatic_complexity}"
                f" (delta: {self.complexity_delta:+d})"
            )
        if self.diff_report:
            lines.append(
                f"  Byte diff: {self.diff_report.total_differences} regions,"
                f" {self.diff_report.similarity:.1%} similar"
            )
        return "\n".join(lines)


def analyze_function(
    binary: BinaryFile,
    offset: int,
    size: int | None = None,
    name: str = "",
    arch: Arch | None = None,
) -> FunctionAnalysis:
    """Perform comprehensive analysis of a code region.

    Args:
        binary: Binary containing the function
        offset: Byte offset where the code starts
        size: Size of code region (None = auto-detect via CFG)
        name: Name for this function
        arch: Architecture (auto-detected if None)
    """
    detected_arch = arch or binary.arch or Arch.X86_64

    # Disassemble
    dis = Disassembler(detected_arch)
    max_size = size or min(4096, len(binary.raw) - offset)
    code = binary.raw[offset : offset + max_size]
    instructions = dis.disassemble(code, offset)

    if not instructions:
        return FunctionAnalysis(
            name=name or f"func_0x{offset:x}",
            offset=offset,
            size=0,
            arch=detected_arch,
            instructions=[],
            cfg=ControlFlowGraph(blocks={}, edges=[], entry_addr=offset),
            semantics=[],
        )

    # Build CFG
    cfg = CFGBuilder().build(instructions)

    # If no size given, trim to reachable blocks
    if size is None and cfg.blocks:
        visited: set[int] = set()
        queue: deque[int] = deque([cfg.entry_addr])
        while queue:
            addr = queue.popleft()
            if addr in visited or addr not in cfg.blocks:
                continue
            visited.add(addr)
            for s in cfg.blocks[addr].successor_addrs:
                queue.append(s)
        if visited:
            max_end = max(cfg.blocks[a].end_addr for a in visited if a in cfg.blocks)
            actual_size = max_end - offset
            instructions = [i for i in instructions if offset <= i.address < max_end]
        else:
            actual_size = max_size
    else:
        actual_size = size or max_size

    # Lift to semantics
    lifter = SemanticLifter()
    semantics = lifter.lift_block(instructions)

    return FunctionAnalysis(
        name=name or f"func_0x{offset:x}",
        offset=offset,
        size=actual_size,
        arch=detected_arch,
        instructions=instructions,
        cfg=cfg,
        semantics=semantics,
    )


def compare_functions(
    binary_a: BinaryFile,
    offset_a: int,
    binary_b: BinaryFile,
    offset_b: int,
    size: int | None = None,
    arch: Arch | None = None,
) -> ComparisonResult:
    """Compare two functions from (possibly different) binaries."""
    analysis_a = analyze_function(binary_a, offset_a, size, name="function_a", arch=arch)
    analysis_b = analyze_function(binary_b, offset_b, size, name="function_b", arch=arch)

    # Byte-level diff of the code regions
    code_a = BinaryFile.from_bytes(
        binary_a.raw[offset_a : offset_a + analysis_a.size], name="code_a"
    )
    code_b = BinaryFile.from_bytes(
        binary_b.raw[offset_b : offset_b + analysis_b.size], name="code_b"
    )
    diff = byte_diff(code_a, code_b)

    return ComparisonResult(
        name_a="function_a",
        name_b="function_b",
        analysis_a=analysis_a,
        analysis_b=analysis_b,
        diff_report=diff,
    )
