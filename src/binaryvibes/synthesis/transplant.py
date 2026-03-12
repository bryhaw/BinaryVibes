"""Binary Transplant System — extract functional "organs" from one binary into another.

Provides tools to extract code regions (functions, basic-block clusters) as
self-contained :class:`TransplantUnit` objects, then transplant them into a
different host binary with automatic relocation adjustment and optional
trampoline generation.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from binaryvibes.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph
from binaryvibes.analysis.disassembler import Disassembler, Instruction
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.patcher import Patch

# Branch / call mnemonics whose operand may be an address we need to relocate.
_BRANCH_MNEMONICS: frozenset[str] = frozenset(
    {
        "call",
        "callq",
        "jmp",
        "jmpq",
        "je",
        "jz",
        "jne",
        "jnz",
        "jg",
        "jge",
        "jl",
        "jle",
        "ja",
        "jae",
        "jb",
        "jbe",
    }
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RelocationEntry:
    """A location in extracted code that needs address adjustment."""

    offset: int  # Offset within the extracted code
    rel_type: str  # "absolute" | "relative" | "rip_relative"
    target_symbol: str  # What this references (function name, label, etc.)
    addend: int = 0  # Additional offset


@dataclass
class TransplantUnit:
    """A self-contained unit of code extracted from a binary.

    Like an organ removed for transplant — carries its code, metadata,
    and everything needed to be placed into a new host.
    """

    code: bytes
    arch: Arch
    source_addr: int
    cfg: ControlFlowGraph | None = None
    instructions: list[Instruction] = field(default_factory=list)
    relocations: list[RelocationEntry] = field(default_factory=list)
    name: str = ""

    @property
    def size(self) -> int:
        return len(self.code)

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def needs_relocation(self) -> bool:
        return len(self.relocations) > 0

    def __str__(self) -> str:
        reloc = f", {len(self.relocations)} relocs" if self.relocations else ""
        return (
            f"TransplantUnit('{self.name}', {self.size}B, {self.instruction_count} instrs{reloc})"
        )


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class FunctionExtractor:
    """Extracts functions from binaries as :class:`TransplantUnit` objects."""

    def __init__(self, arch: Arch = Arch.X86_64) -> None:
        self._arch = arch
        self._disasm = Disassembler(arch)

    def extract_at(
        self,
        binary: BinaryFile,
        offset: int,
        max_size: int = 4096,
        name: str = "",
    ) -> TransplantUnit:
        """Extract code starting at *offset*, using CFG analysis for boundaries.

        Raises :class:`ValueError` when no valid code is found.
        """
        code_region = binary.raw[offset : offset + max_size]
        if not code_region:
            raise ValueError(f"No code at offset 0x{offset:x}")

        base_addr = offset
        instructions = self._disasm.disassemble(code_region, base_addr)
        if not instructions:
            raise ValueError(f"Could not disassemble code at offset 0x{offset:x}")

        builder = CFGBuilder()
        cfg = builder.build(instructions)

        reachable = self._find_reachable_blocks(cfg)

        if reachable:
            min_addr = min(b.start_addr for b in reachable)
            max_addr = max(b.end_addr for b in reachable)
            func_size = max_addr - min_addr
            func_code = binary.raw[offset : offset + func_size]
            func_instrs = [i for i in instructions if min_addr <= i.address < max_addr]
        else:
            func_code = code_region
            func_instrs = instructions
            func_size = len(code_region)

        relocations = self._detect_relocations(func_instrs, base_addr, func_size)

        return TransplantUnit(
            code=func_code,
            arch=self._arch,
            source_addr=offset,
            cfg=cfg,
            instructions=func_instrs,
            relocations=relocations,
            name=name or f"func_0x{offset:x}",
        )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _find_reachable_blocks(cfg: ControlFlowGraph) -> list[BasicBlock]:
        """BFS from entry to find all reachable basic blocks."""
        if not cfg.blocks:
            return []
        visited: set[int] = set()
        queue: deque[int] = deque([cfg.entry_addr])
        result: list[BasicBlock] = []
        while queue:
            addr = queue.popleft()
            if addr in visited or addr not in cfg.blocks:
                continue
            visited.add(addr)
            block = cfg.blocks[addr]
            result.append(block)
            for succ_addr in block.successor_addrs:
                if succ_addr not in visited:
                    queue.append(succ_addr)
        return result

    @staticmethod
    def _detect_relocations(
        instructions: list[Instruction],
        base_addr: int,
        region_size: int,
    ) -> list[RelocationEntry]:
        """Detect instructions that reference addresses outside the extracted region."""
        relocations: list[RelocationEntry] = []
        region_end = base_addr + region_size

        for instr in instructions:
            if instr.mnemonic not in _BRANCH_MNEMONICS:
                continue
            target = _parse_target(instr.op_str)
            if target is not None and (target < base_addr or target >= region_end):
                relocations.append(
                    RelocationEntry(
                        offset=instr.address - base_addr,
                        rel_type="relative",
                        target_symbol=f"ext_0x{target:x}",
                        addend=0,
                    )
                )

        return relocations


# ---------------------------------------------------------------------------
# Transplanter
# ---------------------------------------------------------------------------


class Transplanter:
    """Transplants :class:`TransplantUnit` objects into a target binary."""

    def __init__(self, arch: Arch = Arch.X86_64) -> None:
        self._arch = arch

    def transplant(
        self,
        unit: TransplantUnit,
        target: BinaryFile,
        insert_offset: int,
    ) -> list[Patch]:
        """Generate patches to transplant *unit* into *target* at *insert_offset*.

        Returns a list of :class:`Patch` objects ready for
        :func:`~binaryvibes.synthesis.patcher.apply_patches`.
        """
        if insert_offset + unit.size > len(target.raw):
            raise ValueError(
                f"TransplantUnit ({unit.size}B) doesn't fit at offset "
                f"0x{insert_offset:x} in target ({len(target.raw)}B)"
            )

        relocated_code = self._relocate_code(unit, insert_offset)

        return [
            Patch(
                offset=insert_offset,
                data=relocated_code,
                description=f"transplant: {unit.name} ({unit.size}B)",
            )
        ]

    def create_trampoline(self, source_offset: int, target_offset: int) -> Patch:
        """Create a ``JMP rel32`` trampoline from *source_offset* to *target_offset*.

        Only x86_64 is supported at this time.
        """
        if self._arch != Arch.X86_64:
            raise NotImplementedError("Trampolines only supported for x86_64")

        # JMP rel32: E9 <signed-32-bit displacement>
        displacement = target_offset - (source_offset + 5)
        jmp_bytes = b"\xe9" + displacement.to_bytes(4, byteorder="little", signed=True)

        return Patch(
            offset=source_offset,
            data=jmp_bytes,
            description=f"trampoline: 0x{source_offset:x} → 0x{target_offset:x}",
        )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _relocate_code(unit: TransplantUnit, new_base: int) -> bytes:
        """Adjust relative displacements for the new base address."""
        code = bytearray(unit.code)
        delta = new_base - unit.source_addr

        if delta == 0:
            return bytes(code)

        for reloc in unit.relocations:
            if reloc.rel_type != "relative":
                continue
            instr_offset = reloc.offset
            for instr in unit.instructions:
                if instr.address - unit.source_addr != instr_offset:
                    continue
                # x86_64 call/jmp rel32: displacement occupies last 4 bytes
                if instr.size >= 5:
                    disp_offset = instr_offset + instr.size - 4
                    if disp_offset + 4 <= len(code):
                        old_disp = int.from_bytes(
                            code[disp_offset : disp_offset + 4],
                            byteorder="little",
                            signed=True,
                        )
                        new_disp = old_disp - delta
                        code[disp_offset : disp_offset + 4] = new_disp.to_bytes(
                            4, byteorder="little", signed=True
                        )
                break

        return bytes(code)


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _parse_target(op_str: str) -> int | None:
    """Parse a branch/call target address from an operand string."""
    op_str = op_str.strip()
    try:
        if op_str.startswith(("0x", "0X")):
            return int(op_str, 16)
        if op_str.isdigit():
            return int(op_str)
    except ValueError:
        pass
    return None
