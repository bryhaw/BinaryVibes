"""Binary hardening workflow — apply security patches without source code."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.intent.engine import (
    ChangeReturnValue,
    ForceJump,
    InjectCode,
    Intent,
    IntentCompiler,
    Nop,
)
from binaryvibes.synthesis.patcher import Patch, apply_patches


class HardenAction(Enum):
    NOP_OUT = "nop_out"
    FORCE_RETURN = "force_return"
    REDIRECT = "redirect"
    INJECT = "inject"


@dataclass(frozen=True)
class HardenOp:
    """A single hardening operation applied to a binary."""

    action: HardenAction
    offset: int
    size: int
    description: str


@dataclass
class HardenResult:
    """Result of hardening operations."""

    original_size: int
    patched_binary: BinaryFile
    operations: list[HardenOp] = field(default_factory=list)

    @property
    def op_count(self) -> int:
        return len(self.operations)

    def summary(self) -> str:
        lines = [f"Hardening: {self.op_count} operations applied"]
        for op in self.operations:
            lines.append(f"  [{op.action.value}] 0x{op.offset:x} ({op.size}B): {op.description}")
        return "\n".join(lines)


class BinaryHardener:
    """Applies hardening patches to binaries via the intent engine."""

    def __init__(self, arch: Arch = Arch.X86_64):
        self._arch = arch
        self._compiler = IntentCompiler()
        self._pending: list[tuple[Intent, HardenAction, str]] = []

    def nop_out(self, offset: int, size: int, reason: str = "") -> BinaryHardener:
        """Replace a region with NOPs (disable dangerous code)."""
        intent = Nop(offset=offset, size=size)
        self._pending.append((intent, HardenAction.NOP_OUT, reason or f"NOP {size}B"))
        return self

    def force_return(self, offset: int, value: int, reason: str = "") -> BinaryHardener:
        """Make a function always return a specific value."""
        intent = ChangeReturnValue(func_offset=offset, new_value=value)
        self._pending.append((intent, HardenAction.FORCE_RETURN, reason or f"force return {value}"))
        return self

    def redirect(self, offset: int, target: int, reason: str = "") -> BinaryHardener:
        """Force an unconditional jump from offset to target (skip over code)."""
        intent = ForceJump(offset=offset, target=target)
        self._pending.append((intent, HardenAction.REDIRECT, reason or f"redirect to 0x{target:x}"))
        return self

    def inject_code(self, offset: int, asm_code: str, reason: str = "") -> BinaryHardener:
        """Inject custom assembly at an offset."""
        intent = InjectCode(offset=offset, assembly=asm_code)
        self._pending.append((intent, HardenAction.INJECT, reason or "inject code"))
        return self

    def apply(self, binary: BinaryFile) -> HardenResult:
        """Apply all queued hardening operations to a binary."""
        if not self._pending:
            return HardenResult(
                original_size=len(binary.raw),
                patched_binary=binary,
            )

        all_patches: list[Patch] = []
        ops: list[HardenOp] = []

        for intent, action, desc in self._pending:
            patches = self._compiler.compile_one(binary, intent)
            total_size = sum(p.length for p in patches)
            offset = patches[0].offset if patches else 0
            ops.append(HardenOp(action, offset, total_size, desc))
            all_patches.extend(patches)

        patched_raw = apply_patches(binary, all_patches)
        patched = BinaryFile.from_bytes(patched_raw, name="hardened")

        result = HardenResult(
            original_size=len(binary.raw),
            patched_binary=patched,
            operations=ops,
        )
        # Reset for reuse
        self._pending = []
        return result
