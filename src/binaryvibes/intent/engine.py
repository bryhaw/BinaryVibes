from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.synthesis.patcher import Patch


class Intent(ABC):
    """Base class for all modification intents.

    An Intent is a high-level description of WHAT you want to change,
    without specifying HOW (which machine code to generate).
    """

    @abstractmethod
    def compile(self, context: CompilationContext) -> list[Patch]:
        """Lower this intent to concrete binary patches."""
        ...

    @abstractmethod
    def describe(self) -> str:
        """Human-readable description of this intent."""
        ...


@dataclass
class CompilationContext:
    """Everything the compiler needs to generate patches."""

    binary: BinaryFile
    arch: Arch
    assembler: Assembler

    @classmethod
    def for_binary(cls, binary: BinaryFile) -> CompilationContext:
        """Create context from a binary (auto-detect arch)."""
        arch = binary.arch or Arch.X86_64
        return cls(binary=binary, arch=arch, assembler=Assembler(arch))


# --- Concrete Intent Types ---


@dataclass
class Nop(Intent):
    """Replace a region with NOPs (effectively removing code)."""

    offset: int
    size: int

    def compile(self, ctx: CompilationContext) -> list[Patch]:
        if ctx.arch in (Arch.X86_64, Arch.X86_32):
            nop_byte = b"\x90"
        elif ctx.arch in (Arch.ARM64, Arch.ARM32):
            nop_byte = b"\x1f\x20\x03\xd5" if ctx.arch == Arch.ARM64 else b"\x00\xf0\x20\xe3"
        else:
            nop_byte = b"\x90"

        # Build nop sled of correct size
        if len(nop_byte) == 1:
            nop_data = nop_byte * self.size
        else:
            # ARM nops are 4 bytes — fill as many as fit
            count = self.size // len(nop_byte)
            remainder = self.size % len(nop_byte)
            nop_data = nop_byte * count + b"\x00" * remainder

        return [Patch(self.offset, nop_data, self.describe())]

    def describe(self) -> str:
        return f"NOP {self.size} bytes at 0x{self.offset:x}"


@dataclass
class ChangeReturnValue(Intent):
    """Make a function return a specific constant value."""

    func_offset: int
    new_value: int

    def compile(self, ctx: CompilationContext) -> list[Patch]:
        if ctx.arch in (Arch.X86_64, Arch.X86_32):
            asm_code = f"mov eax, {self.new_value}; ret"
        elif ctx.arch == Arch.ARM64:
            asm_code = f"mov x0, #{self.new_value}; ret"
        else:
            raise NotImplementedError(f"ChangeReturnValue not implemented for {ctx.arch}")

        code = ctx.assembler.assemble(asm_code, self.func_offset)
        return [Patch(self.func_offset, code, self.describe())]

    def describe(self) -> str:
        return f"Change return value to {self.new_value} at 0x{self.func_offset:x}"


@dataclass
class ReplaceCall(Intent):
    """Redirect a call instruction to a different target."""

    call_offset: int
    new_target: int

    def compile(self, ctx: CompilationContext) -> list[Patch]:
        if ctx.arch not in (Arch.X86_64, Arch.X86_32):
            raise NotImplementedError(f"ReplaceCall not implemented for {ctx.arch}")

        # x86: CALL rel32 = E8 <displacement>
        # displacement = target - (call_addr + 5)
        displacement = self.new_target - (self.call_offset + 5)
        call_bytes = b"\xe8" + displacement.to_bytes(4, byteorder="little", signed=True)
        return [Patch(self.call_offset, call_bytes, self.describe())]

    def describe(self) -> str:
        return f"Redirect call at 0x{self.call_offset:x} → 0x{self.new_target:x}"


@dataclass
class InsertCheck(Intent):
    """Insert a conditional check before code (e.g., bounds check, null check).

    If the check fails, jumps to the fail_target (or returns a value).
    """

    offset: int
    reg: str  # "register" collides with ABCMeta.register
    condition: str  # "zero", "nonzero", "negative", "positive"
    fail_value: int = -1

    def compile(self, ctx: CompilationContext) -> list[Patch]:
        if ctx.arch not in (Arch.X86_64, Arch.X86_32):
            raise NotImplementedError(f"InsertCheck not implemented for {ctx.arch}")

        # Generate: test reg, reg; jCC .ok; mov eax, fail_value; ret; .ok:
        if self.condition == "zero":
            asm_code = (
                f"test {self.reg}, {self.reg}; "
                f"jnz 0x{self.offset + 20:x}; "
                f"mov eax, {self.fail_value}; ret"
            )
        elif self.condition == "nonzero":
            asm_code = (
                f"test {self.reg}, {self.reg}; "
                f"jz 0x{self.offset + 20:x}; "
                f"mov eax, {self.fail_value}; ret"
            )
        elif self.condition == "negative":
            asm_code = (
                f"test {self.reg}, {self.reg}; "
                f"jns 0x{self.offset + 20:x}; "
                f"mov eax, {self.fail_value}; ret"
            )
        else:
            asm_code = (
                f"test {self.reg}, {self.reg}; "
                f"js 0x{self.offset + 20:x}; "
                f"mov eax, {self.fail_value}; ret"
            )

        code = ctx.assembler.assemble(asm_code, self.offset)
        return [Patch(self.offset, code, self.describe())]

    def describe(self) -> str:
        return f"Insert {self.condition}-check on {self.reg} at 0x{self.offset:x}"


@dataclass
class InjectCode(Intent):
    """Inject arbitrary assembly code at a location."""

    offset: int
    assembly: str

    def compile(self, ctx: CompilationContext) -> list[Patch]:
        code = ctx.assembler.assemble(self.assembly, self.offset)
        return [Patch(self.offset, code, self.describe())]

    def describe(self) -> str:
        return f"Inject code at 0x{self.offset:x}: {self.assembly[:50]}"


@dataclass
class ForceJump(Intent):
    """Force an unconditional jump at a location (skip over code)."""

    offset: int
    target: int

    def compile(self, ctx: CompilationContext) -> list[Patch]:
        if ctx.arch not in (Arch.X86_64, Arch.X86_32):
            raise NotImplementedError(f"ForceJump not implemented for {ctx.arch}")

        displacement = self.target - (self.offset + 5)
        jmp_bytes = b"\xe9" + displacement.to_bytes(4, byteorder="little", signed=True)
        return [Patch(self.offset, jmp_bytes, self.describe())]

    def describe(self) -> str:
        return f"Force jump 0x{self.offset:x} → 0x{self.target:x}"


# --- The Intent Compiler ---


class IntentCompiler:
    """Compiles a list of intents into patches for a binary."""

    def compile(self, binary: BinaryFile, intents: list[Intent]) -> list[Patch]:
        """Compile all intents into patches."""
        ctx = CompilationContext.for_binary(binary)
        patches = []
        for intent in intents:
            patches.extend(intent.compile(ctx))
        return patches

    def compile_one(self, binary: BinaryFile, intent: Intent) -> list[Patch]:
        """Compile a single intent."""
        return self.compile(binary, [intent])

    def preview(self, intents: list[Intent]) -> list[str]:
        """Preview what intents will do without compiling."""
        return [intent.describe() for intent in intents]
