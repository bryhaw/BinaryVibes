"""Binary Semantics Engine — structured semantic effects for instructions.

Translates instruction syntax (e.g. ``mov rax, rbx``) into semantic effects
(e.g. *write register rax with value from register rbx*).  This is the bridge
that lets an AI reason about binary **behaviour**, not just syntax.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from binaryvibes.analysis.disassembler import Instruction

# ---------------------------------------------------------------------------
# Expression tree — what values flow through the CPU
# ---------------------------------------------------------------------------


class Expr:
    """Base class for value expressions in semantic effects."""


@dataclass(frozen=True)
class Const(Expr):
    """A constant / immediate value."""

    value: int

    def __str__(self) -> str:
        return f"0x{self.value:x}" if self.value > 9 else str(self.value)


@dataclass(frozen=True)
class Reg(Expr):
    """A register reference."""

    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class BinOp(Expr):
    """Binary operation on two expressions."""

    op: str  # "+", "-", "*", "&", "|", "^", "<<", ">>"
    left: Expr
    right: Expr

    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"


@dataclass(frozen=True)
class MemRef(Expr):
    """Memory dereference ``[addr_expr]``."""

    address: Expr
    size: int = 8  # bytes

    def __str__(self) -> str:
        return f"[{self.address}]:{self.size}"


# ---------------------------------------------------------------------------
# Semantic effects — what an instruction DOES
# ---------------------------------------------------------------------------


class Effect:
    """Base class for instruction side effects."""


@dataclass(frozen=True)
class RegisterWrite(Effect):
    """Writes a value to a register."""

    register: str
    value: Expr

    def __str__(self) -> str:
        return f"{self.register} := {self.value}"


@dataclass(frozen=True)
class MemoryWrite(Effect):
    """Writes a value to memory."""

    address: Expr
    value: Expr
    size: int = 8

    def __str__(self) -> str:
        return f"[{self.address}]:{self.size} := {self.value}"


@dataclass(frozen=True)
class MemoryRead(Effect):
    """Reads from memory (tracked for data-flow analysis)."""

    address: Expr
    size: int = 8

    def __str__(self) -> str:
        return f"read [{self.address}]:{self.size}"


@dataclass(frozen=True)
class FlagEffect(Effect):
    """Modifies CPU flags."""

    flags_modified: tuple[str, ...]  # e.g. ("ZF", "SF", "CF", "OF")

    def __str__(self) -> str:
        return f"flags({', '.join(self.flags_modified)})"


@dataclass(frozen=True)
class ControlFlowEffect(Effect):
    """Changes control flow."""

    target: Expr
    conditional: bool
    is_call: bool = False
    is_return: bool = False

    def __str__(self) -> str:
        kind = "call" if self.is_call else "ret" if self.is_return else "branch"
        cond = "conditional " if self.conditional else ""
        return f"{cond}{kind} → {self.target}"


@dataclass(frozen=True)
class StackEffect(Effect):
    """Push / pop effect on the stack."""

    operation: str  # "push" or "pop"
    value: Expr
    size: int = 8

    def __str__(self) -> str:
        return f"{self.operation} {self.value} ({self.size}B)"


# ---------------------------------------------------------------------------
# SemanticInstruction — instruction + its effects
# ---------------------------------------------------------------------------

_ARITH_FLAGS: tuple[str, ...] = ("ZF", "SF", "CF", "OF", "AF", "PF")
_LOGIC_FLAGS: tuple[str, ...] = ("ZF", "SF", "CF", "OF", "PF")


@dataclass
class SemanticInstruction:
    """An instruction enriched with its semantic effects."""

    instruction: Instruction
    effects: list[Effect] = field(default_factory=list)

    @property
    def writes_registers(self) -> list[str]:
        return [e.register for e in self.effects if isinstance(e, RegisterWrite)]

    @property
    def reads_memory(self) -> bool:
        return any(isinstance(e, MemoryRead) for e in self.effects)

    @property
    def writes_memory(self) -> bool:
        return any(isinstance(e, MemoryWrite) for e in self.effects)

    @property
    def is_control_flow(self) -> bool:
        return any(isinstance(e, ControlFlowEffect) for e in self.effects)

    def __str__(self) -> str:
        effects_str = "; ".join(str(e) for e in self.effects)
        return f"{self.instruction} → [{effects_str}]"


# ---------------------------------------------------------------------------
# SemanticLifter — instruction → semantic effects
# ---------------------------------------------------------------------------


class SemanticLifter:
    """Lifts x86_64 instructions to semantic effects.

    This is the core innovation: translating syntax → semantics.
    """

    def lift(self, instruction: Instruction) -> SemanticInstruction:
        """Lift a single instruction to its semantic effects."""
        mnemonic = instruction.mnemonic.lower()
        operands = self._parse_operands(instruction.op_str)
        effects = self._lift_mnemonic(mnemonic, operands, instruction)
        return SemanticInstruction(instruction=instruction, effects=effects)

    def lift_block(self, instructions: list[Instruction]) -> list[SemanticInstruction]:
        """Lift a sequence of instructions."""
        return [self.lift(i) for i in instructions]

    # -- operand parsing ----------------------------------------------------

    def _parse_operands(self, op_str: str) -> list[str]:
        if not op_str.strip():
            return []
        return [op.strip() for op in op_str.split(",")]

    def _operand_to_expr(self, op: str) -> Expr:
        op = op.strip()
        if op.startswith("0x") or op.startswith("-0x"):
            return Const(int(op, 16))
        if op.lstrip("-").isdigit():
            return Const(int(op))
        if "[" in op:
            inner = op[op.index("[") + 1 : op.index("]")]
            return MemRef(self._parse_mem_expr(inner))
        return Reg(op)

    def _parse_mem_expr(self, expr: str) -> Expr:
        expr = expr.strip()
        if expr.isalpha():
            return Reg(expr)
        if " + " in expr:
            parts = expr.split(" + ", 1)
            return BinOp("+", self._parse_mem_expr(parts[0]), self._parse_mem_expr(parts[1]))
        if " - " in expr:
            parts = expr.split(" - ", 1)
            return BinOp("-", self._parse_mem_expr(parts[0]), self._parse_mem_expr(parts[1]))
        if "*" in expr:
            parts = expr.split("*", 1)
            return BinOp("*", self._parse_mem_expr(parts[0]), self._parse_mem_expr(parts[1]))
        if expr.startswith("0x"):
            return Const(int(expr, 16))
        if expr.isdigit():
            return Const(int(expr))
        return Reg(expr)

    # -- dispatch -----------------------------------------------------------

    def _lift_mnemonic(
        self, mnemonic: str, operands: list[str], instr: Instruction
    ) -> list[Effect]:
        handlers: dict[str, _Handler] = {
            "mov": self._lift_mov,
            "movzx": self._lift_mov,
            "movsx": self._lift_mov,
            "lea": self._lift_lea,
            "add": self._lift_add,
            "sub": self._lift_sub,
            "xor": self._lift_xor,
            "and": self._lift_and,
            "or": self._lift_or,
            "shl": self._lift_shift,
            "shr": self._lift_shift,
            "cmp": self._lift_cmp,
            "test": self._lift_test,
            "push": self._lift_push,
            "pop": self._lift_pop,
            "call": self._lift_call,
            "ret": self._lift_ret,
            "retq": self._lift_ret,
            "jmp": self._lift_jmp,
            "jmpq": self._lift_jmp,
            "nop": self._lift_nop,
            "syscall": self._lift_syscall,
            "int": self._lift_interrupt,
        }

        # Conditional jumps (je, jne, jl, …)
        if mnemonic.startswith("j") and mnemonic not in ("jmp", "jmpq"):
            return self._lift_conditional_jump(mnemonic, operands, instr)

        handler = handlers.get(mnemonic)
        if handler:
            return handler(operands, instr)

        # Unknown mnemonic — conservatively return no effects
        return []

    # -- mnemonic handlers --------------------------------------------------

    def _lift_mov(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst_expr = self._operand_to_expr(operands[0])
        src_expr = self._operand_to_expr(operands[1])
        effects: list[Effect] = []
        if isinstance(src_expr, MemRef):
            effects.append(MemoryRead(src_expr.address, src_expr.size))
        if isinstance(dst_expr, Reg):
            effects.append(RegisterWrite(dst_expr.name, src_expr))
        elif isinstance(dst_expr, MemRef):
            effects.append(MemoryWrite(dst_expr.address, src_expr, dst_expr.size))
        return effects

    def _lift_lea(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst = self._operand_to_expr(operands[0])
        src_str = operands[1].strip()
        if "[" in src_str:
            inner = src_str[src_str.index("[") + 1 : src_str.index("]")]
            addr_expr = self._parse_mem_expr(inner)
        else:
            addr_expr = self._operand_to_expr(src_str)
        if isinstance(dst, Reg):
            return [RegisterWrite(dst.name, addr_expr)]
        return []

    def _lift_add(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst = self._operand_to_expr(operands[0])
        src = self._operand_to_expr(operands[1])
        effects: list[Effect] = [FlagEffect(_ARITH_FLAGS)]
        if isinstance(dst, Reg):
            effects.append(RegisterWrite(dst.name, BinOp("+", dst, src)))
        return effects

    def _lift_sub(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst = self._operand_to_expr(operands[0])
        src = self._operand_to_expr(operands[1])
        effects: list[Effect] = [FlagEffect(_ARITH_FLAGS)]
        if isinstance(dst, Reg):
            effects.append(RegisterWrite(dst.name, BinOp("-", dst, src)))
        return effects

    def _lift_xor(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst = self._operand_to_expr(operands[0])
        src = self._operand_to_expr(operands[1])
        effects: list[Effect] = [FlagEffect(_LOGIC_FLAGS)]
        if isinstance(dst, Reg):
            # xor reg, reg → zero idiom
            if isinstance(src, Reg) and dst.name == src.name:
                effects.append(RegisterWrite(dst.name, Const(0)))
            else:
                effects.append(RegisterWrite(dst.name, BinOp("^", dst, src)))
        return effects

    def _lift_and(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst = self._operand_to_expr(operands[0])
        src = self._operand_to_expr(operands[1])
        effects: list[Effect] = [FlagEffect(_LOGIC_FLAGS)]
        if isinstance(dst, Reg):
            effects.append(RegisterWrite(dst.name, BinOp("&", dst, src)))
        return effects

    def _lift_or(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst = self._operand_to_expr(operands[0])
        src = self._operand_to_expr(operands[1])
        effects: list[Effect] = [FlagEffect(_LOGIC_FLAGS)]
        if isinstance(dst, Reg):
            effects.append(RegisterWrite(dst.name, BinOp("|", dst, src)))
        return effects

    def _lift_shift(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if len(operands) < 2:
            return []
        dst = self._operand_to_expr(operands[0])
        amount = self._operand_to_expr(operands[1])
        op = "<<" if "shl" in instr.mnemonic else ">>"
        effects: list[Effect] = [FlagEffect(_LOGIC_FLAGS)]
        if isinstance(dst, Reg):
            effects.append(RegisterWrite(dst.name, BinOp(op, dst, amount)))
        return effects

    def _lift_cmp(self, operands: list[str], instr: Instruction) -> list[Effect]:
        return [FlagEffect(_ARITH_FLAGS)]

    def _lift_test(self, operands: list[str], instr: Instruction) -> list[Effect]:
        return [FlagEffect(_LOGIC_FLAGS)]

    def _lift_push(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if not operands:
            return []
        val = self._operand_to_expr(operands[0])
        return [
            StackEffect("push", val, 8),
            RegisterWrite("rsp", BinOp("-", Reg("rsp"), Const(8))),
            MemoryWrite(Reg("rsp"), val, 8),
        ]

    def _lift_pop(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if not operands:
            return []
        dst = self._operand_to_expr(operands[0])
        effects: list[Effect] = [
            MemoryRead(Reg("rsp"), 8),
            StackEffect("pop", MemRef(Reg("rsp")), 8),
            RegisterWrite("rsp", BinOp("+", Reg("rsp"), Const(8))),
        ]
        if isinstance(dst, Reg):
            effects.append(RegisterWrite(dst.name, MemRef(Reg("rsp"))))
        return effects

    def _lift_call(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if not operands:
            return []
        target = self._operand_to_expr(operands[0])
        return [
            StackEffect("push", Const(instr.address + instr.size), 8),
            ControlFlowEffect(target, conditional=False, is_call=True),
        ]

    def _lift_ret(self, operands: list[str], instr: Instruction) -> list[Effect]:
        return [
            StackEffect("pop", MemRef(Reg("rsp")), 8),
            ControlFlowEffect(MemRef(Reg("rsp")), conditional=False, is_return=True),
        ]

    def _lift_jmp(self, operands: list[str], instr: Instruction) -> list[Effect]:
        if not operands:
            return []
        target = self._operand_to_expr(operands[0])
        return [ControlFlowEffect(target, conditional=False)]

    def _lift_conditional_jump(
        self, mnemonic: str, operands: list[str], instr: Instruction
    ) -> list[Effect]:
        if not operands:
            return []
        target = self._operand_to_expr(operands[0])
        return [ControlFlowEffect(target, conditional=True)]

    def _lift_nop(self, operands: list[str], instr: Instruction) -> list[Effect]:
        return []

    def _lift_syscall(self, operands: list[str], instr: Instruction) -> list[Effect]:
        return [ControlFlowEffect(Const(0), conditional=False, is_call=True)]

    def _lift_interrupt(self, operands: list[str], instr: Instruction) -> list[Effect]:
        return [ControlFlowEffect(Const(0), conditional=False, is_call=True)]


# Type alias for handler signatures
_Handler = Callable[[list[str], Instruction], list[Effect]]
