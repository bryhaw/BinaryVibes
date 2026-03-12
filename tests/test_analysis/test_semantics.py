"""Tests for the Binary Semantics Engine."""

from __future__ import annotations

from binaryvibes.analysis.disassembler import Disassembler
from binaryvibes.analysis.semantics import (
    BinOp,
    Const,
    ControlFlowEffect,
    Effect,
    FlagEffect,
    MemoryRead,
    MemoryWrite,
    MemRef,
    Reg,
    RegisterWrite,
    SemanticInstruction,
    SemanticLifter,
    StackEffect,
)
from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler

BASE = 0x400000

_asm = Assembler(Arch.X86_64)
_dis = Disassembler(Arch.X86_64)
_lifter = SemanticLifter()


def _lift_asm(asm_code: str) -> list[SemanticInstruction]:
    code = _asm.assemble(asm_code, BASE)
    instrs = _dis.disassemble(code, BASE)
    return _lifter.lift_block(instrs)


def _lift_one(asm_code: str) -> SemanticInstruction:
    """Lift a single instruction and return it."""
    sems = _lift_asm(asm_code)
    assert len(sems) >= 1
    return sems[0]


def _effects_of_type(sem: SemanticInstruction, cls: type) -> list[Effect]:
    return [e for e in sem.effects if isinstance(e, cls)]


# ---------------------------------------------------------------------------
# Expression tree __str__ tests
# ---------------------------------------------------------------------------


class TestExpressionStr:
    def test_const_small(self):
        assert str(Const(0)) == "0"
        assert str(Const(9)) == "9"

    def test_const_hex(self):
        assert str(Const(10)) == "0xa"
        assert str(Const(42)) == "0x2a"
        assert str(Const(255)) == "0xff"

    def test_reg(self):
        assert str(Reg("rax")) == "rax"
        assert str(Reg("rsp")) == "rsp"

    def test_binop(self):
        expr = BinOp("+", Reg("rax"), Const(1))
        assert str(expr) == "(rax + 1)"

    def test_binop_nested(self):
        inner = BinOp("*", Reg("rcx"), Const(4))
        outer = BinOp("+", Reg("rax"), inner)
        assert str(outer) == "(rax + (rcx * 4))"

    def test_memref(self):
        m = MemRef(Reg("rsp"), size=8)
        assert str(m) == "[rsp]:8"


# ---------------------------------------------------------------------------
# Effect __str__ tests
# ---------------------------------------------------------------------------


class TestEffectStr:
    def test_register_write(self):
        e = RegisterWrite("rax", Const(42))
        assert str(e) == "rax := 0x2a"

    def test_memory_write(self):
        e = MemoryWrite(Reg("rsp"), Const(0), 8)
        assert str(e) == "[rsp]:8 := 0"

    def test_memory_read(self):
        e = MemoryRead(Reg("rsp"), 8)
        assert str(e) == "read [rsp]:8"

    def test_flag_effect(self):
        e = FlagEffect(("ZF", "SF", "CF"))
        assert str(e) == "flags(ZF, SF, CF)"

    def test_control_flow_branch(self):
        e = ControlFlowEffect(Const(0x401000), conditional=False)
        assert str(e) == "branch → 0x401000"

    def test_control_flow_call(self):
        e = ControlFlowEffect(Const(0x401000), conditional=False, is_call=True)
        assert str(e) == "call → 0x401000"

    def test_control_flow_ret(self):
        e = ControlFlowEffect(MemRef(Reg("rsp")), conditional=False, is_return=True)
        assert str(e) == "ret → [rsp]:8"

    def test_control_flow_conditional(self):
        e = ControlFlowEffect(Const(0x401000), conditional=True)
        assert str(e) == "conditional branch → 0x401000"

    def test_stack_effect_push(self):
        e = StackEffect("push", Reg("rax"), 8)
        assert str(e) == "push rax (8B)"

    def test_stack_effect_pop(self):
        e = StackEffect("pop", MemRef(Reg("rsp")), 8)
        assert str(e) == "pop [rsp]:8 (8B)"


# ---------------------------------------------------------------------------
# Instruction lifting tests
# ---------------------------------------------------------------------------


class TestMovImmediate:
    def test_mov_immediate(self):
        sem = _lift_one("mov rax, 42")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, Const)
        assert rw.value.value == 42


class TestMovRegToReg:
    def test_mov_reg_to_reg(self):
        sem = _lift_one("mov rax, rbx")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, Reg)
        assert rw.value.name == "rbx"


class TestAddInstruction:
    def test_add_has_register_write(self):
        sem = _lift_one("add rax, 8")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == "+"

    def test_add_has_flag_effect(self):
        sem = _lift_one("add rax, 8")
        flags = _effects_of_type(sem, FlagEffect)
        assert len(flags) == 1
        assert "ZF" in flags[0].flags_modified
        assert "CF" in flags[0].flags_modified


class TestSubInstruction:
    def test_sub_register_write(self):
        sem = _lift_one("sub rax, 1")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == "-"

    def test_sub_has_flags(self):
        sem = _lift_one("sub rax, 1")
        flags = _effects_of_type(sem, FlagEffect)
        assert len(flags) == 1


class TestXorSelfZeroes:
    def test_xor_self_produces_const_zero(self):
        sem = _lift_one("xor rax, rax")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, Const)
        assert rw.value.value == 0

    def test_xor_self_has_flag_effect(self):
        sem = _lift_one("xor rax, rax")
        flags = _effects_of_type(sem, FlagEffect)
        assert len(flags) == 1


class TestXorDifferentRegs:
    def test_xor_different_regs_is_binop(self):
        sem = _lift_one("xor rax, rbx")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == "^"


class TestPushEffects:
    def test_push_has_stack_effect(self):
        sem = _lift_one("push rax")
        stacks = _effects_of_type(sem, StackEffect)
        assert len(stacks) == 1
        assert stacks[0].operation == "push"

    def test_push_writes_rsp(self):
        sem = _lift_one("push rax")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        rsp_writes = [rw for rw in reg_writes if rw.register == "rsp"]
        assert len(rsp_writes) == 1

    def test_push_has_memory_write(self):
        sem = _lift_one("push rax")
        mem_writes = _effects_of_type(sem, MemoryWrite)
        assert len(mem_writes) == 1


class TestPopEffects:
    def test_pop_has_stack_effect(self):
        sem = _lift_one("pop rax")
        stacks = _effects_of_type(sem, StackEffect)
        assert len(stacks) == 1
        assert stacks[0].operation == "pop"

    def test_pop_has_memory_read(self):
        sem = _lift_one("pop rax")
        reads = _effects_of_type(sem, MemoryRead)
        assert len(reads) == 1

    def test_pop_writes_rsp(self):
        sem = _lift_one("pop rax")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        rsp_writes = [rw for rw in reg_writes if rw.register == "rsp"]
        assert len(rsp_writes) == 1

    def test_pop_writes_destination(self):
        sem = _lift_one("pop rax")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        rax_writes = [rw for rw in reg_writes if rw.register == "rax"]
        assert len(rax_writes) == 1


class TestCallEffects:
    def test_call_has_control_flow(self):
        # "call label\nlabel: nop" — the call targets the nop
        sem = _lift_one("call 0x400010")
        cfs = _effects_of_type(sem, ControlFlowEffect)
        assert len(cfs) == 1
        assert cfs[0].is_call is True
        assert cfs[0].conditional is False

    def test_call_has_stack_push(self):
        sem = _lift_one("call 0x400010")
        stacks = _effects_of_type(sem, StackEffect)
        assert len(stacks) == 1
        assert stacks[0].operation == "push"


class TestRetEffects:
    def test_ret_has_control_flow(self):
        sem = _lift_one("ret")
        cfs = _effects_of_type(sem, ControlFlowEffect)
        assert len(cfs) == 1
        assert cfs[0].is_return is True
        assert cfs[0].conditional is False

    def test_ret_has_stack_pop(self):
        sem = _lift_one("ret")
        stacks = _effects_of_type(sem, StackEffect)
        assert len(stacks) == 1
        assert stacks[0].operation == "pop"


class TestJmpEffects:
    def test_jmp_unconditional(self):
        sem = _lift_one("jmp 0x400010")
        cfs = _effects_of_type(sem, ControlFlowEffect)
        assert len(cfs) == 1
        assert cfs[0].conditional is False
        assert cfs[0].is_call is False
        assert cfs[0].is_return is False


class TestConditionalJump:
    def test_cmp_je_sequence(self):
        sems = _lift_asm("cmp rax, 0; je 0x400010")
        # First instruction: cmp → FlagEffect
        cmp_sem = sems[0]
        flags = _effects_of_type(cmp_sem, FlagEffect)
        assert len(flags) == 1

        # Second instruction: je → ControlFlowEffect with conditional=True
        je_sem = sems[1]
        cfs = _effects_of_type(je_sem, ControlFlowEffect)
        assert len(cfs) == 1
        assert cfs[0].conditional is True


class TestNopNoEffects:
    def test_nop_empty_effects(self):
        sem = _lift_one("nop")
        assert sem.effects == []


class TestCmpOnlyFlags:
    def test_cmp_only_flags(self):
        sem = _lift_one("cmp rax, rbx")
        assert len(sem.effects) == 1
        assert isinstance(sem.effects[0], FlagEffect)
        assert "AF" in sem.effects[0].flags_modified  # arithmetic flags


class TestTestOnlyFlags:
    def test_test_only_flags(self):
        sem = _lift_one("test rax, rax")
        assert len(sem.effects) == 1
        assert isinstance(sem.effects[0], FlagEffect)
        # test uses logic flags — no AF
        assert "AF" not in sem.effects[0].flags_modified
        assert "ZF" in sem.effects[0].flags_modified


class TestSemanticInstructionProperties:
    def test_writes_registers(self):
        sem = _lift_one("mov rax, 42")
        assert "rax" in sem.writes_registers

    def test_reads_memory(self):
        sem = _lift_one("pop rax")
        assert sem.reads_memory is True

    def test_reads_memory_false(self):
        sem = _lift_one("mov rax, 42")
        assert sem.reads_memory is False

    def test_writes_memory(self):
        sem = _lift_one("push rax")
        assert sem.writes_memory is True

    def test_writes_memory_false(self):
        sem = _lift_one("mov rax, 42")
        assert sem.writes_memory is False

    def test_is_control_flow(self):
        sem = _lift_one("ret")
        assert sem.is_control_flow is True

    def test_is_not_control_flow(self):
        sem = _lift_one("mov rax, 42")
        assert sem.is_control_flow is False


class TestLiftBlock:
    def test_lift_block_multiple_instructions(self):
        sems = _lift_asm("mov rax, 1; add rax, 2; ret")
        assert len(sems) == 3
        assert all(isinstance(s, SemanticInstruction) for s in sems)

    def test_lift_block_preserves_order(self):
        sems = _lift_asm("push rax; pop rbx")
        assert len(sems) == 2
        # First is push, second is pop
        assert any(isinstance(e, StackEffect) and e.operation == "push" for e in sems[0].effects)
        assert any(isinstance(e, StackEffect) and e.operation == "pop" for e in sems[1].effects)

    def test_lift_block_empty(self):
        sems = _lifter.lift_block([])
        assert sems == []


class TestSemanticInstructionStr:
    def test_str_format(self):
        sem = _lift_one("nop")
        s = str(sem)
        # Should contain the instruction text and effects brackets
        assert "nop" in s
        assert "→" in s
        assert "[" in s and "]" in s


# ---------------------------------------------------------------------------
# LEA instruction
# ---------------------------------------------------------------------------


class TestLeaInstruction:
    def test_lea_reg_plus_offset(self):
        sem = _lift_one("lea rax, [rbx + 8]")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        # LEA computes the address, does NOT dereference memory
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == "+"

    def test_lea_no_memory_read(self):
        sem = _lift_one("lea rax, [rbx + 8]")
        assert sem.reads_memory is False


# ---------------------------------------------------------------------------
# AND instruction
# ---------------------------------------------------------------------------


class TestAndInstruction:
    def test_and_register_write(self):
        sem = _lift_one("and rax, 0xff")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == "&"

    def test_and_has_flag_effect(self):
        sem = _lift_one("and rax, 0xff")
        flags = _effects_of_type(sem, FlagEffect)
        assert len(flags) == 1
        assert "ZF" in flags[0].flags_modified


# ---------------------------------------------------------------------------
# OR instruction
# ---------------------------------------------------------------------------


class TestOrInstruction:
    def test_or_register_write(self):
        sem = _lift_one("or rax, 1")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == "|"

    def test_or_has_flag_effect(self):
        sem = _lift_one("or rax, 1")
        flags = _effects_of_type(sem, FlagEffect)
        assert len(flags) == 1
        assert "ZF" in flags[0].flags_modified


# ---------------------------------------------------------------------------
# Shift instructions (SHL / SHR)
# ---------------------------------------------------------------------------


class TestShiftInstructions:
    def test_shl_register_write(self):
        sem = _lift_one("shl rax, 4")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rax"
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == "<<"

    def test_shr_register_write(self):
        sem = _lift_one("shr rbx, 2")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        rw = reg_writes[0]
        assert rw.register == "rbx"
        assert isinstance(rw.value, BinOp)
        assert rw.value.op == ">>"

    def test_shift_has_flag_effect(self):
        sem = _lift_one("shl rax, 4")
        flags = _effects_of_type(sem, FlagEffect)
        assert len(flags) == 1


# ---------------------------------------------------------------------------
# Memory operand parsing (via MOV with memory operands)
# ---------------------------------------------------------------------------


class TestMemoryOperands:
    def test_mov_from_memory_offset(self):
        """mov rax, [rsp + 8] — MemoryRead with parsed address."""
        sem = _lift_one("mov rax, [rsp + 8]")
        reads = _effects_of_type(sem, MemoryRead)
        assert len(reads) == 1
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 1
        assert reg_writes[0].register == "rax"
        # The source should be a MemRef
        assert isinstance(reg_writes[0].value, MemRef)

    def test_mov_to_memory(self):
        """mov [rsp], rax → MemoryWrite effect."""
        sem = _lift_one("mov [rsp], rax")
        mem_writes = _effects_of_type(sem, MemoryWrite)
        assert len(mem_writes) == 1
        assert sem.writes_memory is True

    def test_mov_to_memory_no_register_write(self):
        """mov [rsp], rax — destination is memory, not a register."""
        sem = _lift_one("mov [rsp], rax")
        reg_writes = _effects_of_type(sem, RegisterWrite)
        assert len(reg_writes) == 0

    def test_push_immediate(self):
        """push 0x42 — pushes a constant, exercises memory-operand code path."""
        sem = _lift_one("push 0x42")
        stacks = _effects_of_type(sem, StackEffect)
        assert len(stacks) == 1
        assert stacks[0].operation == "push"
        mem_writes = _effects_of_type(sem, MemoryWrite)
        assert len(mem_writes) == 1


# ---------------------------------------------------------------------------
# _parse_mem_expr coverage (complex address expressions)
# ---------------------------------------------------------------------------


class TestParseMemExpr:
    """Directly test _parse_mem_expr for complex address forms."""

    def test_simple_register(self):
        expr = _lifter._parse_mem_expr("rax")
        assert isinstance(expr, Reg)
        assert expr.name == "rax"

    def test_register_plus_offset(self):
        expr = _lifter._parse_mem_expr("rsp + 8")
        assert isinstance(expr, BinOp)
        assert expr.op == "+"

    def test_register_minus_offset(self):
        expr = _lifter._parse_mem_expr("rsp - 0x10")
        assert isinstance(expr, BinOp)
        assert expr.op == "-"

    def test_scaled_index(self):
        expr = _lifter._parse_mem_expr("rax*4")
        assert isinstance(expr, BinOp)
        assert expr.op == "*"

    def test_hex_constant(self):
        expr = _lifter._parse_mem_expr("0x100")
        assert isinstance(expr, Const)
        assert expr.value == 0x100

    def test_decimal_constant(self):
        expr = _lifter._parse_mem_expr("42")
        assert isinstance(expr, Const)
        assert expr.value == 42

    def test_complex_base_plus_scaled_index(self):
        expr = _lifter._parse_mem_expr("rbx + rax*4")
        assert isinstance(expr, BinOp)
        assert expr.op == "+"

    def test_non_alpha_register_name(self):
        """Register names like 'r12' are not purely alpha — hits the fallback."""
        expr = _lifter._parse_mem_expr("r12")
        assert isinstance(expr, Reg)
        assert expr.name == "r12"


# ---------------------------------------------------------------------------
# INT instruction
# ---------------------------------------------------------------------------


class TestInterruptInstruction:
    def test_int_0x80(self):
        sem = _lift_one("int 0x80")
        cfs = _effects_of_type(sem, ControlFlowEffect)
        assert len(cfs) == 1
        assert cfs[0].is_call is True


# ---------------------------------------------------------------------------
# Unknown mnemonic — returns empty effects
# ---------------------------------------------------------------------------


class TestUnknownMnemonic:
    def test_unknown_mnemonic_returns_empty_effects(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake_instr = Instr(
            address=0x400000,
            mnemonic="ud2",
            op_str="",
            raw=b"\x0f\x0b",
            size=2,
        )
        sem = _lifter.lift(fake_instr)
        assert sem.effects == []


# ---------------------------------------------------------------------------
# Edge cases: empty operands handled by handlers
# ---------------------------------------------------------------------------


class TestEmptyOperandEdgeCases:
    def test_mov_single_operand(self):
        """MOV with < 2 operands should return empty effects."""
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="mov", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_push_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="push", op_str="", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_pop_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="pop", op_str="", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_lea_single_operand(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="lea", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_add_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="add", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_sub_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="sub", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_xor_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="xor", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_and_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="and", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_or_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="or", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_shift_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="shl", op_str="rax", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_call_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="call", op_str="", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_jmp_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="jmp", op_str="", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []

    def test_je_no_operands(self):
        from binaryvibes.analysis.disassembler import Instruction as Instr

        fake = Instr(address=0x400000, mnemonic="je", op_str="", raw=b"\x00", size=1)
        sem = _lifter.lift(fake)
        assert sem.effects == []


# ---------------------------------------------------------------------------
# syscall instruction
# ---------------------------------------------------------------------------


class TestSyscallInstruction:
    def test_syscall_is_call_effect(self):
        sem = _lift_one("syscall")
        cfs = _effects_of_type(sem, ControlFlowEffect)
        assert len(cfs) == 1
        assert cfs[0].is_call is True
        assert cfs[0].conditional is False
