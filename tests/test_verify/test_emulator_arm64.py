"""Tests for ARM64 emulation support."""

import pytest

from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.verify.emulator import Emulator

BASE = 0x400000


@pytest.fixture
def asm():
    return Assembler(Arch.ARM64)


@pytest.fixture
def emu():
    return Emulator(Arch.ARM64)


def test_arm64_mov_immediate(asm, emu):
    """MOV immediate loads a constant into a register."""
    code = asm.assemble("mov x0, #100", base_addr=BASE)
    result = emu.run(code, base=BASE, max_instructions=1)

    assert result.error is None
    assert result.final_registers["x0"] == 100


def test_arm64_add(asm, emu):
    """ADD computes the sum of two registers."""
    code = asm.assemble(
        "mov x0, #10\nmov x1, #20\nadd x2, x0, x1",
        base_addr=BASE,
    )
    result = emu.run(code, base=BASE, max_instructions=3)

    assert result.error is None
    assert result.final_registers["x2"] == 30


def test_arm64_multiple_registers(asm, emu):
    """Multiple MOV instructions set distinct registers."""
    code = asm.assemble(
        "mov x0, #1\nmov x1, #2\nmov x2, #3\nmov x3, #4",
        base_addr=BASE,
    )
    result = emu.run(code, base=BASE, max_instructions=4)

    assert result.error is None
    assert result.final_registers["x0"] == 1
    assert result.final_registers["x1"] == 2
    assert result.final_registers["x2"] == 3
    assert result.final_registers["x3"] == 4


def test_arm64_stack_pointer(asm, emu):
    """SP register is accessible in the emulation result."""
    code = asm.assemble("mov x0, #1", base_addr=BASE)
    result = emu.run(code, base=BASE, max_instructions=1)

    assert result.error is None
    assert "sp" in result.final_registers


def test_arm64_pc_advances(asm, emu):
    """PC advances beyond the base address after execution."""
    code = asm.assemble(
        "mov x0, #1\nmov x1, #2",
        base_addr=BASE,
    )
    result = emu.run(code, base=BASE, max_instructions=2)

    assert result.error is None
    assert result.final_registers["pc"] > BASE


def test_arm64_max_instructions(asm, emu):
    """max_instructions caps the number of instructions executed."""
    code = asm.assemble(
        "mov x0, #1\nmov x1, #2\nmov x2, #3\nmov x3, #4\nmov x4, #5",
        base_addr=BASE,
    )
    result = emu.run(code, base=BASE, max_instructions=2)

    assert result.error is None
    assert result.instructions_executed == 2
    # Only the first two registers should be set
    assert result.final_registers["x0"] == 1
    assert result.final_registers["x1"] == 2
    # x2-x4 should still be zero (not executed)
    assert result.final_registers["x2"] == 0
