"""Tests for the emulation-based verification module."""

from __future__ import annotations

import pytest

from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.verify.emulator import Emulator

# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_emulator_x86_64_creation() -> None:
    emu = Emulator(Arch.X86_64)
    assert emu is not None


def test_emulator_arm64_creation() -> None:
    emu = Emulator(Arch.ARM64)
    assert emu is not None


def test_unsupported_arch() -> None:
    with pytest.raises(NotImplementedError, match=r"(?i)arm32"):
        Emulator(Arch.ARM32)


# ---------------------------------------------------------------------------
# x86-64 emulation
# ---------------------------------------------------------------------------


def test_run_simple_x86_64() -> None:
    asm = Assembler(Arch.X86_64)
    code = asm.assemble("mov rax, 42")
    emu = Emulator(Arch.X86_64)
    result = emu.run(code, max_instructions=1)

    assert result.final_registers["rax"] == 42
    assert result.error is None


def test_run_multiple_instructions_x86_64() -> None:
    asm = Assembler(Arch.X86_64)
    code = asm.assemble("mov rax, 1; mov rbx, 2")
    emu = Emulator(Arch.X86_64)
    result = emu.run(code, max_instructions=2)

    assert result.final_registers["rax"] == 1
    assert result.final_registers["rbx"] == 2
    assert result.error is None


def test_emulation_result_fields() -> None:
    asm = Assembler(Arch.X86_64)
    code = asm.assemble("mov rax, 1")
    emu = Emulator(Arch.X86_64)
    result = emu.run(code, max_instructions=1)

    assert result.instructions_executed > 0
    assert isinstance(result.final_registers, dict)
    assert result.error is None


# ---------------------------------------------------------------------------
# ARM64 emulation
# ---------------------------------------------------------------------------


def test_run_arm64_simple() -> None:
    asm = Assembler(Arch.ARM64)
    code = asm.assemble("mov x0, #42", 0)
    emu = Emulator(Arch.ARM64)
    result = emu.run(code, max_instructions=1)

    assert result.final_registers["x0"] == 42
    assert result.error is None


def test_arm64_registers() -> None:
    asm = Assembler(Arch.ARM64)
    code = asm.assemble("mov x0, #42", 0)
    emu = Emulator(Arch.ARM64)
    result = emu.run(code, max_instructions=1)

    assert "x0" in result.final_registers
    assert "sp" in result.final_registers
    assert "pc" in result.final_registers


# ---------------------------------------------------------------------------
# Instruction limits & error paths
# ---------------------------------------------------------------------------


def test_max_instructions_limit() -> None:
    asm = Assembler(Arch.X86_64)
    code = asm.assemble("mov rax, 1; mov rbx, 2; mov rcx, 3")
    emu = Emulator(Arch.X86_64)
    result = emu.run(code, max_instructions=1)

    assert result.instructions_executed == 1


def test_emulation_error() -> None:
    # Assemble a jump to unmapped memory to trigger a clean emulation error.
    asm = Assembler(Arch.X86_64)
    # "jmp 0xDEAD0000" — jumps far outside the mapped region
    code = asm.assemble("mov rax, 0xDEAD0000; jmp rax")
    emu = Emulator(Arch.X86_64)
    result = emu.run(code, max_instructions=10)

    assert result.error is not None
