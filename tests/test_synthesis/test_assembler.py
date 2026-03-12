"""Tests for the assembly engine."""

from __future__ import annotations

import pytest

from binaryvibes.analysis.disassembler import Disassembler
from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler


class TestAssembler:
    """Assembler functionality tests."""

    def test_assemble_nop(self):
        asm = Assembler(Arch.X86_64)
        result = asm.assemble("nop", 0)
        assert result == b"\x90"

    def test_assemble_mov(self):
        asm = Assembler(Arch.X86_64)
        result = asm.assemble("mov rax, 1", 0)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_assemble_multiple(self):
        asm = Assembler(Arch.X86_64)
        result = asm.assemble("nop; nop; nop", 0)
        assert result == b"\x90\x90\x90"

    def test_assemble_invalid(self):
        asm = Assembler(Arch.X86_64)
        with pytest.raises((ValueError, Exception)):
            asm.assemble("invalid_mnemonic", 0)

    def test_assemble_x86_32(self):
        asm = Assembler(Arch.X86_32)
        result = asm.assemble("nop", 0)
        assert result == b"\x90"

    def test_round_trip(self):
        """Assemble an instruction, then disassemble it back — mnemonic must match."""
        asm = Assembler(Arch.X86_64)
        dis = Disassembler(Arch.X86_64)

        code = asm.assemble("nop", 0)
        insn = dis.disassemble_one(code, 0)

        assert insn is not None
        assert insn.mnemonic == "nop"
