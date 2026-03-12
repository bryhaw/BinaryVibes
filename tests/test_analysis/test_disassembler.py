"""Tests for the disassembly engine."""

from __future__ import annotations

from binaryvibes.analysis.disassembler import Disassembler, Instruction
from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler

BASE_ADDR = 0x00401000


# ── Creation ────────────────────────────────────────────────────────


def test_disassembler_creation():
    dis = Disassembler(Arch.X86_64)
    assert dis is not None


# ── Disassemble known code ──────────────────────────────────────────


def test_disassemble_known_code(x86_code_bytes: bytes):
    dis = Disassembler(Arch.X86_64)
    instructions = dis.disassemble(x86_code_bytes, BASE_ADDR)
    assert isinstance(instructions, list)
    assert len(instructions) == 3


def test_instruction_fields(x86_code_bytes: bytes):
    dis = Disassembler(Arch.X86_64)
    insn = dis.disassemble(x86_code_bytes, BASE_ADDR)[0]
    assert insn.mnemonic == "mov"
    assert "rax" in insn.op_str


def test_instruction_addresses(x86_code_bytes: bytes):
    dis = Disassembler(Arch.X86_64)
    instructions = dis.disassemble(x86_code_bytes, BASE_ADDR)
    assert instructions[0].address == BASE_ADDR
    from itertools import pairwise

    for prev, cur in pairwise(instructions):
        assert cur.address == prev.address + prev.size


def test_instruction_raw_bytes(x86_code_bytes: bytes):
    dis = Disassembler(Arch.X86_64)
    instructions = dis.disassemble(x86_code_bytes, BASE_ADDR)
    offset = 0
    for insn in instructions:
        assert insn.raw == x86_code_bytes[offset : offset + insn.size]
        offset += insn.size


def test_instruction_size(x86_code_bytes: bytes):
    dis = Disassembler(Arch.X86_64)
    instructions = dis.disassemble(x86_code_bytes, BASE_ADDR)
    for insn in instructions:
        assert insn.size > 0


def test_instruction_str_format(x86_code_bytes: bytes):
    dis = Disassembler(Arch.X86_64)
    insn = dis.disassemble(x86_code_bytes, BASE_ADDR)[0]
    s = str(insn)
    assert s.startswith("0x00401000:")
    assert "mov" in s


# ── disassemble_one ─────────────────────────────────────────────────


def test_disassemble_one(x86_code_bytes: bytes):
    dis = Disassembler(Arch.X86_64)
    insn = dis.disassemble_one(x86_code_bytes, BASE_ADDR)
    assert isinstance(insn, Instruction)
    assert insn.mnemonic == "mov"


def test_disassemble_one_empty():
    dis = Disassembler(Arch.X86_64)
    assert dis.disassemble_one(b"", BASE_ADDR) is None


# ── Edge cases ──────────────────────────────────────────────────────


def test_disassemble_empty():
    dis = Disassembler(Arch.X86_64)
    assert dis.disassemble(b"", BASE_ADDR) == []


# ── Other architectures ────────────────────────────────────────────


def test_disassemble_x86_32():
    asm = Assembler(Arch.X86_32)
    code = asm.assemble("nop; nop; ret")
    dis = Disassembler(Arch.X86_32)
    instructions = dis.disassemble(code, BASE_ADDR)
    assert len(instructions) == 3
    assert instructions[0].mnemonic == "nop"
    assert instructions[2].mnemonic == "ret"


# ── Round-trip ──────────────────────────────────────────────────────


def test_round_trip_with_assembler():
    asm = Assembler(Arch.X86_64)
    code = asm.assemble("nop")
    dis = Disassembler(Arch.X86_64)
    insn = dis.disassemble_one(code, BASE_ADDR)
    assert insn is not None
    assert insn.mnemonic == "nop"
