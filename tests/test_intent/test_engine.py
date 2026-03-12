"""Tests for the Intent-to-Binary Engine."""

from __future__ import annotations

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.intent.engine import (
    ChangeReturnValue,
    CompilationContext,
    ForceJump,
    InjectCode,
    InsertCheck,
    IntentCompiler,
    Nop,
    ReplaceCall,
)


def _make_binary(size: int = 1000) -> BinaryFile:
    return BinaryFile.from_bytes(b"\x90" * size, name="test")


# --- CompilationContext ---


class TestCompilationContext:
    def test_context_for_binary(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        assert ctx.binary is binary
        assert ctx.arch in (Arch.X86_64, Arch.X86_32, Arch.ARM64, Arch.ARM32)

    def test_context_has_assembler(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        assert ctx.assembler is not None


# --- Nop intent ---


class TestNop:
    def test_nop_compile(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = Nop(0x10, 5).compile(ctx)
        assert len(patches) == 1
        assert patches[0].data == b"\x90" * 5

    def test_nop_describe(self):
        desc = Nop(0x10, 5).describe()
        assert isinstance(desc, str)
        assert "NOP" in desc or "nop" in desc.lower()

    def test_nop_correct_offset(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = Nop(0x20, 3).compile(ctx)
        assert patches[0].offset == 0x20


# --- ChangeReturnValue ---


class TestChangeReturnValue:
    def test_change_return_value(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ChangeReturnValue(func_offset=0x100, new_value=42).compile(ctx)
        assert len(patches) == 1
        data = patches[0].data
        # x86_64: mov eax, 42 → includes 0x2a; ret → ends with 0xc3
        assert 0x2A in data  # immediate value 42
        assert data[-1] == 0xC3  # ret

    def test_change_return_value_patch_offset(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ChangeReturnValue(func_offset=0x50, new_value=1).compile(ctx)
        assert patches[0].offset == 0x50

    def test_change_return_value_describe(self):
        desc = ChangeReturnValue(func_offset=0x100, new_value=42).describe()
        assert isinstance(desc, str)
        assert "42" in desc


# --- ReplaceCall ---


class TestReplaceCall:
    def test_replace_call(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ReplaceCall(call_offset=0x10, new_target=0x200).compile(ctx)
        assert len(patches) == 1
        data = patches[0].data
        assert data[0] == 0xE8

    def test_replace_call_size(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ReplaceCall(call_offset=0x10, new_target=0x200).compile(ctx)
        assert len(patches[0].data) == 5

    def test_replace_call_opcode(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ReplaceCall(call_offset=0x10, new_target=0x200).compile(ctx)
        assert patches[0].data[0] == 0xE8


# --- InsertCheck ---


class TestInsertCheck:
    def test_insert_check(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        intent = InsertCheck(offset=0x100, reg="eax", condition="zero", fail_value=-1)
        patches = intent.compile(ctx)
        assert len(patches) == 1
        data = patches[0].data
        # Should contain test+branch+mov+ret sequence — at minimum has a ret (0xc3)
        assert 0xC3 in data

    def test_insert_check_produces_code(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        intent = InsertCheck(offset=0x100, reg="eax", condition="nonzero")
        patches = intent.compile(ctx)
        assert len(patches[0].data) > 0


# --- InjectCode ---


class TestInjectCode:
    def test_inject_code(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = InjectCode(offset=0x10, assembly="nop; nop").compile(ctx)
        assert len(patches) == 1
        assert patches[0].data == b"\x90\x90"

    def test_inject_code_offset(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = InjectCode(offset=0x30, assembly="nop").compile(ctx)
        assert patches[0].offset == 0x30


# --- ForceJump ---


class TestForceJump:
    def test_force_jump(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ForceJump(offset=0x10, target=0x200).compile(ctx)
        assert len(patches) == 1
        assert patches[0].data[0] == 0xE9

    def test_force_jump_size(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ForceJump(offset=0x10, target=0x200).compile(ctx)
        assert len(patches[0].data) == 5

    def test_force_jump_opcode(self):
        binary = _make_binary()
        ctx = CompilationContext.for_binary(binary)
        patches = ForceJump(offset=0x10, target=0x200).compile(ctx)
        assert patches[0].data[0] == 0xE9


# --- IntentCompiler ---


class TestIntentCompiler:
    def test_compile_multiple_intents(self):
        binary = _make_binary()
        compiler = IntentCompiler()
        intents = [
            Nop(0x10, 5),
            ChangeReturnValue(func_offset=0x100, new_value=0),
            ForceJump(offset=0x50, target=0x200),
        ]
        patches = compiler.compile(binary, intents)
        assert len(patches) == 3

    def test_compile_one(self):
        binary = _make_binary()
        compiler = IntentCompiler()
        patches = compiler.compile_one(binary, Nop(0x10, 3))
        assert len(patches) == 1
        assert patches[0].data == b"\x90" * 3

    def test_preview(self):
        compiler = IntentCompiler()
        intents = [Nop(0x10, 5), ForceJump(offset=0x50, target=0x200)]
        descriptions = compiler.preview(intents)
        assert len(descriptions) == 2
        assert all(isinstance(d, str) for d in descriptions)

    def test_preview_order(self):
        compiler = IntentCompiler()
        intents = [Nop(0x10, 5), ForceJump(offset=0x50, target=0x200)]
        descriptions = compiler.preview(intents)
        assert descriptions[0] == Nop(0x10, 5).describe()
        assert descriptions[1] == ForceJump(offset=0x50, target=0x200).describe()


# --- Edge cases ---


class TestEdgeCases:
    def test_empty_intent_list(self):
        binary = _make_binary()
        compiler = IntentCompiler()
        patches = compiler.compile(binary, [])
        assert patches == []
