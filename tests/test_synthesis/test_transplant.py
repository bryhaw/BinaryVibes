"""Tests for the Binary Transplant System."""

from __future__ import annotations

import struct

import pytest

from binaryvibes.analysis.cfg import BasicBlock, ControlFlowGraph
from binaryvibes.analysis.disassembler import Instruction
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.synthesis.patcher import Patch, apply_patches
from binaryvibes.synthesis.transplant import (
    FunctionExtractor,
    RelocationEntry,
    Transplanter,
    TransplantUnit,
    _parse_target,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ASM = Assembler(Arch.X86_64)


def _make_binary(code: bytes, *, pad: int = 256) -> BinaryFile:
    """Wrap *code* in a zero-padded buffer and return a BinaryFile."""
    data = code + b"\x00" * (pad - len(code)) if len(code) < pad else code
    return BinaryFile.from_bytes(data)


def _simple_code() -> bytes:
    """``mov rax, 42; ret`` — a trivial function."""
    return _ASM.assemble("mov rax, 42; ret", 0)


# ---------------------------------------------------------------------------
# TransplantUnit
# ---------------------------------------------------------------------------


class TestTransplantUnit:
    def test_creation(self):
        code = b"\xb8\x2a\x00\x00\x00\xc3"
        unit = TransplantUnit(
            code=code,
            arch=Arch.X86_64,
            source_addr=0x1000,
            name="my_func",
        )
        assert unit.code == code
        assert unit.arch is Arch.X86_64
        assert unit.source_addr == 0x1000
        assert unit.name == "my_func"

    def test_size_matches_code_length(self):
        code = b"\x90" * 10
        unit = TransplantUnit(code=code, arch=Arch.X86_64, source_addr=0)
        assert unit.size == 10

    def test_str_includes_name_and_size(self):
        unit = TransplantUnit(
            code=b"\x90\x90\x90",
            arch=Arch.X86_64,
            source_addr=0,
            name="nops",
        )
        text = str(unit)
        assert "nops" in text
        assert "3B" in text

    def test_needs_relocation_true_when_present(self):
        reloc = RelocationEntry(offset=0, rel_type="relative", target_symbol="ext_0x5000")
        unit = TransplantUnit(
            code=b"\xc3",
            arch=Arch.X86_64,
            source_addr=0,
            relocations=[reloc],
        )
        assert unit.needs_relocation is True

    def test_needs_relocation_false_when_empty(self):
        unit = TransplantUnit(code=b"\xc3", arch=Arch.X86_64, source_addr=0)
        assert unit.needs_relocation is False

    def test_instruction_count(self):
        unit = TransplantUnit(code=b"\xc3", arch=Arch.X86_64, source_addr=0, instructions=[1, 2, 3])
        assert unit.instruction_count == 3

    def test_str_with_relocations(self):
        reloc = RelocationEntry(offset=0, rel_type="relative", target_symbol="ext")
        unit = TransplantUnit(
            code=b"\xc3",
            arch=Arch.X86_64,
            source_addr=0,
            relocations=[reloc],
            name="f",
        )
        text = str(unit)
        assert "reloc" in text


# ---------------------------------------------------------------------------
# FunctionExtractor
# ---------------------------------------------------------------------------


class TestFunctionExtractor:
    def test_extract_simple_function(self):
        code = _simple_code()
        binary = _make_binary(code)
        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code))
        assert isinstance(unit, TransplantUnit)

    def test_extracted_has_code(self):
        code = _simple_code()
        binary = _make_binary(code)
        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code))
        assert isinstance(unit.code, bytes)
        assert len(unit.code) > 0

    def test_extracted_has_instructions(self):
        code = _simple_code()
        binary = _make_binary(code)
        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code))
        assert isinstance(unit.instructions, list)
        assert len(unit.instructions) > 0

    def test_extracted_has_cfg(self):
        code = _simple_code()
        binary = _make_binary(code)
        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code))
        assert isinstance(unit.cfg, ControlFlowGraph)

    def test_extract_with_name(self):
        code = _simple_code()
        binary = _make_binary(code)
        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code), name="answer")
        assert unit.name == "answer"

    def test_extract_default_name(self):
        code = _simple_code()
        binary = _make_binary(code)
        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code))
        assert "0x0" in unit.name

    def test_extract_invalid_offset(self):
        code = _simple_code()
        binary = _make_binary(code, pad=32)
        extractor = FunctionExtractor(Arch.X86_64)
        with pytest.raises(ValueError):
            extractor.extract_at(binary, 9999, max_size=64)


# ---------------------------------------------------------------------------
# Transplanter
# ---------------------------------------------------------------------------


class TestTransplanter:
    def _make_unit(self, size: int = 8) -> TransplantUnit:
        code = b"\x90" * size
        return TransplantUnit(
            code=code,
            arch=Arch.X86_64,
            source_addr=0,
            name="stub",
        )

    def test_transplant_generates_patches(self):
        unit = self._make_unit()
        target = _make_binary(b"\x00" * 64)
        transplanter = Transplanter(Arch.X86_64)
        patches = transplanter.transplant(unit, target, insert_offset=0)
        assert isinstance(patches, list)
        assert len(patches) > 0
        assert all(isinstance(p, Patch) for p in patches)

    def test_transplant_patch_at_correct_offset(self):
        unit = self._make_unit()
        target = _make_binary(b"\x00" * 64)
        transplanter = Transplanter(Arch.X86_64)
        patches = transplanter.transplant(unit, target, insert_offset=16)
        assert patches[0].offset == 16

    def test_transplant_patch_has_code(self):
        unit = self._make_unit(size=5)
        target = _make_binary(b"\x00" * 64)
        transplanter = Transplanter(Arch.X86_64)
        patches = transplanter.transplant(unit, target, insert_offset=0)
        assert len(patches[0].data) == unit.size

    def test_transplant_too_large(self):
        unit = self._make_unit(size=100)
        target = _make_binary(b"\x00" * 32, pad=32)
        transplanter = Transplanter(Arch.X86_64)
        with pytest.raises(ValueError):
            transplanter.transplant(unit, target, insert_offset=0)


# ---------------------------------------------------------------------------
# Trampoline
# ---------------------------------------------------------------------------


class TestTrampoline:
    def test_trampoline_is_jmp(self):
        t = Transplanter(Arch.X86_64)
        patch = t.create_trampoline(source_offset=0x100, target_offset=0x500)
        assert patch.data[0:1] == b"\xe9"

    def test_trampoline_correct_size(self):
        t = Transplanter(Arch.X86_64)
        patch = t.create_trampoline(source_offset=0, target_offset=0x100)
        assert len(patch.data) == 5

    def test_trampoline_displacement(self):
        source, target = 0x1000, 0x2000
        t = Transplanter(Arch.X86_64)
        patch = t.create_trampoline(source, target)
        # displacement = target - (source + 5)
        expected_disp = target - (source + 5)
        actual_disp = struct.unpack_from("<i", patch.data, 1)[0]
        assert actual_disp == expected_disp

    def test_trampoline_negative_displacement(self):
        source, target = 0x2000, 0x1000
        t = Transplanter(Arch.X86_64)
        patch = t.create_trampoline(source, target)
        expected_disp = target - (source + 5)
        actual_disp = struct.unpack_from("<i", patch.data, 1)[0]
        assert actual_disp == expected_disp
        assert actual_disp < 0

    def test_trampoline_patch_offset(self):
        t = Transplanter(Arch.X86_64)
        patch = t.create_trampoline(source_offset=0x400, target_offset=0x800)
        assert patch.offset == 0x400


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_extract_and_transplant(self):
        """Extract from binary A, transplant into binary B, verify code present."""
        code = _simple_code()
        source = _make_binary(code)

        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(source, 0, max_size=len(code), name="answer42")

        target_data = b"\xcc" * 256  # INT3 fill
        target = _make_binary(target_data, pad=256)

        transplanter = Transplanter(Arch.X86_64)
        patches = transplanter.transplant(unit, target, insert_offset=64)

        result = apply_patches(target, patches)

        # The transplanted code should appear at offset 64
        transplanted = result[64 : 64 + unit.size]
        assert len(transplanted) == unit.size
        assert transplanted != b"\xcc" * unit.size  # no longer just INT3

    def test_extract_transplant_with_trampoline(self):
        """Full flow: extract, transplant, add trampoline redirect."""
        code = _simple_code()
        source = _make_binary(code)

        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(source, 0, max_size=len(code))

        target_data = b"\xcc" * 512
        target = _make_binary(target_data, pad=512)

        transplanter = Transplanter(Arch.X86_64)
        transplant_offset = 256
        patches = transplanter.transplant(unit, target, insert_offset=transplant_offset)

        # Add a trampoline from offset 0 to the transplanted code
        trampoline = transplanter.create_trampoline(
            source_offset=0, target_offset=transplant_offset
        )
        all_patches = [*patches, trampoline]

        result = apply_patches(target, all_patches)

        # Trampoline at offset 0 should be a JMP
        assert result[0:1] == b"\xe9"
        # Transplanted code at offset 256 should be present
        assert result[transplant_offset : transplant_offset + unit.size] != b"\xcc" * unit.size


# ---------------------------------------------------------------------------
# _parse_target
# ---------------------------------------------------------------------------


class TestParseTarget:
    def test_hex_lowercase(self):
        assert _parse_target("0x1234") == 0x1234

    def test_hex_uppercase_prefix(self):
        assert _parse_target("0X1234") == 0x1234

    def test_decimal(self):
        assert _parse_target("4096") == 4096

    def test_register_indirect_returns_none(self):
        assert _parse_target("rax") is None

    def test_memory_operand_returns_none(self):
        assert _parse_target("[rax+0x10]") is None

    def test_whitespace_stripped(self):
        assert _parse_target("  0x100  ") == 0x100

    def test_empty_string_returns_none(self):
        assert _parse_target("") is None

    def test_non_numeric_label_returns_none(self):
        assert _parse_target("some_label") is None


# ---------------------------------------------------------------------------
# Relocation Detection
# ---------------------------------------------------------------------------


class TestRelocationDetection:
    def test_call_outside_region_detected(self):
        """CALL to address outside region → relocation entry."""
        instr = Instruction(
            address=0, mnemonic="call", op_str="0x5000", raw=b"\xe8" + b"\x00" * 4, size=5
        )
        relocs = FunctionExtractor._detect_relocations([instr], base_addr=0, region_size=100)
        assert len(relocs) == 1
        assert relocs[0].rel_type == "relative"
        assert "5000" in relocs[0].target_symbol

    def test_call_inside_region_no_relocation(self):
        """CALL to address within region → no relocation."""
        instr = Instruction(
            address=0, mnemonic="call", op_str="0x10", raw=b"\xe8" + b"\x00" * 4, size=5
        )
        relocs = FunctionExtractor._detect_relocations([instr], base_addr=0, region_size=100)
        assert len(relocs) == 0

    def test_jmp_outside_region_detected(self):
        instr = Instruction(
            address=0, mnemonic="jmp", op_str="0x2000", raw=b"\xe9" + b"\x00" * 4, size=5
        )
        relocs = FunctionExtractor._detect_relocations([instr], base_addr=0, region_size=100)
        assert len(relocs) == 1

    def test_conditional_jump_outside_region_detected(self):
        instr = Instruction(
            address=0, mnemonic="je", op_str="0x3000", raw=b"\x0f\x84" + b"\x00" * 4, size=6
        )
        relocs = FunctionExtractor._detect_relocations([instr], base_addr=0, region_size=100)
        assert len(relocs) == 1

    def test_non_branch_mnemonic_ignored(self):
        instr = Instruction(address=0, mnemonic="mov", op_str="0x5000", raw=b"\x00" * 5, size=5)
        relocs = FunctionExtractor._detect_relocations([instr], base_addr=0, region_size=100)
        assert len(relocs) == 0

    def test_indirect_call_no_relocation(self):
        """Register-indirect call → _parse_target returns None → no relocation."""
        instr = Instruction(address=0, mnemonic="call", op_str="rax", raw=b"\xff\xd0", size=2)
        relocs = FunctionExtractor._detect_relocations([instr], base_addr=0, region_size=100)
        assert len(relocs) == 0

    def test_call_at_region_boundary_detected(self):
        """Target exactly at region_end is outside the region."""
        instr = Instruction(
            address=0, mnemonic="call", op_str="0x64", raw=b"\xe8" + b"\x00" * 4, size=5
        )
        relocs = FunctionExtractor._detect_relocations([instr], base_addr=0, region_size=0x64)
        assert len(relocs) == 1

    def test_multiple_relocations(self):
        call_raw = b"\xe8" + b"\x00" * 4
        jmp_raw = b"\xe9" + b"\x00" * 4
        instrs = [
            Instruction(address=0, mnemonic="call", op_str="0x5000", raw=call_raw, size=5),
            Instruction(address=5, mnemonic="jmp", op_str="0x6000", raw=jmp_raw, size=5),
            Instruction(address=10, mnemonic="ret", op_str="", raw=b"\xc3", size=1),
        ]
        relocs = FunctionExtractor._detect_relocations(instrs, base_addr=0, region_size=20)
        assert len(relocs) == 2


# ---------------------------------------------------------------------------
# Relocation Code Adjustment (_relocate_code)
# ---------------------------------------------------------------------------


class TestRelocateCode:
    def test_adjusts_displacement_forward(self):
        """Transplanting to higher address adjusts call displacement down."""
        # E8 <4-byte signed displacement>; call to absolute target 0x5000 from addr 0
        original_disp = 0x5000 - 5  # target - (instr_addr + 5)
        code = b"\xe8" + struct.pack("<i", original_disp)

        instr = Instruction(address=0, mnemonic="call", op_str="0x5000", raw=code, size=5)
        reloc = RelocationEntry(offset=0, rel_type="relative", target_symbol="ext_0x5000")

        unit = TransplantUnit(
            code=code,
            arch=Arch.X86_64,
            source_addr=0,
            instructions=[instr],
            relocations=[reloc],
            name="test_func",
        )

        new_base = 0x1000
        relocated = Transplanter._relocate_code(unit, new_base)

        expected_disp = original_disp - new_base
        actual_disp = struct.unpack_from("<i", relocated, 1)[0]
        assert actual_disp == expected_disp

    def test_adjusts_displacement_backward(self):
        """Transplanting to lower address adjusts call displacement up."""
        original_disp = 0x1000 - 5
        code = b"\xe8" + struct.pack("<i", original_disp)

        instr = Instruction(address=0x2000, mnemonic="call", op_str="0x3000", raw=code, size=5)
        reloc = RelocationEntry(offset=0, rel_type="relative", target_symbol="ext_0x3000")

        unit = TransplantUnit(
            code=code,
            arch=Arch.X86_64,
            source_addr=0x2000,
            instructions=[instr],
            relocations=[reloc],
            name="test_func",
        )

        new_base = 0x1000  # delta = -0x1000
        relocated = Transplanter._relocate_code(unit, new_base)

        expected_disp = original_disp - (new_base - 0x2000)
        actual_disp = struct.unpack_from("<i", relocated, 1)[0]
        assert actual_disp == expected_disp

    def test_zero_delta_returns_unchanged(self):
        """When delta is 0, code is returned unchanged."""
        code = b"\xe8\xfb\x4f\x00\x00"
        unit = TransplantUnit(code=code, arch=Arch.X86_64, source_addr=0x1000, name="t")
        relocated = Transplanter._relocate_code(unit, 0x1000)
        assert relocated == code

    def test_skips_non_relative_relocations(self):
        """Only 'relative' relocations are adjusted; 'absolute' is skipped."""
        code = b"\xe8\xfb\x4f\x00\x00"
        instr = Instruction(address=0, mnemonic="call", op_str="0x5000", raw=code, size=5)
        reloc = RelocationEntry(offset=0, rel_type="absolute", target_symbol="ext_0x5000")

        unit = TransplantUnit(
            code=code,
            arch=Arch.X86_64,
            source_addr=0,
            instructions=[instr],
            relocations=[reloc],
            name="t",
        )
        relocated = Transplanter._relocate_code(unit, 0x1000)
        assert relocated == code

    def test_small_instruction_not_relocated(self):
        """Instructions smaller than 5 bytes should not be relocated."""
        code = b"\xeb\x10"  # short jmp
        instr = Instruction(address=0, mnemonic="jmp", op_str="0x12", raw=code, size=2)
        reloc = RelocationEntry(offset=0, rel_type="relative", target_symbol="ext_0x5000")

        unit = TransplantUnit(
            code=code,
            arch=Arch.X86_64,
            source_addr=0,
            instructions=[instr],
            relocations=[reloc],
            name="t",
        )
        relocated = Transplanter._relocate_code(unit, 0x1000)
        # Short jmp: size < 5 → no adjustment
        assert relocated == code


# ---------------------------------------------------------------------------
# Non-x86_64 Trampoline
# ---------------------------------------------------------------------------


class TestNonX86Trampoline:
    def test_arm64_raises_not_implemented(self):
        t = Transplanter(Arch.ARM64)
        with pytest.raises(NotImplementedError, match="x86_64"):
            t.create_trampoline(source_offset=0, target_offset=0x100)

    def test_arm32_raises_not_implemented(self):
        t = Transplanter(Arch.ARM32)
        with pytest.raises(NotImplementedError, match="x86_64"):
            t.create_trampoline(source_offset=0, target_offset=0x100)

    def test_x86_32_raises_not_implemented(self):
        t = Transplanter(Arch.X86_32)
        with pytest.raises(NotImplementedError, match="x86_64"):
            t.create_trampoline(source_offset=0, target_offset=0x100)


# ---------------------------------------------------------------------------
# Extract with External References (integration)
# ---------------------------------------------------------------------------


class TestExtractWithExternalReferences:
    def test_function_with_external_call_has_relocations(self):
        """Extract a function containing a call to an address beyond max_size."""
        code = _ASM.assemble("call 0x5000; ret", 0)
        binary = _make_binary(code, pad=256)

        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code), name="caller")

        assert unit.needs_relocation is True
        assert any("5000" in r.target_symbol for r in unit.relocations)

    def test_transplant_with_relocation_adjusts_code(self):
        """Full flow: extract code with call, transplant to new offset, verify adjustment."""
        code = _ASM.assemble("call 0x5000; ret", 0)
        binary = _make_binary(code, pad=256)

        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=len(code), name="caller")
        assert unit.needs_relocation

        target = _make_binary(b"\xcc" * 512, pad=512)
        transplanter = Transplanter(Arch.X86_64)
        patches = transplanter.transplant(unit, target, insert_offset=0x100)

        result = apply_patches(target, patches)
        transplanted = result[0x100 : 0x100 + unit.size]
        # Code should differ from original because displacement was adjusted
        assert transplanted != unit.code


# ---------------------------------------------------------------------------
# Empty / Unreachable CFG blocks
# ---------------------------------------------------------------------------


class TestFindReachableBlocks:
    def test_empty_cfg_returns_empty(self):
        cfg = ControlFlowGraph(blocks={}, edges=[], entry_addr=0)
        result = FunctionExtractor._find_reachable_blocks(cfg)
        assert result == []

    def test_single_block_no_successors(self):
        block = BasicBlock(start_addr=0, end_addr=5, successor_addrs=[])
        cfg = ControlFlowGraph(blocks={0: block}, edges=[], entry_addr=0)
        result = FunctionExtractor._find_reachable_blocks(cfg)
        assert len(result) == 1
        assert result[0].start_addr == 0

    def test_follows_successors(self):
        """BFS should traverse successor edges."""
        block_a = BasicBlock(start_addr=0, end_addr=5, successor_addrs=[10])
        block_b = BasicBlock(start_addr=10, end_addr=15, successor_addrs=[])
        cfg = ControlFlowGraph(blocks={0: block_a, 10: block_b}, edges=[], entry_addr=0)
        result = FunctionExtractor._find_reachable_blocks(cfg)
        assert len(result) == 2
        addrs = {b.start_addr for b in result}
        assert addrs == {0, 10}

    def test_unreachable_block_excluded(self):
        """A block not reachable from entry should be excluded."""
        block_a = BasicBlock(start_addr=0, end_addr=5, successor_addrs=[])
        block_orphan = BasicBlock(start_addr=100, end_addr=110, successor_addrs=[])
        cfg = ControlFlowGraph(blocks={0: block_a, 100: block_orphan}, edges=[], entry_addr=0)
        result = FunctionExtractor._find_reachable_blocks(cfg)
        assert len(result) == 1
        assert result[0].start_addr == 0

    def test_successor_pointing_outside_cfg(self):
        """A successor addr not in cfg.blocks is silently skipped."""
        block = BasicBlock(start_addr=0, end_addr=5, successor_addrs=[999])
        cfg = ControlFlowGraph(blocks={0: block}, edges=[], entry_addr=0)
        result = FunctionExtractor._find_reachable_blocks(cfg)
        assert len(result) == 1

    def test_cycle_does_not_loop(self):
        """BFS should handle cycles (A→B→A) without infinite loop."""
        block_a = BasicBlock(start_addr=0, end_addr=5, successor_addrs=[10])
        block_b = BasicBlock(start_addr=10, end_addr=15, successor_addrs=[0])
        cfg = ControlFlowGraph(blocks={0: block_a, 10: block_b}, edges=[], entry_addr=0)
        result = FunctionExtractor._find_reachable_blocks(cfg)
        assert len(result) == 2

    def test_extract_at_empty_reachable_uses_full_region(self, monkeypatch):
        """When _find_reachable_blocks returns [], extract_at uses the full code region."""
        monkeypatch.setattr(
            FunctionExtractor,
            "_find_reachable_blocks",
            staticmethod(lambda cfg: []),
        )
        code = _simple_code()
        binary = _make_binary(code, pad=256)
        extractor = FunctionExtractor(Arch.X86_64)
        unit = extractor.extract_at(binary, 0, max_size=64)
        # Falls through to else branch: func_code = code_region (full 64 bytes)
        assert unit.size == 64
