"""Tests for the binary patching module."""

from __future__ import annotations

import dataclasses

import pytest

from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.patcher import Patch, apply_patches


class TestPatch:
    """Patch dataclass tests."""

    def test_patch_creation(self):
        p = Patch(0, b"\x90", "nop")
        assert p.offset == 0
        assert p.data == b"\x90"
        assert p.description == "nop"

    def test_patch_length(self):
        p = Patch(0, b"\x90\x90")
        assert p.length == 2

    def test_patch_frozen(self):
        p = Patch(0, b"\x90", "nop")
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.offset = 1  # type: ignore[misc]


class TestApplyPatches:
    """apply_patches() tests."""

    def test_apply_single_patch(self, tiny_elf_binary: BinaryFile):
        patch = Patch(0, b"\x00", "zero first byte")
        result = apply_patches(tiny_elf_binary, [patch])
        assert isinstance(result, bytes)
        assert result[0] == 0x00
        assert len(result) == len(tiny_elf_binary.raw)

    def test_apply_multiple_patches(self, tiny_elf_binary: BinaryFile):
        p1 = Patch(0, b"\xaa", "first")
        p2 = Patch(2, b"\xbb", "second")
        result = apply_patches(tiny_elf_binary, [p1, p2])
        assert result[0] == 0xAA
        assert result[2] == 0xBB

    def test_patches_sorted(self, tiny_elf_binary: BinaryFile):
        """Patches applied in offset order regardless of input order."""
        p_later = Patch(2, b"\xbb", "later")
        p_early = Patch(0, b"\xaa", "early")
        result = apply_patches(tiny_elf_binary, [p_later, p_early])
        assert result[0] == 0xAA
        assert result[2] == 0xBB

    def test_patch_out_of_bounds(self, tiny_elf_binary: BinaryFile):
        size = len(tiny_elf_binary.raw)
        patch = Patch(size, b"\x90", "oob")
        with pytest.raises(ValueError, match="exceeds binary size"):
            apply_patches(tiny_elf_binary, [patch])

    def test_apply_empty_patches(self, tiny_elf_binary: BinaryFile):
        result = apply_patches(tiny_elf_binary, [])
        assert result == tiny_elf_binary.raw

    def test_patch_preserves_original(self, tiny_elf_binary: BinaryFile):
        original = tiny_elf_binary.raw
        patch = Patch(0, b"\x00", "zero")
        apply_patches(tiny_elf_binary, [patch])
        assert tiny_elf_binary.raw == original
