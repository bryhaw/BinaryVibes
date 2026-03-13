"""Comprehensive tests for core modules: arch.py and binary.py."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import capstone
import keystone
import lief
import pytest

from binaryvibes.core.arch import (
    ARCH_CONFIGS,
    Arch,
    ArchConfig,
    BinaryFormat,
    Endianness,
    detect_native_format,
)
from binaryvibes.core.binary import BinaryFile

# ── Arch tests ──────────────────────────────────────────────────────


class TestArchEnum:
    def test_arch_enum_values(self):
        assert Arch.X86_64.value == "x86_64"
        assert Arch.X86_32.value == "x86_32"
        assert Arch.ARM64.value == "arm64"
        assert Arch.ARM32.value == "arm32"
        assert len(Arch) == 4

    def test_endianness_enum(self):
        assert Endianness.LITTLE.value == "little"
        assert Endianness.BIG.value == "big"
        assert len(Endianness) == 2


class TestArchConfig:
    def test_arch_config_for_all_arches(self):
        for member in Arch:
            assert member in ARCH_CONFIGS, f"Missing ARCH_CONFIGS entry for {member}"
            cfg = ARCH_CONFIGS[member]
            assert isinstance(cfg, ArchConfig)
            assert cfg.arch is member

    def test_arch_config_x86_64(self):
        cfg = ARCH_CONFIGS[Arch.X86_64]
        assert cfg.cs_arch == capstone.CS_ARCH_X86
        assert cfg.cs_mode == capstone.CS_MODE_64
        assert cfg.ks_arch == keystone.KS_ARCH_X86
        assert cfg.ks_mode == keystone.KS_MODE_64
        assert cfg.word_size == 8
        assert cfg.endianness is Endianness.LITTLE

    def test_arch_config_arm64(self):
        cfg = ARCH_CONFIGS[Arch.ARM64]
        assert cfg.cs_arch == capstone.CS_ARCH_ARM64
        assert cfg.cs_mode == capstone.CS_MODE_ARM
        assert cfg.ks_arch == keystone.KS_ARCH_ARM64
        assert cfg.ks_mode == keystone.KS_MODE_LITTLE_ENDIAN
        assert cfg.word_size == 8
        assert cfg.endianness is Endianness.LITTLE

    def test_arch_config_x86_32(self):
        cfg = ARCH_CONFIGS[Arch.X86_32]
        assert cfg.cs_arch == capstone.CS_ARCH_X86
        assert cfg.cs_mode == capstone.CS_MODE_32
        assert cfg.ks_arch == keystone.KS_ARCH_X86
        assert cfg.ks_mode == keystone.KS_MODE_32
        assert cfg.word_size == 4
        assert cfg.endianness is Endianness.LITTLE

    def test_arch_config_arm32(self):
        cfg = ARCH_CONFIGS[Arch.ARM32]
        assert cfg.cs_arch == capstone.CS_ARCH_ARM
        assert cfg.cs_mode == capstone.CS_MODE_ARM
        assert cfg.ks_arch == keystone.KS_ARCH_ARM
        assert cfg.ks_mode == keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN
        assert cfg.word_size == 4
        assert cfg.endianness is Endianness.LITTLE

    def test_arch_config_frozen(self):
        cfg = ARCH_CONFIGS[Arch.X86_64]
        with pytest.raises(FrozenInstanceError):
            cfg.word_size = 16  # type: ignore[misc]


# ── BinaryFile tests ────────────────────────────────────────────────


class TestBinaryFileFromPath:
    def test_from_path(self, tiny_elf: Path):
        bf = BinaryFile.from_path(tiny_elf)
        assert isinstance(bf.raw, bytes)
        assert len(bf.raw) > 0
        assert bf.arch is not None
        assert bf.path == tiny_elf

    def test_from_path_nonexistent(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            BinaryFile.from_path(tmp_path / "does_not_exist.bin")


class TestBinaryFileFromBytes:
    def test_from_bytes(self, x86_code_bytes: bytes):
        bf = BinaryFile.from_bytes(x86_code_bytes)
        assert bf.raw == x86_code_bytes
        assert isinstance(bf.raw, bytes)

    def test_lief_property_raw_bytes(self, x86_code_bytes: bytes):
        bf = BinaryFile.from_bytes(x86_code_bytes)
        with pytest.raises(ValueError, match="LIEF could not parse"):
            _ = bf.lief


class TestBinaryFileLief:
    def test_lief_property(self, tiny_elf_binary: BinaryFile):
        parsed = tiny_elf_binary.lief
        assert parsed is not None
        assert isinstance(parsed, lief.Binary)


class TestBinaryFileDetection:
    def test_arch_detection_elf(self, tiny_elf_binary: BinaryFile):
        assert tiny_elf_binary.arch is Arch.X86_64

    def test_format_name(self, tiny_elf_binary: BinaryFile):
        # LIEF's type(parsed).__name__ is "Binary" for ELF objects
        assert tiny_elf_binary.format_name != ""
        assert tiny_elf_binary.format_name != "unknown"


class TestBinaryFileWrite:
    def test_write(self, tiny_elf_binary: BinaryFile, tmp_path: Path):
        dest = tmp_path / "output.elf"
        tiny_elf_binary.write(dest)
        assert dest.exists()
        written = dest.read_bytes()
        assert len(written) > 0

    def test_binary_file_size(self, tiny_elf_binary: BinaryFile):
        assert len(tiny_elf_binary.raw) > 0
        file_size = tiny_elf_binary.path.stat().st_size
        assert len(tiny_elf_binary.raw) == file_size


# ── BinaryFormat tests ──────────────────────────────────────────────


class TestBinaryFormat:
    def test_enum_values(self):
        assert BinaryFormat.ELF.value == "elf"
        assert BinaryFormat.PE.value == "pe"
        assert BinaryFormat.MACHO.value == "macho"

    def test_detect_native_format(self):
        fmt = detect_native_format()
        assert isinstance(fmt, BinaryFormat)
