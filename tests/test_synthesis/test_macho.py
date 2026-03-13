"""Tests for the Mach-O binary synthesis module."""

from __future__ import annotations

import struct

import lief
import pytest

from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.macho import (
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    MACHO_BASE_ADDR,
    MACHO_CODE_OFFSET,
    MACHO_CODE_VA,
    MACHO_PAGE_SIZE,
    MH_MAGIC_64,
    build_macho64,
)

# macOS x86_64 exit(42): mov rax,0x2000001; mov rdi,42; syscall
X86_64_EXIT42 = (
    b"\x48\xc7\xc0\x01\x00\x00\x02"  # mov rax, 0x2000001
    b"\x48\xc7\xc7\x2a\x00\x00\x00"  # mov rdi, 42
    b"\x0f\x05"  # syscall
)

# ARM64 exit(42): mov x0,#42; mov x16,#1; svc #0x80
ARM64_EXIT42 = (
    b"\x40\x05\x80\xd2"  # mov x0, #42
    b"\x30\x00\x80\xd2"  # mov x16, #1
    b"\x01\x10\x00\xd4"  # svc #0x80
)


# ── Basic x86_64 build ──────────────────────────────────────────────


class TestBuildX8664:
    """Tests for default x86_64 Mach-O generation."""

    def test_build_returns_bytes(self) -> None:
        result = build_macho64(X86_64_EXIT42)
        assert isinstance(result, bytes)

    def test_macho_magic(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        magic = struct.unpack("<I", raw[:4])[0]
        assert magic == MH_MAGIC_64

    def test_cpu_type_x86_64(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        cputype = struct.unpack("<i", raw[4:8])[0]
        assert cputype == CPU_TYPE_X86_64

    def test_code_at_expected_offset(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        offset = MACHO_CODE_OFFSET[Arch.X86_64]
        assert raw[offset : offset + len(X86_64_EXIT42)] == X86_64_EXIT42

    def test_file_size(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        expected = MACHO_CODE_OFFSET[Arch.X86_64] + len(X86_64_EXIT42)
        assert len(raw) == expected


# ── ARM64 build ─────────────────────────────────────────────────────


class TestBuildARM64:
    """Tests for ARM64 Mach-O generation."""

    def test_macho_magic(self) -> None:
        raw = build_macho64(ARM64_EXIT42, arch=Arch.ARM64)
        magic = struct.unpack("<I", raw[:4])[0]
        assert magic == MH_MAGIC_64

    def test_cpu_type_arm64(self) -> None:
        raw = build_macho64(ARM64_EXIT42, arch=Arch.ARM64)
        cputype = struct.unpack("<i", raw[4:8])[0]
        assert cputype == CPU_TYPE_ARM64

    def test_code_at_expected_offset(self) -> None:
        raw = build_macho64(ARM64_EXIT42, arch=Arch.ARM64)
        offset = MACHO_CODE_OFFSET[Arch.ARM64]
        assert raw[offset : offset + len(ARM64_EXIT42)] == ARM64_EXIT42

    def test_page_aligned_code_offset(self) -> None:
        build_macho64(ARM64_EXIT42, arch=Arch.ARM64)
        page = MACHO_PAGE_SIZE[Arch.ARM64]
        assert MACHO_CODE_OFFSET[Arch.ARM64] % page == 0


# ── LIEF parsing ────────────────────────────────────────────────────


class TestLIEFParsing:
    """Verify that generated binaries are valid enough for LIEF to parse."""

    def test_lief_parses_x86_64(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        parsed = lief.parse(list(raw))
        assert parsed is not None
        assert isinstance(parsed, lief.MachO.Binary)

    def test_lief_parses_arm64(self) -> None:
        raw = build_macho64(ARM64_EXIT42, arch=Arch.ARM64)
        parsed = lief.parse(list(raw))
        assert parsed is not None
        assert isinstance(parsed, lief.MachO.Binary)

    def test_segments_present(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        parsed = lief.parse(list(raw))
        seg_names = [s.name for s in parsed.segments]
        assert "__PAGEZERO" in seg_names
        assert "__TEXT" in seg_names

    def test_text_section_present(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        parsed = lief.parse(list(raw))
        section_names = [s.name for s in parsed.sections]
        assert "__text" in section_names

    def test_entry_point_x86_64(self) -> None:
        raw = build_macho64(X86_64_EXIT42)
        parsed = lief.parse(list(raw))
        expected_va = MACHO_CODE_VA[Arch.X86_64]
        assert parsed.entrypoint == expected_va

    def test_entry_point_arm64(self) -> None:
        raw = build_macho64(ARM64_EXIT42, arch=Arch.ARM64)
        parsed = lief.parse(list(raw))
        expected_va = MACHO_CODE_VA[Arch.ARM64]
        assert parsed.entrypoint == expected_va


# ── Constants ───────────────────────────────────────────────────────


class TestConstants:
    """Verify exported constants are consistent."""

    def test_code_offset_x86_64(self) -> None:
        assert MACHO_CODE_OFFSET[Arch.X86_64] == 0x1000

    def test_code_offset_arm64(self) -> None:
        assert MACHO_CODE_OFFSET[Arch.ARM64] == 0x4000

    def test_code_va_x86_64(self) -> None:
        assert MACHO_CODE_VA[Arch.X86_64] == MACHO_BASE_ADDR + 0x1000

    def test_code_va_arm64(self) -> None:
        assert MACHO_CODE_VA[Arch.ARM64] == MACHO_BASE_ADDR + 0x4000

    def test_page_sizes(self) -> None:
        assert MACHO_PAGE_SIZE[Arch.X86_64] == 0x1000
        assert MACHO_PAGE_SIZE[Arch.ARM64] == 0x4000


# ── Edge cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases and error handling."""

    def test_empty_code(self) -> None:
        raw = build_macho64(b"")
        magic = struct.unpack("<I", raw[:4])[0]
        assert magic == MH_MAGIC_64

    def test_data_appended_after_code(self) -> None:
        data = b"\xde\xad\xbe\xef"
        raw = build_macho64(X86_64_EXIT42, data=data)
        offset = MACHO_CODE_OFFSET[Arch.X86_64]
        code_end = offset + len(X86_64_EXIT42)
        assert raw[code_end : code_end + len(data)] == data

    def test_unsupported_arch(self) -> None:
        with pytest.raises(NotImplementedError, match="x86_32"):
            build_macho64(b"\xcc", arch=Arch.X86_32)

    def test_unsupported_arch_arm32(self) -> None:
        with pytest.raises(NotImplementedError, match="arm32"):
            build_macho64(b"\xcc", arch=Arch.ARM32)

    def test_header_sizes_correct(self) -> None:
        """Verify struct packing produces correct header sizes."""
        raw = build_macho64(X86_64_EXIT42)
        # mach_header_64 = 32 bytes
        # __PAGEZERO = 72 bytes
        # __TEXT segment + section = 152 bytes
        # LC_MAIN = 24 bytes
        # Total headers = 32 + 72 + 152 + 24 = 280
        # Padded to page boundary = 0x1000 for x86_64
        assert len(raw) >= 280
        # Verify ncmds from header
        ncmds = struct.unpack("<I", raw[16:20])[0]
        assert ncmds == 3
        # Verify sizeofcmds from header
        sizeofcmds = struct.unpack("<I", raw[20:24])[0]
        assert sizeofcmds == 248  # 72 + 152 + 24
