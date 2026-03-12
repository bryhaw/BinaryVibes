"""Tests for the binary synthesis / generator module."""

from __future__ import annotations

import lief
import pytest

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.generator import (
    DEFAULT_BASE_ADDR,
    ELF32_EHDR_SIZE,
    ELF32_PHDR_SIZE,
    ELF64_EHDR_SIZE,
    ELF64_PHDR_SIZE,
    BinaryBuilder,
)

# A tiny x86_64 program: exit(42)
#   mov eax, 60    →  b8 3c 00 00 00
#   mov edi, 42    →  bf 2a 00 00 00
#   syscall        →  0f 05
SAMPLE_CODE = b"\xb8\x3c\x00\x00\x00\xbf\x2a\x00\x00\x00\x0f\x05"


# ── Basic build ─────────────────────────────────────────────────────


class TestBuildX8664:
    """Tests for default x86_64 ELF generation."""

    def test_build_x86_64_elf(self) -> None:
        """Build with simple code produces a BinaryFile."""
        binary = BinaryBuilder().add_code(SAMPLE_CODE).build()
        assert isinstance(binary, BinaryFile)

    def test_elf_magic_bytes(self) -> None:
        raw = BinaryBuilder().add_code(SAMPLE_CODE).build().raw
        assert raw[:4] == b"\x7fELF"

    def test_elf_class_64bit(self) -> None:
        raw = BinaryBuilder().add_code(SAMPLE_CODE).build().raw
        assert raw[4] == 2, "EI_CLASS should be ELFCLASS64 (2)"

    def test_elf_little_endian(self) -> None:
        raw = BinaryBuilder().add_code(SAMPLE_CODE).build().raw
        assert raw[5] == 1, "EI_DATA should be ELFDATA2LSB (1)"


# ── LIEF parsing ────────────────────────────────────────────────────


class TestLIEFParsing:
    """Verify that generated binaries are valid enough for LIEF to parse."""

    def test_lief_parses_generated(self) -> None:
        raw = BinaryBuilder().add_code(SAMPLE_CODE).build().raw
        parsed = lief.parse(list(raw))
        assert parsed is not None
        assert isinstance(parsed, lief.ELF.Binary)

    def test_entry_point(self) -> None:
        binary = BinaryBuilder().add_code(SAMPLE_CODE).build()
        parsed = lief.parse(list(binary.raw))
        expected_entry = DEFAULT_BASE_ADDR + ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        assert parsed.entrypoint == expected_entry

    def test_code_present(self) -> None:
        """The code bytes appear at the correct offset in the generated binary."""
        raw = BinaryBuilder().add_code(SAMPLE_CODE).build().raw
        code_offset = ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        assert raw[code_offset : code_offset + len(SAMPLE_CODE)] == SAMPLE_CODE


# ── Custom base address ─────────────────────────────────────────────


class TestCustomBaseAddress:
    def test_custom_base_address(self) -> None:
        custom_base = 0x800000
        binary = BinaryBuilder().set_base_address(custom_base).add_code(SAMPLE_CODE).build()
        parsed = lief.parse(list(binary.raw))
        expected_entry = custom_base + ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        assert parsed.entrypoint == expected_entry


# ── Architecture variants ───────────────────────────────────────────


class TestArchitectures:
    def test_arm64_elf(self) -> None:
        """ARM64 build produces a valid ELF with EM_AARCH64."""
        # ARM64 NOP: d503201f
        arm64_nop = b"\x1f\x20\x03\xd5"
        binary = BinaryBuilder().set_arch(Arch.ARM64).add_code(arm64_nop).build()
        raw = binary.raw

        assert raw[:4] == b"\x7fELF"
        assert raw[4] == 2, "ARM64 ELF should be 64-bit"

        parsed = lief.parse(list(raw))
        assert parsed is not None
        assert parsed.header.machine_type == lief.ELF.ARCH.AARCH64

    def test_x86_32_elf(self) -> None:
        """x86_32 build produces a valid ELF32."""
        # x86_32 exit(0): mov eax,1; xor ebx,ebx; int 0x80
        x86_32_code = b"\xb8\x01\x00\x00\x00\x31\xdb\xcd\x80"
        binary = BinaryBuilder().set_arch(Arch.X86_32).add_code(x86_32_code).build()
        raw = binary.raw

        assert raw[:4] == b"\x7fELF"
        assert raw[4] == 1, "x86_32 ELF should be ELFCLASS32 (1)"

        parsed = lief.parse(list(raw))
        assert parsed is not None
        assert parsed.header.machine_type == lief.ELF.ARCH.I386

        expected_entry = DEFAULT_BASE_ADDR + ELF32_EHDR_SIZE + ELF32_PHDR_SIZE
        assert parsed.entrypoint == expected_entry

    def test_arm32_not_supported(self) -> None:
        """ARM32 binary generation raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="arm32"):
            BinaryBuilder().set_arch(Arch.ARM32).build()


# ── Fluent API ──────────────────────────────────────────────────────


class TestFluentAPI:
    def test_fluent_api(self) -> None:
        """Method chaining works end-to-end."""
        binary = (
            BinaryBuilder()
            .set_arch(Arch.X86_64)
            .set_base_address(DEFAULT_BASE_ADDR)
            .add_code(SAMPLE_CODE)
            .build()
        )
        assert isinstance(binary, BinaryFile)
        assert binary.raw[:4] == b"\x7fELF"

    def test_set_arch_returns_builder(self) -> None:
        result = BinaryBuilder().set_arch(Arch.X86_64)
        assert isinstance(result, BinaryBuilder)

    def test_set_base_address_returns_builder(self) -> None:
        result = BinaryBuilder().set_base_address(0x400000)
        assert isinstance(result, BinaryBuilder)

    def test_add_code_returns_builder(self) -> None:
        result = BinaryBuilder().add_code(b"\xc3")
        assert isinstance(result, BinaryBuilder)

    def test_add_data_returns_builder(self) -> None:
        result = BinaryBuilder().add_data(b"\x00")
        assert isinstance(result, BinaryBuilder)


# ── Edge cases & data handling ──────────────────────────────────────


class TestEdgeCases:
    def test_empty_code(self) -> None:
        """build() with no code still produces a valid ELF (just headers)."""
        binary = BinaryBuilder().build()
        raw = binary.raw
        assert raw[:4] == b"\x7fELF"

        parsed = lief.parse(list(raw))
        assert parsed is not None
        assert isinstance(parsed, lief.ELF.Binary)

    def test_add_data(self) -> None:
        """add_data() appends data after code in the binary."""
        data = b"\xde\xad\xbe\xef"
        binary = BinaryBuilder().add_code(SAMPLE_CODE).add_data(data).build()
        raw = binary.raw

        data_offset = ELF64_EHDR_SIZE + ELF64_PHDR_SIZE + len(SAMPLE_CODE)
        assert raw[data_offset : data_offset + len(data)] == data

    def test_multiple_add_code(self) -> None:
        """Multiple add_code() calls concatenate the code."""
        part1 = b"\xb8\x3c\x00\x00\x00"  # mov eax, 60
        part2 = b"\xbf\x2a\x00\x00\x00"  # mov edi, 42
        part3 = b"\x0f\x05"  # syscall

        binary = BinaryBuilder().add_code(part1).add_code(part2).add_code(part3).build()
        raw = binary.raw
        code_offset = ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        assert raw[code_offset : code_offset + len(SAMPLE_CODE)] == SAMPLE_CODE

    def test_default_base_address(self) -> None:
        """Default base address is 0x400000."""
        assert DEFAULT_BASE_ADDR == 0x400000
