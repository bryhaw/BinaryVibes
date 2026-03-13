"""Tests for PE (Windows) binary generation."""

from __future__ import annotations

import struct

import lief

from binaryvibes.synthesis.pe import (
    PE_CODE_RVA,
    PE_FILE_ALIGNMENT,
    PE_IAT_EXPORTS,
    PE_IDATA_RVA,
    PE_IMAGE_BASE,
    _align,
    _build_idata_section,
    build_pe64,
)

# x86_64 machine code: ExitProcess(42) via IAT
# mov ecx, 42              → b9 2a 00 00 00
# sub rsp, 0x28            → 48 83 ec 28
# mov rax, [0x402000]      → 48 a1 00 20 40 00 00 00 00 00  (movabs rax, [0x402000])
# call rax                 → ff d0
EXIT42_CODE = (
    b"\xb9\x2a\x00\x00\x00"          # mov ecx, 42
    b"\x48\x83\xec\x28"              # sub rsp, 0x28
    b"\x48\xa1"                       # movabs rax, [imm64]
    + struct.pack("<Q", 0x402000)     # address of ExitProcess IAT entry
    + b"\xff\xd0"                     # call rax
)


# ── Basic PE structure ──────────────────────────────────────────────


class TestBuildPE64Basic:
    """Basic structural tests for the generated PE64 binary."""

    def test_dos_magic(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        assert pe[:2] == b"MZ"

    def test_pe_signature(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
        assert pe[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"

    def test_pe_signature_at_offset_64(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        assert pe[64:68] == b"PE\x00\x00"

    def test_machine_amd64(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        machine = struct.unpack_from("<H", pe, 0x44)[0]
        assert machine == 0x8664

    def test_number_of_sections(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        num_sections = struct.unpack_from("<H", pe, 0x46)[0]
        assert num_sections == 2

    def test_optional_header_magic_pe32plus(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        magic = struct.unpack_from("<H", pe, 0x58)[0]
        assert magic == 0x20B

    def test_entry_point(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        entry = struct.unpack_from("<I", pe, 0x58 + 16)[0]
        assert entry == PE_CODE_RVA

    def test_image_base(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        base = struct.unpack_from("<Q", pe, 0x58 + 24)[0]
        assert base == PE_IMAGE_BASE

    def test_subsystem_console(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        # Subsystem offset within opt_win (starts at 0x70):
        # ImageBase(8) + SectionAlign(4) + FileAlign(4) + 6xH(12) +
        # Win32VersionValue(4) + SizeOfImage(4) + SizeOfHeaders(4) +
        # CheckSum(4) = 44
        subsystem = struct.unpack_from("<H", pe, 0x70 + 44)[0]
        assert subsystem == 3  # IMAGE_SUBSYSTEM_WINDOWS_CUI

    def test_code_at_text_offset(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        assert pe[0x200 : 0x200 + len(EXIT42_CODE)] == EXIT42_CODE

    def test_file_size_aligned(self) -> None:
        pe = build_pe64(EXIT42_CODE)
        assert len(pe) % PE_FILE_ALIGNMENT == 0

    def test_minimum_file_size(self) -> None:
        pe = build_pe64(b"\xc3")  # single RET
        # headers (0x200) + .text (0x200) + .idata (0x200) = 0x600
        assert len(pe) >= 0x600


# ── LIEF parsing ────────────────────────────────────────────────────


class TestLIEFParsing:
    """Verify that LIEF can successfully parse the generated PE."""

    def _parse(self, code: bytes = EXIT42_CODE) -> lief.PE.Binary:
        pe_bytes = build_pe64(code)
        parsed = lief.parse(list(pe_bytes))
        assert parsed is not None
        return parsed

    def test_lief_parses_pe(self) -> None:
        parsed = self._parse()
        assert isinstance(parsed, lief.PE.Binary)

    def test_lief_entry_point(self) -> None:
        parsed = self._parse()
        assert parsed.optional_header.addressof_entrypoint == PE_CODE_RVA

    def test_lief_image_base(self) -> None:
        parsed = self._parse()
        assert parsed.optional_header.imagebase == PE_IMAGE_BASE

    def test_lief_machine_type(self) -> None:
        parsed = self._parse()
        assert parsed.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64

    def test_lief_two_sections(self) -> None:
        parsed = self._parse()
        assert len(parsed.sections) == 2

    def test_lief_section_names(self) -> None:
        parsed = self._parse()
        names = [s.name for s in parsed.sections]
        assert ".text" in names
        assert ".idata" in names

    def test_lief_imports_kernel32(self) -> None:
        parsed = self._parse()
        import_libs = [lib.name.lower() for lib in parsed.imports]
        assert "kernel32.dll" in import_libs

    def test_lief_imported_functions(self) -> None:
        parsed = self._parse()
        funcs: list[str] = []
        for lib in parsed.imports:
            for entry in lib.entries:
                if entry.name:
                    funcs.append(entry.name)
        assert "ExitProcess" in funcs
        assert "GetStdHandle" in funcs
        assert "WriteFile" in funcs

    def test_lief_console_subsystem(self) -> None:
        parsed = self._parse()
        assert (
            parsed.optional_header.subsystem
            == lief.PE.OptionalHeader.SUBSYSTEM.WINDOWS_CUI
        )


# ── Import table details ───────────────────────────────────────────


class TestImportTable:
    """Verify the .idata section structure."""

    def test_idata_section_builds(self) -> None:
        section, iat_off, ilt_off, idt_off = _build_idata_section()
        assert len(section) > 0
        assert iat_off == 0
        assert ilt_off > iat_off
        assert idt_off > ilt_off

    def test_iat_at_section_start(self) -> None:
        """IAT must be at offset 0 so VA addresses match PE_IAT_EXPORTS."""
        _section, iat_off, _ilt_off, _idt_off = _build_idata_section()
        assert iat_off == 0

    def test_iat_contains_hint_name_rvas(self) -> None:
        section, _iat_off, _ilt_off, _idt_off = _build_idata_section()
        # First 3 entries should be non-zero RVAs; 4th should be null
        for i in range(3):
            entry = struct.unpack_from("<Q", section, i * 8)[0]
            assert entry != 0, f"IAT[{i}] should be non-zero"
        null_term = struct.unpack_from("<Q", section, 3 * 8)[0]
        assert null_term == 0

    def test_dll_name_in_section(self) -> None:
        section, *_ = _build_idata_section()
        assert b"kernel32.dll\x00" in section

    def test_function_names_in_section(self) -> None:
        section, *_ = _build_idata_section()
        assert b"ExitProcess\x00" in section
        assert b"GetStdHandle\x00" in section
        assert b"WriteFile\x00" in section


# ── Exported constants ──────────────────────────────────────────────


class TestExportedConstants:
    """Verify the exported constants match the PE layout."""

    def test_iat_exports_exit_process(self) -> None:
        assert PE_IAT_EXPORTS["ExitProcess"] == 0x402000

    def test_iat_exports_get_std_handle(self) -> None:
        assert PE_IAT_EXPORTS["GetStdHandle"] == 0x402008

    def test_iat_exports_write_file(self) -> None:
        assert PE_IAT_EXPORTS["WriteFile"] == 0x402010

    def test_iat_exports_consistent_with_layout(self) -> None:
        assert PE_IAT_EXPORTS["ExitProcess"] == PE_IMAGE_BASE + PE_IDATA_RVA
        assert PE_IAT_EXPORTS["GetStdHandle"] == PE_IMAGE_BASE + PE_IDATA_RVA + 8
        assert PE_IAT_EXPORTS["WriteFile"] == PE_IMAGE_BASE + PE_IDATA_RVA + 16

    def test_code_rva(self) -> None:
        assert PE_CODE_RVA == 0x1000

    def test_idata_rva(self) -> None:
        assert PE_IDATA_RVA == 0x2000


# ── Alignment helper ───────────────────────────────────────────────


class TestAlign:
    def test_already_aligned(self) -> None:
        assert _align(0x200, 0x200) == 0x200

    def test_rounds_up(self) -> None:
        assert _align(1, 0x200) == 0x200

    def test_rounds_up_boundary(self) -> None:
        assert _align(0x201, 0x200) == 0x400

    def test_zero(self) -> None:
        assert _align(0, 0x200) == 0


# ── Edge cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_code(self) -> None:
        """build_pe64 with empty code still produces a valid PE."""
        pe = build_pe64(b"")
        assert pe[:2] == b"MZ"
        parsed = lief.parse(list(pe))
        assert parsed is not None

    def test_single_ret(self) -> None:
        pe = build_pe64(b"\xc3")
        assert pe[0x200] == 0xC3

    def test_with_data(self) -> None:
        code = b"\xc3"
        data = b"Hello, World!\x00"
        pe = build_pe64(code, data=data)
        offset = 0x200 + len(code)
        assert pe[offset : offset + len(data)] == data

    def test_large_code(self) -> None:
        """Code larger than one file-alignment block works."""
        big_code = b"\x90" * 600  # 600 NOPs > 0x200
        pe = build_pe64(big_code)
        assert pe[:2] == b"MZ"
        parsed = lief.parse(list(pe))
        assert parsed is not None
        assert pe[0x200 : 0x200 + 600] == big_code


# ── Keystone assembly integration ──────────────────────────────────


class TestKeystoneIntegration:
    """Test with real assembly using the keystone engine."""

    def test_assemble_exit_process_call(self) -> None:
        import keystone

        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        asm_code = (
            "mov ecx, 42;"
            "sub rsp, 0x28;"
            "mov rax, qword ptr [0x402000];"
            "call rax"
        )
        encoding, _count = ks.asm(asm_code)
        pe = build_pe64(bytes(encoding))

        assert pe[:2] == b"MZ"
        assert b"PE\x00\x00" in pe[:256]

        parsed = lief.parse(list(pe))
        assert parsed is not None
        assert parsed.optional_header.addressof_entrypoint == PE_CODE_RVA
        import_libs = [lib.name.lower() for lib in parsed.imports]
        assert "kernel32.dll" in import_libs
