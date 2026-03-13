"""Whole-binary synthesis — generate minimal binaries from scratch."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from binaryvibes.core.arch import Arch, BinaryFormat
from binaryvibes.core.binary import BinaryFile

# ELF constants
ELF_MAGIC = b"\x7fELF"
ET_EXEC = 2
EM_X86_64 = 0x3E
EM_386 = 0x03
EM_AARCH64 = 0xB7
PT_LOAD = 1
PF_X = 1
PF_R = 4

# ELF identification bytes
ELFCLASS64 = 2
ELFCLASS32 = 1
ELFDATA2LSB = 1  # Little-endian
EV_CURRENT = 1
ELFOSABI_NONE = 0

# ELF64 header and program header sizes
ELF64_EHDR_SIZE = 64
ELF64_PHDR_SIZE = 56
ELF32_EHDR_SIZE = 52
ELF32_PHDR_SIZE = 32

# Default virtual address
DEFAULT_BASE_ADDR = 0x400000


@dataclass
class BinaryBuilder:
    """Fluent builder for constructing minimal binaries from scratch.

    Supports generating ELF64 (x86_64, AArch64), ELF32 (x86_32),
    PE64 (x86_64), and Mach-O 64 (x86_64, ARM64) executables
    containing user-provided machine code and data.

    Example::

        binary = (
            BinaryBuilder()
            .set_arch(Arch.X86_64)
            .set_format(BinaryFormat.ELF)
            .add_code(b"\\xb8\\x3c\\x00\\x00\\x00\\xbf\\x2a\\x00\\x00\\x00\\x0f\\x05")
            .build()
        )
    """

    _arch: Arch = Arch.X86_64
    _format: BinaryFormat | None = None  # None means auto-detect
    _code: bytes = b""
    _data: bytes = b""
    _base_addr: int = DEFAULT_BASE_ADDR

    def set_arch(self, arch: Arch) -> BinaryBuilder:
        """Set target architecture."""
        self._arch = arch
        return self

    def set_format(self, fmt: BinaryFormat) -> BinaryBuilder:
        """Set output binary format (ELF, PE, Mach-O)."""
        self._format = fmt
        return self

    def set_base_address(self, addr: int) -> BinaryBuilder:
        """Set base virtual address."""
        self._base_addr = addr
        return self

    def add_code(self, code: bytes) -> BinaryBuilder:
        """Append machine code to the code section."""
        self._code += code
        return self

    def add_data(self, data: bytes) -> BinaryBuilder:
        """Append data to the data section (after code)."""
        self._data += data
        return self

    def build(self) -> BinaryFile:
        """Generate the binary and return as BinaryFile."""
        fmt = self._format or BinaryFormat.ELF

        if fmt == BinaryFormat.PE:
            from binaryvibes.synthesis.pe import build_pe64

            if self._arch in (Arch.X86_64,):
                raw = build_pe64(self._code, self._data)
            else:
                msg = f"PE generation not supported for {self._arch.value}"
                raise NotImplementedError(msg)
        elif fmt == BinaryFormat.MACHO:
            from binaryvibes.synthesis.macho import build_macho64

            if self._arch in (Arch.X86_64, Arch.ARM64):
                raw = build_macho64(self._code, self._data, self._arch)
            else:
                msg = f"Mach-O generation not supported for {self._arch.value}"
                raise NotImplementedError(msg)
        elif fmt == BinaryFormat.ELF:
            if self._arch == Arch.X86_64:
                raw = self._build_elf64(EM_X86_64)
            elif self._arch == Arch.X86_32:
                raw = self._build_elf32()
            elif self._arch == Arch.ARM64:
                raw = self._build_elf64(EM_AARCH64)
            else:
                msg = f"ELF generation not supported for {self._arch.value}"
                raise NotImplementedError(msg)
        else:
            msg = f"Unknown format: {fmt}"
            raise NotImplementedError(msg)

        return BinaryFile.from_bytes(raw, name=f"generated_{self._arch.value}")

    def _build_elf64(self, machine: int) -> bytes:
        """Build a minimal ELF64 binary for the given machine type."""
        payload = self._code + self._data
        entry_point = self._base_addr + ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        total_size = ELF64_EHDR_SIZE + ELF64_PHDR_SIZE + len(payload)

        # ELF64 header (64 bytes)
        e_ident = struct.pack(
            "4sBBBBB7s",
            ELF_MAGIC,  # magic
            ELFCLASS64,  # class: 64-bit
            ELFDATA2LSB,  # data: little-endian
            EV_CURRENT,  # version
            ELFOSABI_NONE,  # OS/ABI
            0,  # ABI version
            b"\x00" * 7,  # padding
        )
        elf_header = e_ident + struct.pack(
            "<HHIQQQIHHHHHH",
            ET_EXEC,  # e_type
            machine,  # e_machine
            EV_CURRENT,  # e_version
            entry_point,  # e_entry
            ELF64_EHDR_SIZE,  # e_phoff (program header right after ELF header)
            0,  # e_shoff (no section headers)
            0,  # e_flags
            ELF64_EHDR_SIZE,  # e_ehsize
            ELF64_PHDR_SIZE,  # e_phentsize
            1,  # e_phnum
            0,  # e_shentsize
            0,  # e_shnum
            0,  # e_shstrndx
        )

        # ELF64 program header (56 bytes)
        program_header = struct.pack(
            "<IIQQQQQQ",
            PT_LOAD,  # p_type
            PF_R | PF_X,  # p_flags
            0,  # p_offset
            self._base_addr,  # p_vaddr
            self._base_addr,  # p_paddr
            total_size,  # p_filesz
            total_size,  # p_memsz
            0x1000,  # p_align
        )

        return elf_header + program_header + payload

    def _build_elf32(self) -> bytes:
        """Build a minimal ELF32 x86 binary."""
        payload = self._code + self._data
        entry_point = self._base_addr + ELF32_EHDR_SIZE + ELF32_PHDR_SIZE
        total_size = ELF32_EHDR_SIZE + ELF32_PHDR_SIZE + len(payload)

        # ELF32 header (52 bytes)
        e_ident = struct.pack(
            "4sBBBBB7s",
            ELF_MAGIC,
            ELFCLASS32,
            ELFDATA2LSB,
            EV_CURRENT,
            ELFOSABI_NONE,
            0,
            b"\x00" * 7,
        )
        elf_header = e_ident + struct.pack(
            "<HHIIIIIHHHHHH",
            ET_EXEC,  # e_type
            EM_386,  # e_machine
            EV_CURRENT,  # e_version
            entry_point,  # e_entry
            ELF32_EHDR_SIZE,  # e_phoff
            0,  # e_shoff
            0,  # e_flags
            ELF32_EHDR_SIZE,  # e_ehsize
            ELF32_PHDR_SIZE,  # e_phentsize
            1,  # e_phnum
            0,  # e_shentsize
            0,  # e_shnum
            0,  # e_shstrndx
        )

        # ELF32 program header (32 bytes)
        program_header = struct.pack(
            "<IIIIIIII",
            PT_LOAD,  # p_type
            0,  # p_offset
            self._base_addr,  # p_vaddr
            self._base_addr,  # p_paddr
            total_size,  # p_filesz
            total_size,  # p_memsz
            PF_R | PF_X,  # p_flags
            0x1000,  # p_align
        )

        return elf_header + program_header + payload
