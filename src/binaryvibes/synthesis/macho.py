"""Mach-O (macOS) binary generation."""

from __future__ import annotations

import struct

from binaryvibes.core.arch import Arch

# Mach-O magic
MH_MAGIC_64 = 0xFEEDFACF

# CPU types
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ALL = 0x03
CPU_SUBTYPE_ARM64_ALL = 0x00

# File type
MH_EXECUTE = 2

# Flags
MH_NOUNDEFS = 0x1
MH_PIE = 0x200000

# Load command types
LC_SEGMENT_64 = 0x19
LC_MAIN = 0x80000028

# VM protection
VM_PROT_READ = 0x01
VM_PROT_EXECUTE = 0x04

# Section types/attributes
S_REGULAR = 0x0
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

# Default base addresses
MACHO_BASE_ADDR = 0x100000000

# Page sizes per architecture
MACHO_PAGE_SIZE = {
    Arch.X86_64: 0x1000,  # 4 KiB
    Arch.ARM64: 0x4000,  # 16 KiB
}

# Computed code offsets (exported for use by agent/prompts)
MACHO_CODE_OFFSET = {
    Arch.X86_64: 0x1000,
    Arch.ARM64: 0x4000,
}

MACHO_CODE_VA = {
    Arch.X86_64: MACHO_BASE_ADDR + 0x1000,  # 0x100001000
    Arch.ARM64: MACHO_BASE_ADDR + 0x4000,  # 0x100004000
}


def _align(value: int, alignment: int) -> int:
    """Round up to next multiple of alignment."""
    return (value + alignment - 1) & ~(alignment - 1)


def build_macho64(code: bytes, data: bytes = b"", arch: Arch = Arch.X86_64) -> bytes:
    """Generate a minimal Mach-O 64-bit executable.

    Args:
        code: Machine code bytes.
        data: Optional data to append after code.
        arch: Target architecture (X86_64 or ARM64).

    Returns:
        Complete Mach-O file as bytes.
    """
    if arch not in (Arch.X86_64, Arch.ARM64):
        raise NotImplementedError(f"Mach-O generation not supported for {arch.value}")

    page_size = MACHO_PAGE_SIZE[arch]
    payload = code + data

    # CPU type selection
    if arch == Arch.X86_64:
        cputype = CPU_TYPE_X86_64
        cpusubtype = CPU_SUBTYPE_ALL
    else:
        cputype = CPU_TYPE_ARM64
        cpusubtype = CPU_SUBTYPE_ARM64_ALL

    # Calculate layout
    # Load commands: __PAGEZERO (72) + __TEXT with 1 section (72+80=152) + LC_MAIN (24) = 248
    pagezero_cmd_size = 72
    text_cmd_size = 72 + 80  # segment + 1 section header
    main_cmd_size = 24
    sizeofcmds = pagezero_cmd_size + text_cmd_size + main_cmd_size
    header_size = 32  # mach_header_64

    code_offset = _align(header_size + sizeofcmds, page_size)  # Page-aligned
    total_size = code_offset + len(payload)
    text_vmsize = _align(total_size, page_size)

    # ── mach_header_64 (32 bytes) ────────────────────────────
    mach_header = struct.pack(
        "<IiiIIII",
        MH_MAGIC_64,
        cputype,
        cpusubtype,
        MH_EXECUTE,
        3,  # ncmds
        sizeofcmds,
        MH_NOUNDEFS | MH_PIE,
    )
    mach_header += struct.pack("<I", 0)  # reserved (for 64-bit)

    # ── LC_SEGMENT_64 __PAGEZERO (72 bytes) ──────────────────
    pagezero = struct.pack("<II", LC_SEGMENT_64, pagezero_cmd_size)
    pagezero += b"__PAGEZERO\x00\x00\x00\x00\x00\x00"  # segname (16 bytes)
    pagezero += struct.pack(
        "<QQQQII",
        0,  # vmaddr
        MACHO_BASE_ADDR,  # vmsize (4 GB guard)
        0,  # fileoff
        0,  # filesize
        0,  # maxprot
        0,  # initprot
    )
    pagezero += struct.pack("<II", 0, 0)  # nsects, flags

    # ── LC_SEGMENT_64 __TEXT (72 + 80 = 152 bytes) ───────────
    text_seg = struct.pack("<II", LC_SEGMENT_64, text_cmd_size)
    text_seg += b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # segname (16 bytes)
    text_seg += struct.pack(
        "<QQQQII",
        MACHO_BASE_ADDR,  # vmaddr
        text_vmsize,  # vmsize
        0,  # fileoff
        total_size,  # filesize
        VM_PROT_READ | VM_PROT_EXECUTE,  # maxprot (5)
        VM_PROT_READ | VM_PROT_EXECUTE,  # initprot (5)
    )
    text_seg += struct.pack("<II", 1, 0)  # nsects=1, flags=0

    # Section __text in __TEXT (80 bytes)
    section = b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # sectname (16 bytes)
    section += b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # segname (16 bytes)
    section += struct.pack(
        "<QQ",
        MACHO_BASE_ADDR + code_offset,  # addr (VA)
        len(payload),  # size
    )
    section += struct.pack(
        "<II",
        code_offset,  # offset (file offset)
        4,  # align (2^4 = 16)
    )
    section += struct.pack(
        "<IIIII",
        0,  # reloff
        0,  # nreloc
        S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,  # type+attrs
        0,  # reserved1
        0,  # reserved2
    )
    section += struct.pack("<I", 0)  # reserved3

    text_seg += section

    # ── LC_MAIN (24 bytes) ───────────────────────────────────
    lc_main = struct.pack("<II", LC_MAIN, main_cmd_size)
    lc_main += struct.pack(
        "<QQ",
        code_offset,  # entryoff (offset from start of __TEXT in file)
        0,  # stacksize (0 = default)
    )

    # ── Assemble ─────────────────────────────────────────────
    headers = mach_header + pagezero + text_seg + lc_main
    padding = b"\x00" * (code_offset - len(headers))

    return headers + padding + payload
