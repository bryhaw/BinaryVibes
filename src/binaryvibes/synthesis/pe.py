"""PE (Windows) binary generation.

Generates minimal PE64 (x86_64) Windows executables that import
commonly-used Windows API functions from kernel32.dll via an
Import Address Table (IAT) at known virtual addresses.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# PE constants
# ---------------------------------------------------------------------------
PE_IMAGE_BASE = 0x400000
PE_SECTION_ALIGNMENT = 0x1000
PE_FILE_ALIGNMENT = 0x200
PE_CODE_RVA = 0x1000
PE_IDATA_RVA = 0x2000

IMAGE_FILE_MACHINE_AMD64 = 0x8664

# Functions imported from kernel32.dll.
_KERNEL32_FUNCTIONS = [
    "ExitProcess",
    "GetStdHandle",
    "WriteFile",
    "ReadFile",
    "CreateFileA",
    "CloseHandle",
    "GetFileSize",
    "GetComputerNameA",
    "GetLocalTime",
    "GlobalMemoryStatusEx",
    "GetCurrentProcessId",
    "GetCommandLineA",
    "Sleep",
    "GetProcessHeap",
    "HeapAlloc",
    "HeapFree",
    "FindFirstFileA",
    "FindNextFileA",
    "FindClose",
    "SetConsoleTitleA",
    "GetLastError",
    "lstrlenA",
    "GetEnvironmentVariableA",
    "GetTickCount64",
]

# IAT virtual addresses exported for use by the prompt/codegen system.
# The IAT lives at the very start of .idata (RVA 0x2000), so each 8-byte
# entry maps to ImageBase + 0x2000 + index*8.
PE_IAT_EXPORTS: dict[str, int] = {
    name: PE_IMAGE_BASE + PE_IDATA_RVA + i * 8
    for i, name in enumerate(_KERNEL32_FUNCTIONS)
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _align(value: int, alignment: int) -> int:
    """Round *value* up to the next multiple of *alignment*."""
    return (value + alignment - 1) & ~(alignment - 1)


def _build_idata_section() -> tuple[bytes, int, int, int]:
    """Build the .idata section with import tables for kernel32.dll.

    Internal layout (offsets relative to section start, i.e. RVA 0x2000)::

        [IAT]               (num_funcs + 1) * 8   Import Address Table
        [ILT]               (num_funcs + 1) * 8   Import Lookup Table
        [IDT]               40                     Import Directory Table
        [Hint/Name entries] variable               2-byte hint + ASCII name
        [DLL name]          variable               "kernel32.dll\\0"

    Returns:
        ``(section_bytes, iat_offset, ilt_offset, idt_offset)``
    """
    num_funcs = len(_KERNEL32_FUNCTIONS)
    table_size = (num_funcs + 1) * 8  # entries + null terminator

    iat_offset = 0
    ilt_offset = iat_offset + table_size
    idt_offset = ilt_offset + table_size
    hint_names_start = idt_offset + 40  # IDT = 1 entry (20) + null (20)

    # -- Hint/Name entries --------------------------------------------------
    hint_names = bytearray()
    hint_name_rvas: list[int] = []
    for func in _KERNEL32_FUNCTIONS:
        rva = PE_IDATA_RVA + hint_names_start + len(hint_names)
        hint_name_rvas.append(rva)
        entry = struct.pack("<H", 0) + func.encode("ascii") + b"\x00"
        if len(entry) % 2:
            entry += b"\x00"  # pad to even boundary
        hint_names += entry

    # -- DLL name -----------------------------------------------------------
    dll_name_rva = PE_IDATA_RVA + hint_names_start + len(hint_names)
    dll_name = b"kernel32.dll\x00"

    # -- IAT & ILT (identical at link time; loader patches IAT) -------------
    table = bytearray()
    for rva in hint_name_rvas:
        table += struct.pack("<Q", rva)
    table += struct.pack("<Q", 0)  # null terminator

    iat = bytes(table)
    ilt = bytes(table)

    # -- Import Directory Table (IDT) ---------------------------------------
    idt = struct.pack(
        "<IIIII",
        PE_IDATA_RVA + ilt_offset,   # OriginalFirstThunk → ILT
        0,                            # TimeDateStamp
        0,                            # ForwarderChain
        dll_name_rva,                 # Name → DLL name string
        PE_IDATA_RVA + iat_offset,   # FirstThunk → IAT
    )
    idt += b"\x00" * 20  # null terminator entry

    section = iat + ilt + idt + bytes(hint_names) + dll_name
    return section, iat_offset, ilt_offset, idt_offset


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_pe64(code: bytes, data: bytes = b"") -> bytes:
    """Generate a minimal PE64 (x86_64) Windows executable.

    The binary imports commonly-used Windows API functions from
    kernel32.dll.  IAT entries reside at fixed virtual addresses so that
    generated machine code can reference them directly (see
    ``PE_IAT_EXPORTS`` for the full mapping).

    Args:
        code: Machine code placed at the start of the ``.text`` section.
        data: Optional data appended after *code* in the same section.

    Returns:
        Complete PE file as :class:`bytes`.
    """
    payload = code + data

    # -- .idata section -----------------------------------------------------
    idata_raw, iat_off, _ilt_off, idt_off = _build_idata_section()

    num_funcs = len(_KERNEL32_FUNCTIONS)
    iat_size = (num_funcs + 1) * 8

    # -- sizes (file layout) ------------------------------------------------
    headers_size = PE_FILE_ALIGNMENT  # 0x200
    text_raw_size = _align(max(len(payload), 1), PE_FILE_ALIGNMENT)
    idata_raw_size = _align(len(idata_raw), PE_FILE_ALIGNMENT)

    text_file_offset = headers_size
    idata_file_offset = text_file_offset + text_raw_size

    # Virtual image size (headers + .text + .idata pages)
    size_of_image = _align(
        PE_IDATA_RVA + len(idata_raw), PE_SECTION_ALIGNMENT,
    )

    # ── DOS Header (64 bytes) ─────────────────────────────────────────────
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew → offset of PE sig

    # ── PE Signature (4 bytes) ────────────────────────────────────────────
    pe_sig = b"PE\x00\x00"

    # ── COFF File Header (20 bytes) ───────────────────────────────────────
    coff = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_AMD64,  # Machine
        2,                          # NumberOfSections
        0,                          # TimeDateStamp
        0,                          # PointerToSymbolTable
        0,                          # NumberOfSymbols
        240,                        # SizeOfOptionalHeader (PE32+)
        0x22,                       # Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)
    )

    # ── Optional Header — standard fields (24 bytes) ──────────────────────
    opt_std = struct.pack(
        "<HBBIIIII",
        0x20B,          # Magic (PE32+)
        14,             # MajorLinkerVersion
        0,              # MinorLinkerVersion
        text_raw_size,  # SizeOfCode
        idata_raw_size, # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        PE_CODE_RVA,    # AddressOfEntryPoint
        PE_CODE_RVA,    # BaseOfCode
    )

    # ── Optional Header — Windows-specific fields (88 bytes) ──────────────
    opt_win = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        PE_IMAGE_BASE,          # ImageBase
        PE_SECTION_ALIGNMENT,   # SectionAlignment
        PE_FILE_ALIGNMENT,      # FileAlignment
        6,                      # MajorOperatingSystemVersion
        0,                      # MinorOperatingSystemVersion
        0,                      # MajorImageVersion
        0,                      # MinorImageVersion
        6,                      # MajorSubsystemVersion
        0,                      # MinorSubsystemVersion
        0,                      # Win32VersionValue
        size_of_image,          # SizeOfImage
        headers_size,           # SizeOfHeaders
        0,                      # CheckSum
        3,                      # Subsystem (IMAGE_SUBSYSTEM_WINDOWS_CUI)
        0x8100,                 # DllCharacteristics (ASLR disabled)
        0x100000,               # SizeOfStackReserve
        0x1000,                 # SizeOfStackCommit
        0x100000,               # SizeOfHeapReserve
        0x1000,                 # SizeOfHeapCommit
        0,                      # LoaderFlags
        16,                     # NumberOfRvaAndSizes
    )

    # ── Data directories (16 x 8 = 128 bytes) ────────────────────────────
    data_dirs = bytearray(128)
    # [1] Import Table → IDT
    struct.pack_into("<II", data_dirs, 1 * 8,
                     PE_IDATA_RVA + idt_off, 40)
    # [12] IAT
    struct.pack_into("<II", data_dirs, 12 * 8,
                     PE_IDATA_RVA + iat_off, iat_size)

    optional = opt_std + opt_win + bytes(data_dirs)

    # ── Section headers (40 bytes each) ───────────────────────────────────
    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(payload),       # VirtualSize
        PE_CODE_RVA,        # VirtualAddress
        text_raw_size,      # SizeOfRawData
        text_file_offset,   # PointerToRawData
        0, 0, 0, 0,
        0x60000020,         # CODE | EXECUTE | READ
    )

    sec_idata = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\x00\x00",
        len(idata_raw),     # VirtualSize
        PE_IDATA_RVA,       # VirtualAddress
        idata_raw_size,     # SizeOfRawData
        idata_file_offset,  # PointerToRawData
        0, 0, 0, 0,
        0xC0000040,         # INITIALIZED_DATA | READ | WRITE
    )

    # ── Assemble ──────────────────────────────────────────────────────────
    hdr = bytes(dos) + pe_sig + coff + optional + sec_text + sec_idata
    hdr_padded = hdr + b"\x00" * (headers_size - len(hdr))

    text_padded = payload + b"\x00" * (text_raw_size - len(payload))
    idata_padded = idata_raw + b"\x00" * (idata_raw_size - len(idata_raw))

    return hdr_padded + text_padded + idata_padded
