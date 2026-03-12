"""Shared test fixtures for BinaryVibes."""

from __future__ import annotations

import struct
from pathlib import Path

import keystone
import pytest

from binaryvibes.core.binary import BinaryFile

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _assemble_x86_64(asm: str) -> bytes:
    """Assemble x86_64 instructions using Keystone."""
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    encoding, _ = ks.asm(asm)
    return bytes(encoding)


def _build_minimal_elf64(code: bytes) -> bytes:
    """Construct a minimal ELF64 executable containing *code*."""
    ehdr_size = 64
    phdr_size = 56
    base_addr = 0x400000
    code_offset = ehdr_size + phdr_size
    entry_point = base_addr + code_offset
    total_size = code_offset + len(code)

    # ELF64 header
    ehdr = struct.pack(
        "<4sBBBBB7sHHIQQQIHHHHHH",
        b"\x7fELF",  # e_ident magic
        2,  # EI_CLASS: 64-bit
        1,  # EI_DATA: little-endian
        1,  # EI_VERSION: current
        0,  # EI_OSABI: ELFOSABI_NONE
        0,  # EI_ABIVERSION
        b"\x00" * 7,  # EI_PAD
        2,  # e_type: ET_EXEC
        0x3E,  # e_machine: EM_X86_64
        1,  # e_version: EV_CURRENT
        entry_point,  # e_entry
        ehdr_size,  # e_phoff (program header offset)
        0,  # e_shoff (no section headers)
        0,  # e_flags
        ehdr_size,  # e_ehsize
        phdr_size,  # e_phentsize
        1,  # e_phnum
        0,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )

    # Program header: PT_LOAD, R+X
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type: PT_LOAD
        5,  # p_flags: PF_R | PF_X
        0,  # p_offset
        base_addr,  # p_vaddr
        base_addr,  # p_paddr
        total_size,  # p_filesz
        total_size,  # p_memsz
        0x200000,  # p_align
    )

    return ehdr + phdr + code


def _generate_tiny_elf(dest: Path) -> Path:
    """Assemble and write the tiny ELF fixture to *dest*."""
    asm = "mov rax, 60; mov rdi, 42; syscall"
    code = _assemble_x86_64(asm)
    elf_bytes = _build_minimal_elf64(code)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(elf_bytes)
    return dest


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixture binaries."""
    return FIXTURES_DIR


@pytest.fixture(scope="session", autouse=True)
def ensure_tiny_elf() -> Path:
    """Auto-generate the tiny_elf fixture if it doesn't exist."""
    path = FIXTURES_DIR / "tiny_elf"
    if not path.exists():
        _generate_tiny_elf(path)
    return path


@pytest.fixture
def tiny_elf(fixtures_dir: Path) -> Path:
    """Path to a minimal ELF binary for testing."""
    return fixtures_dir / "tiny_elf"


@pytest.fixture
def tiny_elf_binary(tiny_elf: Path) -> BinaryFile:
    """A loaded BinaryFile from the tiny ELF fixture."""
    return BinaryFile.from_path(tiny_elf)


@pytest.fixture
def x86_code_bytes() -> bytes:
    """Raw assembled x86_64 bytes: mov rax,60; mov rdi,42; syscall."""
    return _assemble_x86_64("mov rax, 60; mov rdi, 42; syscall")
