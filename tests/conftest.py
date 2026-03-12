"""Shared test fixtures for BinaryVibes."""

from __future__ import annotations

import struct
from pathlib import Path

import keystone
import pytest

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.synthesis.generator import BinaryBuilder

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


# ── Complex fixture generators ──────────────────────────────────────

# Code starts after ELF64 header (64) + program header (56) = 120 = 0x78
_CODE_VADDR = 0x400078


def _generate_multi_func_elf(dest: Path) -> Path:
    """Build an ELF with multiple functions calling each other."""
    asm = Assembler(Arch.X86_64)
    code = asm.assemble(
        """
        func_add:
            mov rax, rdi
            add rax, rsi
            ret
        func_double:
            mov rsi, rdi
            call func_add
            ret
        main:
            mov rdi, 10
            mov rsi, 20
            call func_add
            mov rdi, rax
            call func_double
            mov rdi, rax
            mov rax, 60
            syscall
        """,
        _CODE_VADDR,
    )
    binary = BinaryBuilder().set_arch(Arch.X86_64).add_code(code).build()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(binary.raw)
    return dest


def _generate_vuln_elf(dest: Path) -> Path:
    """Build an ELF with 'vulnerable' patterns for security audit demos."""
    asm = Assembler(Arch.X86_64)
    code = asm.assemble(
        """
        start:
            xor rax, rax
            call dangerous_func
            mov rdi, rax
            call another_func
            test rax, rax
            je skip_check
            nop
            nop
            nop
            nop
            nop
        skip_check:
            xor rdi, rdi
            mov rax, 60
            syscall
        dangerous_func:
            mov rax, 1
            ret
        another_func:
            mov rax, 0
            ret
        """,
        _CODE_VADDR,
    )
    binary = BinaryBuilder().set_arch(Arch.X86_64).add_code(code).build()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(binary.raw)
    return dest


def _generate_padded_elf(dest: Path) -> Path:
    """Build an ELF with NOP padding for transplant/hooking demos."""
    asm = Assembler(Arch.X86_64)
    code = asm.assemble("mov rax, 42; ret", _CODE_VADDR)
    padding = b"\x90" * 256
    binary = BinaryBuilder().set_arch(Arch.X86_64).add_code(code + padding).build()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(binary.raw)
    return dest


# ── Complex fixtures ────────────────────────────────────────────────


@pytest.fixture(scope="session")
def multi_func_elf() -> Path:
    """Path to an ELF with multiple inter-calling functions."""
    path = FIXTURES_DIR / "multi_func_elf"
    if not path.exists():
        _generate_multi_func_elf(path)
    return path


@pytest.fixture(scope="session")
def multi_func_binary(multi_func_elf: Path) -> BinaryFile:
    """A loaded BinaryFile from the multi-function ELF fixture."""
    return BinaryFile.from_path(multi_func_elf)


@pytest.fixture(scope="session")
def vuln_elf() -> Path:
    """Path to an ELF with vulnerable code patterns."""
    path = FIXTURES_DIR / "vuln_elf"
    if not path.exists():
        _generate_vuln_elf(path)
    return path


@pytest.fixture(scope="session")
def vuln_binary(vuln_elf: Path) -> BinaryFile:
    """A loaded BinaryFile from the vulnerable ELF fixture."""
    return BinaryFile.from_path(vuln_elf)


@pytest.fixture(scope="session")
def padded_elf() -> Path:
    """Path to an ELF with NOP padding for hook space."""
    path = FIXTURES_DIR / "padded_elf"
    if not path.exists():
        _generate_padded_elf(path)
    return path


@pytest.fixture(scope="session")
def padded_binary(padded_elf: Path) -> BinaryFile:
    """A loaded BinaryFile from the padded ELF fixture."""
    return BinaryFile.from_path(padded_elf)
