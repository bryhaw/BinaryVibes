"""Architecture definitions and ISA abstractions."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from enum import Enum

import capstone
import keystone


class Arch(Enum):
    """Supported CPU architectures."""

    X86_64 = "x86_64"
    X86_32 = "x86_32"
    ARM64 = "arm64"
    ARM32 = "arm32"


class BinaryFormat(Enum):
    """Output binary format."""

    ELF = "elf"
    PE = "pe"
    MACHO = "macho"


def detect_native_format() -> BinaryFormat:
    """Return the binary format native to the current OS."""
    system = platform.system()
    if system == "Windows":
        return BinaryFormat.PE
    elif system == "Darwin":
        return BinaryFormat.MACHO
    return BinaryFormat.ELF


class Endianness(Enum):
    LITTLE = "little"
    BIG = "big"


@dataclass(frozen=True)
class ArchConfig:
    """Capstone/Keystone configuration for an architecture."""

    arch: Arch
    cs_arch: int
    cs_mode: int
    ks_arch: int
    ks_mode: int
    word_size: int
    endianness: Endianness


ARCH_CONFIGS: dict[Arch, ArchConfig] = {
    Arch.X86_64: ArchConfig(
        arch=Arch.X86_64,
        cs_arch=capstone.CS_ARCH_X86,
        cs_mode=capstone.CS_MODE_64,
        ks_arch=keystone.KS_ARCH_X86,
        ks_mode=keystone.KS_MODE_64,
        word_size=8,
        endianness=Endianness.LITTLE,
    ),
    Arch.X86_32: ArchConfig(
        arch=Arch.X86_32,
        cs_arch=capstone.CS_ARCH_X86,
        cs_mode=capstone.CS_MODE_32,
        ks_arch=keystone.KS_ARCH_X86,
        ks_mode=keystone.KS_MODE_32,
        word_size=4,
        endianness=Endianness.LITTLE,
    ),
    Arch.ARM64: ArchConfig(
        arch=Arch.ARM64,
        cs_arch=capstone.CS_ARCH_ARM64,
        cs_mode=capstone.CS_MODE_ARM,
        ks_arch=keystone.KS_ARCH_ARM64,
        ks_mode=keystone.KS_MODE_LITTLE_ENDIAN,
        word_size=8,
        endianness=Endianness.LITTLE,
    ),
    Arch.ARM32: ArchConfig(
        arch=Arch.ARM32,
        cs_arch=capstone.CS_ARCH_ARM,
        cs_mode=capstone.CS_MODE_ARM,
        ks_arch=keystone.KS_ARCH_ARM,
        ks_mode=keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN,
        word_size=4,
        endianness=Endianness.LITTLE,
    ),
}
