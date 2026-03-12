"""Emulation-based verification using Unicorn."""

from __future__ import annotations

from dataclasses import dataclass, field

import unicorn
from unicorn.arm64_const import (
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X12,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X14,
    UC_ARM64_REG_X15,
    UC_ARM64_REG_X16,
    UC_ARM64_REG_X17,
    UC_ARM64_REG_X18,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X25,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X27,
    UC_ARM64_REG_X28,
    UC_ARM64_REG_X29,
    UC_ARM64_REG_X30,
)
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

from binaryvibes.core.arch import Arch

# 2 MiB default memory region
DEFAULT_MEM_SIZE = 2 * 1024 * 1024
DEFAULT_BASE = 0x400000
DEFAULT_STACK = 0x800000


@dataclass(frozen=True)
class _EmulatorConfig:
    """Architecture-specific Unicorn configuration."""

    uc_arch: int
    uc_mode: int
    registers: dict[str, int]  # name → Unicorn register constant
    stack_reg: int  # Unicorn constant for stack pointer
    pc_reg: int  # Unicorn constant for program counter


_CONFIGS: dict[Arch, _EmulatorConfig] = {
    Arch.X86_64: _EmulatorConfig(
        uc_arch=unicorn.UC_ARCH_X86,
        uc_mode=unicorn.UC_MODE_64,
        registers={
            "rax": UC_X86_REG_RAX,
            "rbx": UC_X86_REG_RBX,
            "rcx": UC_X86_REG_RCX,
            "rdx": UC_X86_REG_RDX,
            "rsp": UC_X86_REG_RSP,
            "rbp": UC_X86_REG_RBP,
            "rdi": UC_X86_REG_RDI,
            "rsi": UC_X86_REG_RSI,
            "rip": UC_X86_REG_RIP,
        },
        stack_reg=UC_X86_REG_RSP,
        pc_reg=UC_X86_REG_RIP,
    ),
    Arch.ARM64: _EmulatorConfig(
        uc_arch=unicorn.UC_ARCH_ARM64,
        uc_mode=unicorn.UC_MODE_ARM,
        registers={
            "x0": UC_ARM64_REG_X0,
            "x1": UC_ARM64_REG_X1,
            "x2": UC_ARM64_REG_X2,
            "x3": UC_ARM64_REG_X3,
            "x4": UC_ARM64_REG_X4,
            "x5": UC_ARM64_REG_X5,
            "x6": UC_ARM64_REG_X6,
            "x7": UC_ARM64_REG_X7,
            "x8": UC_ARM64_REG_X8,
            "x9": UC_ARM64_REG_X9,
            "x10": UC_ARM64_REG_X10,
            "x11": UC_ARM64_REG_X11,
            "x12": UC_ARM64_REG_X12,
            "x13": UC_ARM64_REG_X13,
            "x14": UC_ARM64_REG_X14,
            "x15": UC_ARM64_REG_X15,
            "x16": UC_ARM64_REG_X16,
            "x17": UC_ARM64_REG_X17,
            "x18": UC_ARM64_REG_X18,
            "x19": UC_ARM64_REG_X19,
            "x20": UC_ARM64_REG_X20,
            "x21": UC_ARM64_REG_X21,
            "x22": UC_ARM64_REG_X22,
            "x23": UC_ARM64_REG_X23,
            "x24": UC_ARM64_REG_X24,
            "x25": UC_ARM64_REG_X25,
            "x26": UC_ARM64_REG_X26,
            "x27": UC_ARM64_REG_X27,
            "x28": UC_ARM64_REG_X28,
            "x29": UC_ARM64_REG_X29,
            "x30": UC_ARM64_REG_X30,
            "sp": UC_ARM64_REG_SP,
            "pc": UC_ARM64_REG_PC,
        },
        stack_reg=UC_ARM64_REG_SP,
        pc_reg=UC_ARM64_REG_PC,
    ),
}


@dataclass
class EmulationResult:
    """Outcome of emulating a code snippet."""

    instructions_executed: int = 0
    final_registers: dict[str, int] = field(default_factory=dict)
    error: str | None = None


class Emulator:
    """Lightweight Unicorn wrapper for verifying patched code snippets."""

    def __init__(self, arch: Arch) -> None:
        if arch not in _CONFIGS:
            msg = f"Emulation not supported for {arch.value}"
            raise NotImplementedError(msg)
        self._arch = arch
        self._config = _CONFIGS[arch]
        self._uc = unicorn.Uc(self._config.uc_arch, self._config.uc_mode)

    def run(
        self,
        code: bytes,
        *,
        base: int = DEFAULT_BASE,
        mem_size: int = DEFAULT_MEM_SIZE,
        max_instructions: int = 1000,
    ) -> EmulationResult:
        """Map memory, load code, emulate, and return register state."""
        uc = self._uc
        cfg = self._config

        uc.mem_map(base, mem_size)
        uc.mem_map(DEFAULT_STACK - mem_size, mem_size)
        uc.mem_write(base, code)
        uc.reg_write(cfg.stack_reg, DEFAULT_STACK)

        count = 0

        def _hook_code(_uc: unicorn.Uc, _addr: int, _size: int, _data: object) -> None:
            nonlocal count
            count += 1

        uc.hook_add(unicorn.UC_HOOK_CODE, _hook_code)

        result = EmulationResult()
        try:
            uc.emu_start(base, base + len(code), count=max_instructions)
        except unicorn.UcError as e:
            result.error = str(e)

        result.instructions_executed = count
        result.final_registers = {name: uc.reg_read(const) for name, const in cfg.registers.items()}
        return result
