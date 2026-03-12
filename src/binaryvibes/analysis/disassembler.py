"""Disassembly engine built on Capstone."""

from __future__ import annotations

from dataclasses import dataclass

import capstone

from binaryvibes.core.arch import ARCH_CONFIGS, Arch


@dataclass(frozen=True)
class Instruction:
    """A single disassembled instruction."""

    address: int
    mnemonic: str
    op_str: str
    raw: bytes
    size: int

    def __str__(self) -> str:
        return f"0x{self.address:08x}: {self.mnemonic} {self.op_str}"


class Disassembler:
    """Disassemble raw bytes for a given architecture."""

    def __init__(self, arch: Arch) -> None:
        cfg = ARCH_CONFIGS[arch]
        self._md = capstone.Cs(cfg.cs_arch, cfg.cs_mode)
        self._md.detail = True

    def disassemble(self, code: bytes, base_addr: int = 0) -> list[Instruction]:
        return [
            Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                raw=bytes(insn.bytes),
                size=insn.size,
            )
            for insn in self._md.disasm(code, base_addr)
        ]

    def disassemble_one(self, code: bytes, base_addr: int = 0) -> Instruction | None:
        result = self.disassemble(code, base_addr)
        return result[0] if result else None
