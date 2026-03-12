"""Assembly engine built on Keystone — turns mnemonics into bytes."""

from __future__ import annotations

import keystone

from binaryvibes.core.arch import ARCH_CONFIGS, Arch


class Assembler:
    """Assemble instruction strings into machine code."""

    def __init__(self, arch: Arch) -> None:
        cfg = ARCH_CONFIGS[arch]
        self._ks = keystone.Ks(cfg.ks_arch, cfg.ks_mode)

    def assemble(self, asm: str, base_addr: int = 0) -> bytes:
        """Assemble one or more instructions. Returns raw bytes."""
        encoding, _count = self._ks.asm(asm, base_addr)
        if encoding is None:
            msg = f"Keystone failed to assemble: {asm}"
            raise ValueError(msg)
        return bytes(encoding)
