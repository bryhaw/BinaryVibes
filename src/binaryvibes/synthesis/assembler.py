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

    def assemble_with_diagnostics(self, asm: str, base_addr: int = 0) -> bytes:
        """Assemble with detailed error reporting on failure.

        On success, returns bytes (same as assemble()).
        On failure, raises ValueError with a message identifying the
        specific failing line and error.
        """
        try:
            return self.assemble(asm, base_addr=base_addr)
        except (ValueError, Exception) as original_error:
            lines = asm.strip().split('\n')
            failing_line = None
            line_num = None
            line_error = str(original_error)

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.endswith(':') or stripped.startswith('.'):
                    continue
                try:
                    self._ks.asm(stripped, base_addr)
                except Exception as e:
                    failing_line = stripped
                    line_num = i
                    line_error = str(e)
                    break

            if failing_line:
                msg = (
                    f"Assembly error on line {line_num}: {failing_line!r}\n"
                    f"Error: {line_error}"
                )
            else:
                msg = (
                    "Assembly failed (possibly unresolved label or "
                    f"multi-line issue): {line_error}"
                )

            raise ValueError(msg) from original_error
