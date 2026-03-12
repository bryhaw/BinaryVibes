"""Binary file abstraction — the central object in BinaryVibes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import lief

from binaryvibes.core.arch import Arch


@dataclass
class BinaryFile:
    """Represents a loaded binary with parsed metadata.

    This is the primary object that flows through analysis → synthesis → verify.
    """

    path: Path
    raw: bytes = field(repr=False)
    arch: Arch | None = None
    format_name: str = ""
    _lief_binary: lief.Binary | None = field(default=None, repr=False)

    @classmethod
    def from_path(cls, path: str | Path) -> BinaryFile:
        """Load a binary from disk."""
        path = Path(path)
        raw = path.read_bytes()
        parsed = lief.parse(str(path))

        arch = _detect_arch(parsed) if parsed else None
        fmt = type(parsed).__name__ if parsed else "unknown"

        return cls(path=path, raw=raw, arch=arch, format_name=fmt, _lief_binary=parsed)

    @classmethod
    def from_bytes(cls, data: bytes, *, name: str = "<memory>") -> BinaryFile:
        """Create a BinaryFile from raw bytes."""
        parsed = lief.parse(list(data))
        arch = _detect_arch(parsed) if parsed else None
        fmt = type(parsed).__name__ if parsed else "unknown"
        return cls(path=Path(name), raw=data, arch=arch, format_name=fmt, _lief_binary=parsed)

    @property
    def lief(self) -> lief.Binary:
        if self._lief_binary is None:
            msg = f"LIEF could not parse {self.path}"
            raise ValueError(msg)
        return self._lief_binary

    def write(self, dest: str | Path) -> None:
        """Write the (possibly modified) binary to disk."""
        self.lief.write(str(dest))


def _detect_arch(parsed: lief.Binary | None) -> Arch | None:
    """Best-effort architecture detection from a LIEF binary."""
    if parsed is None:
        return None
    if isinstance(parsed, lief.ELF.Binary):
        machine = parsed.header.machine_type
        if machine == lief.ELF.ARCH.X86_64:
            return Arch.X86_64
        if machine == lief.ELF.ARCH.I386:
            return Arch.X86_32
        if machine == lief.ELF.ARCH.AARCH64:
            return Arch.ARM64
        if machine == lief.ELF.ARCH.ARM:
            return Arch.ARM32
    if isinstance(parsed, lief.PE.Binary):
        machine = parsed.header.machine
        if machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            return Arch.X86_64
        if machine == lief.PE.Header.MACHINE_TYPES.I386:
            return Arch.X86_32
    return None
