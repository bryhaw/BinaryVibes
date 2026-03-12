"""Binary patching — apply byte-level changes to a binary."""

from __future__ import annotations

from dataclasses import dataclass

from binaryvibes.core.binary import BinaryFile


@dataclass(frozen=True)
class Patch:
    """A single byte-level patch: overwrite `length` bytes at `offset` with `data`."""

    offset: int
    data: bytes
    description: str = ""

    @property
    def length(self) -> int:
        return len(self.data)


def apply_patches(binary: BinaryFile, patches: list[Patch]) -> bytes:
    """Apply a list of patches to a binary's raw bytes, returning the new content."""
    buf = bytearray(binary.raw)
    for p in sorted(patches, key=lambda x: x.offset):
        end = p.offset + p.length
        if end > len(buf):
            msg = f"Patch at 0x{p.offset:x} exceeds binary size ({len(buf)} bytes)"
            raise ValueError(msg)
        buf[p.offset : end] = p.data
    return bytes(buf)
