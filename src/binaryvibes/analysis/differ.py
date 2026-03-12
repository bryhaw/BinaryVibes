"""Binary diffing — compare two binaries to find differences."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from binaryvibes.core.binary import BinaryFile


class DiffType(Enum):
    MODIFIED = "modified"  # Bytes changed at same offset
    ADDED = "added"  # Bytes present only in second binary (longer)
    REMOVED = "removed"  # Bytes present only in first binary (shorter)


@dataclass(frozen=True)
class Difference:
    """A contiguous region where two binaries differ."""

    offset: int
    old_bytes: bytes  # From first binary (empty if ADDED)
    new_bytes: bytes  # From second binary (empty if REMOVED)
    diff_type: DiffType

    @property
    def length(self) -> int:
        return max(len(self.old_bytes), len(self.new_bytes))

    def __str__(self) -> str:
        return (
            f"0x{self.offset:08x} [{self.diff_type.value}] "
            f"{self.old_bytes.hex()} → {self.new_bytes.hex()}"
        )


@dataclass
class DiffReport:
    """Summary of differences between two binaries."""

    differences: list[Difference] = field(default_factory=list)
    size_a: int = 0
    size_b: int = 0

    @property
    def total_differences(self) -> int:
        return len(self.differences)

    @property
    def bytes_changed(self) -> int:
        return sum(d.length for d in self.differences)

    @property
    def similarity(self) -> float:
        """Return similarity ratio 0.0-1.0 (1.0 = identical)."""
        max_size = max(self.size_a, self.size_b)
        if max_size == 0:
            return 1.0
        return 1.0 - (self.bytes_changed / max_size)

    @property
    def is_identical(self) -> bool:
        return len(self.differences) == 0

    def summary(self) -> str:
        return (
            f"Diff: {self.total_differences} regions, "
            f"{self.bytes_changed} bytes changed, "
            f"{self.similarity:.1%} similar"
        )


def byte_diff(a: BinaryFile, b: BinaryFile) -> DiffReport:
    """Compare two binaries byte-by-byte, grouping contiguous changes."""
    report = DiffReport(size_a=len(a.raw), size_b=len(b.raw))

    min_len = min(len(a.raw), len(b.raw))

    # Find contiguous regions of difference in the shared range
    i = 0
    while i < min_len:
        if a.raw[i] != b.raw[i]:
            start = i
            while i < min_len and a.raw[i] != b.raw[i]:
                i += 1
            report.differences.append(
                Difference(
                    offset=start,
                    old_bytes=a.raw[start:i],
                    new_bytes=b.raw[start:i],
                    diff_type=DiffType.MODIFIED,
                )
            )
        else:
            i += 1

    # Handle size differences
    if len(a.raw) > len(b.raw):
        report.differences.append(
            Difference(
                offset=min_len,
                old_bytes=a.raw[min_len:],
                new_bytes=b"",
                diff_type=DiffType.REMOVED,
            )
        )
    elif len(b.raw) > len(a.raw):
        report.differences.append(
            Difference(
                offset=min_len,
                old_bytes=b"",
                new_bytes=b.raw[min_len:],
                diff_type=DiffType.ADDED,
            )
        )

    return report


def hex_dump_diff(a: BinaryFile, b: BinaryFile, context: int = 16) -> str:
    """Generate a human-readable hex diff with context lines."""
    report = byte_diff(a, b)
    if report.is_identical:
        return "Binaries are identical"

    lines = [report.summary(), ""]
    for diff in report.differences:
        lines.append(str(diff))
        # Show context: a few bytes before and after
        ctx_start = max(0, diff.offset - context)
        ctx_end = min(min(len(a.raw), len(b.raw)), diff.offset + diff.length + context)
        if ctx_start < diff.offset:
            lines.append(f"  context before: ...{a.raw[ctx_start : diff.offset].hex()}")
        if diff.offset + diff.length < ctx_end:
            end_offset = diff.offset + diff.length
            lines.append(f"  context after:  {a.raw[end_offset:ctx_end].hex()}...")

    return "\n".join(lines)
