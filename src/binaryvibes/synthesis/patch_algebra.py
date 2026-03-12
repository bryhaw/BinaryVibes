"""Patch Algebra — a mathematical framework for composing binary patches as algebraic objects.

Treats patches as first-class algebraic objects with operations for composition,
inversion, conflict detection, and optimization. Enables compositional reasoning
about patch sequences: commutativity checks, automatic merging, and minimal
patch-set computation.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from binaryvibes.synthesis.patcher import Patch


@dataclass(frozen=True)
class PatchEffect:
    """Records what a patch overwrites, enabling inversion."""

    patch: Patch
    original_bytes: bytes  # What was at the offset before patching


def capture_effect(patch: Patch, binary_data: bytes) -> PatchEffect:
    """Capture the original bytes that a patch would overwrite."""
    original = binary_data[patch.offset : patch.offset + len(patch.data)]
    return PatchEffect(patch=patch, original_bytes=original)


def invert(effect: PatchEffect) -> Patch:
    """Create a patch that undoes the given effect (restores original bytes)."""
    return Patch(
        offset=effect.patch.offset,
        data=effect.original_bytes,
        description=f"invert: {effect.patch.description}",
    )


def rebase(patch: Patch, delta: int) -> Patch:
    """Relocate a patch by shifting its offset by delta bytes."""
    if patch.offset + delta < 0:
        raise ValueError(f"Rebased offset would be negative: {patch.offset} + {delta}")
    return Patch(
        offset=patch.offset + delta,
        data=patch.data,
        description=patch.description,
    )


def overlaps(a: Patch, b: Patch) -> bool:
    """Check if two patches modify overlapping byte ranges."""
    a_start, a_end = a.offset, a.offset + len(a.data)
    b_start, b_end = b.offset, b.offset + len(b.data)
    return a_start < b_end and b_start < a_end


def conflicts(a: Patch, b: Patch) -> bool:
    """Two patches conflict if they overlap AND write different bytes to shared region."""
    if not overlaps(a, b):
        return False
    overlap_start = max(a.offset, b.offset)
    overlap_end = min(a.offset + len(a.data), b.offset + len(b.data))
    a_slice = a.data[overlap_start - a.offset : overlap_end - a.offset]
    b_slice = b.data[overlap_start - b.offset : overlap_end - b.offset]
    return a_slice != b_slice


def compose(a: Patch, b: Patch) -> Patch | list[Patch]:
    """Compose two patches into one (if adjacent/overlapping) or return both (if disjoint).

    If patches overlap, b takes priority (applied second).
    If adjacent, merges into a single contiguous patch.
    If disjoint, returns a list of two patches sorted by offset.
    """
    a_end = a.offset + len(a.data)
    b_end = b.offset + len(b.data)

    # Disjoint: no overlap and not adjacent
    if a_end < b.offset or b_end < a.offset:
        return sorted([a, b], key=lambda p: p.offset)

    # Overlapping or adjacent — merge with b taking priority
    merged_start = min(a.offset, b.offset)
    merged_end = max(a_end, b_end)
    buf = bytearray(merged_end - merged_start)

    # Lay down a first, then b on top (b wins on overlap)
    buf[a.offset - merged_start : a_end - merged_start] = a.data
    buf[b.offset - merged_start : b_end - merged_start] = b.data

    return Patch(
        offset=merged_start,
        data=bytes(buf),
        description=f"compose: {a.description} + {b.description}",
    )


@dataclass(frozen=True)
class PatchSet:
    """An immutable, ordered collection of non-conflicting patches.

    Supports set-algebraic operations for reasoning about patch combinations.
    """

    patches: tuple[Patch, ...]

    def __init__(self, patches: Iterable[Patch] = ()) -> None:
        sorted_patches = tuple(sorted(patches, key=lambda p: p.offset))
        object.__setattr__(self, "patches", sorted_patches)

    def __len__(self) -> int:
        return len(self.patches)

    def __iter__(self):
        return iter(self.patches)

    def __contains__(self, patch: object) -> bool:
        return patch in self.patches

    @property
    def span(self) -> tuple[int, int] | None:
        """Return (min_offset, max_end) covered by this patch set, or None if empty."""
        if not self.patches:
            return None
        return (
            self.patches[0].offset,
            max(p.offset + len(p.data) for p in self.patches),
        )

    @property
    def total_bytes(self) -> int:
        """Total number of bytes modified by all patches."""
        return sum(len(p.data) for p in self.patches)

    def has_conflicts(self) -> bool:
        """Check if any patches in this set conflict with each other."""
        for i, a in enumerate(self.patches):
            for b in self.patches[i + 1 :]:
                if conflicts(a, b):
                    return True
        return False

    def rebase(self, delta: int) -> PatchSet:
        """Relocate all patches by delta bytes."""
        return PatchSet(rebase(p, delta) for p in self.patches)

    def union(self, other: PatchSet) -> PatchSet:
        """Combine two patch sets. Raises ValueError if resulting set has conflicts."""
        combined = PatchSet((*self.patches, *other.patches))
        if combined.has_conflicts():
            raise ValueError("Cannot union conflicting patch sets")
        return combined

    def difference(self, other: PatchSet) -> PatchSet:
        """Return patches in self that don't overlap with any in other."""
        return PatchSet(p for p in self.patches if not any(overlaps(p, o) for o in other.patches))

    def intersection(self, other: PatchSet) -> PatchSet:
        """Return patches in self that DO overlap with patches in other."""
        return PatchSet(p for p in self.patches if any(overlaps(p, o) for o in other.patches))

    def without(self, patch: Patch) -> PatchSet:
        """Return a new PatchSet with the specified patch removed."""
        return PatchSet(p for p in self.patches if p != patch)

    def with_patch(self, patch: Patch) -> PatchSet:
        """Return a new PatchSet with the given patch added. Raises if conflicts."""
        new_set = PatchSet((*self.patches, patch))
        if new_set.has_conflicts():
            raise ValueError(f"Patch at offset 0x{patch.offset:x} conflicts with existing patches")
        return new_set


def optimize(patches: list[Patch]) -> list[Patch]:
    """Merge adjacent and overlapping patches into minimal set.

    Adjacent patches (a.offset + len(a.data) == b.offset) are merged.
    Overlapping patches are merged with later patches taking priority.
    Returns a minimal list of non-overlapping patches covering the same modifications.
    """
    if not patches:
        return []

    sorted_patches = sorted(patches, key=lambda p: p.offset)
    result: list[Patch] = []
    current_start = sorted_patches[0].offset
    current_data = bytearray(sorted_patches[0].data)
    current_end = current_start + len(current_data)

    for patch in sorted_patches[1:]:
        p_end = patch.offset + len(patch.data)
        if patch.offset <= current_end:
            # Overlapping or adjacent — merge
            new_end = max(current_end, p_end)
            if new_end > current_end:
                current_data.extend(b"\x00" * (new_end - current_end))
            # Overwrite with this patch's data (later patch wins)
            rel_start = patch.offset - current_start
            current_data[rel_start : rel_start + len(patch.data)] = patch.data
            current_end = new_end
        else:
            # Disjoint — flush current and start new
            result.append(
                Patch(offset=current_start, data=bytes(current_data), description="merged")
            )
            current_start = patch.offset
            current_data = bytearray(patch.data)
            current_end = p_end

    result.append(Patch(offset=current_start, data=bytes(current_data), description="merged"))
    return result
