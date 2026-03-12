"""Tests for the Patch Algebra system."""

import pytest

from binaryvibes.synthesis.patch_algebra import (
    PatchEffect,
    PatchSet,
    capture_effect,
    compose,
    conflicts,
    invert,
    optimize,
    overlaps,
    rebase,
)
from binaryvibes.synthesis.patcher import Patch

# ---------------------------------------------------------------------------
# overlaps()
# ---------------------------------------------------------------------------


class TestOverlaps:
    def test_no_overlap(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04")
        assert overlaps(p1, p2) is False

    def test_overlap(self):
        p1 = Patch(offset=0, data=b"\x01\x02\x03\x04")
        p2 = Patch(offset=2, data=b"\x05\x06")
        assert overlaps(p1, p2) is True

    def test_adjacent_no_overlap(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=2, data=b"\x03\x04")
        assert overlaps(p1, p2) is False


# ---------------------------------------------------------------------------
# conflicts()
# ---------------------------------------------------------------------------


class TestConflicts:
    def test_no_conflict_disjoint(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04")
        assert conflicts(p1, p2) is False

    def test_conflict_overlapping_different(self):
        p1 = Patch(offset=0, data=b"\x01\x02\x03")
        p2 = Patch(offset=2, data=b"\xff\xfe")
        assert conflicts(p1, p2) is True

    def test_no_conflict_same_bytes(self):
        p1 = Patch(offset=0, data=b"\x01\x02\x03")
        p2 = Patch(offset=2, data=b"\x03\x04")
        # Overlap at byte offset 2: p1 writes 0x03, p2 writes 0x03 → same byte
        assert conflicts(p1, p2) is False


# ---------------------------------------------------------------------------
# rebase()
# ---------------------------------------------------------------------------


class TestRebase:
    def test_rebase_positive(self):
        p = Patch(offset=10, data=b"\xaa\xbb", description="orig")
        rebased = rebase(p, 5)
        assert rebased.offset == 15
        assert rebased.data == b"\xaa\xbb"
        assert rebased.description == "orig"

    def test_rebase_negative(self):
        p = Patch(offset=10, data=b"\xaa\xbb")
        rebased = rebase(p, -3)
        assert rebased.offset == 7

    def test_rebase_negative_underflow(self):
        p = Patch(offset=5, data=b"\xaa")
        with pytest.raises(ValueError, match="negative"):
            rebase(p, -10)


# ---------------------------------------------------------------------------
# capture_effect / invert
# ---------------------------------------------------------------------------


class TestCaptureEffectAndInvert:
    def test_capture_effect(self):
        binary_data = b"\x00\x11\x22\x33\x44\x55"
        patch = Patch(offset=2, data=b"\xff\xfe")
        effect = capture_effect(patch, binary_data)
        assert isinstance(effect, PatchEffect)
        assert effect.patch is patch
        assert effect.original_bytes == b"\x22\x33"

    def test_invert_patch(self):
        binary_data = b"\x00\x11\x22\x33\x44\x55"
        patch = Patch(offset=2, data=b"\xff\xfe", description="modify")
        effect = capture_effect(patch, binary_data)
        inv = invert(effect)
        assert inv.offset == 2
        assert inv.data == b"\x22\x33"
        assert "invert" in inv.description

    def test_round_trip(self):
        original = bytearray(b"\x00\x11\x22\x33\x44\x55")
        patch = Patch(offset=1, data=b"\xaa\xbb\xcc")

        # Capture effect before applying
        effect = capture_effect(patch, bytes(original))

        # Apply the patch
        modified = bytearray(original)
        modified[patch.offset : patch.offset + len(patch.data)] = patch.data
        assert modified != original

        # Invert and apply the undo patch
        undo = invert(effect)
        modified[undo.offset : undo.offset + len(undo.data)] = undo.data
        assert bytes(modified) == bytes(original)


# ---------------------------------------------------------------------------
# compose()
# ---------------------------------------------------------------------------


class TestCompose:
    def test_compose_disjoint(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04")
        result = compose(p1, p2)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0].offset < result[1].offset

    def test_compose_overlapping(self):
        p1 = Patch(offset=0, data=b"\x01\x02\x03\x04", description="a")
        p2 = Patch(offset=2, data=b"\xaa\xbb", description="b")
        result = compose(p1, p2)
        assert isinstance(result, Patch)
        assert result.offset == 0
        assert len(result.data) == 4
        # b takes priority on overlap region (bytes 2-3)
        assert result.data == b"\x01\x02\xaa\xbb"

    def test_compose_adjacent(self):
        p1 = Patch(offset=0, data=b"\x01\x02", description="a")
        p2 = Patch(offset=2, data=b"\x03\x04", description="b")
        result = compose(p1, p2)
        assert isinstance(result, Patch)
        assert result.offset == 0
        assert result.data == b"\x01\x02\x03\x04"


# ---------------------------------------------------------------------------
# PatchSet
# ---------------------------------------------------------------------------


class TestPatchSet:
    def test_patchset_creation(self):
        p1 = Patch(offset=10, data=b"\xaa")
        p2 = Patch(offset=0, data=b"\xbb")
        ps = PatchSet([p1, p2])
        # Should be sorted by offset
        assert ps.patches[0].offset == 0
        assert ps.patches[1].offset == 10

    def test_patchset_len(self):
        ps = PatchSet([Patch(offset=0, data=b"\x01"), Patch(offset=5, data=b"\x02")])
        assert len(ps) == 2

    def test_patchset_iter(self):
        patches = [Patch(offset=0, data=b"\x01"), Patch(offset=5, data=b"\x02")]
        ps = PatchSet(patches)
        collected = list(ps)
        assert len(collected) == 2

    def test_patchset_contains(self):
        p1 = Patch(offset=0, data=b"\x01")
        p2 = Patch(offset=5, data=b"\x02")
        ps = PatchSet([p1])
        assert p1 in ps
        assert p2 not in ps

    def test_patchset_span(self):
        p1 = Patch(offset=2, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04\x05")
        ps = PatchSet([p1, p2])
        assert ps.span == (2, 13)

    def test_patchset_span_empty(self):
        ps = PatchSet()
        assert ps.span is None

    def test_patchset_total_bytes(self):
        p1 = Patch(offset=0, data=b"\x01\x02\x03")
        p2 = Patch(offset=10, data=b"\x04\x05")
        ps = PatchSet([p1, p2])
        assert ps.total_bytes == 5

    def test_patchset_has_conflicts(self):
        p1 = Patch(offset=0, data=b"\x01\x02\x03")
        p2 = Patch(offset=2, data=b"\xff")  # overlaps at byte 2, different data
        ps = PatchSet([p1, p2])
        assert ps.has_conflicts() is True

    def test_patchset_no_conflicts(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04")
        ps = PatchSet([p1, p2])
        assert ps.has_conflicts() is False

    def test_patchset_union(self):
        ps1 = PatchSet([Patch(offset=0, data=b"\x01")])
        ps2 = PatchSet([Patch(offset=10, data=b"\x02")])
        combined = ps1.union(ps2)
        assert len(combined) == 2

    def test_patchset_union_conflict(self):
        ps1 = PatchSet([Patch(offset=0, data=b"\x01\x02\x03")])
        ps2 = PatchSet([Patch(offset=2, data=b"\xff")])
        with pytest.raises(ValueError, match="conflicting"):
            ps1.union(ps2)

    def test_patchset_difference(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04")
        ps1 = PatchSet([p1, p2])
        # other overlaps with p2
        ps2 = PatchSet([Patch(offset=10, data=b"\xff")])
        diff = ps1.difference(ps2)
        assert len(diff) == 1
        assert p1 in diff

    def test_patchset_intersection(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04")
        ps1 = PatchSet([p1, p2])
        ps2 = PatchSet([Patch(offset=10, data=b"\xff")])
        inter = ps1.intersection(ps2)
        assert len(inter) == 1
        assert p2 in inter

    def test_patchset_rebase(self):
        ps = PatchSet([Patch(offset=0, data=b"\x01"), Patch(offset=10, data=b"\x02")])
        rebased = ps.rebase(100)
        offsets = [p.offset for p in rebased]
        assert offsets == [100, 110]

    def test_patchset_with_patch(self):
        ps = PatchSet([Patch(offset=0, data=b"\x01")])
        new_ps = ps.with_patch(Patch(offset=10, data=b"\x02"))
        assert len(new_ps) == 2

    def test_patchset_with_patch_conflict(self):
        ps = PatchSet([Patch(offset=0, data=b"\x01\x02\x03")])
        with pytest.raises(ValueError, match="conflicts"):
            ps.with_patch(Patch(offset=2, data=b"\xff"))

    def test_patchset_without(self):
        p1 = Patch(offset=0, data=b"\x01")
        p2 = Patch(offset=10, data=b"\x02")
        ps = PatchSet([p1, p2])
        reduced = ps.without(p1)
        assert len(reduced) == 1
        assert p1 not in reduced
        assert p2 in reduced


# ---------------------------------------------------------------------------
# optimize()
# ---------------------------------------------------------------------------


class TestOptimize:
    def test_optimize_adjacent(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=2, data=b"\x03\x04")
        result = optimize([p1, p2])
        assert len(result) == 1
        assert result[0].offset == 0
        assert result[0].data == b"\x01\x02\x03\x04"

    def test_optimize_overlapping(self):
        p1 = Patch(offset=0, data=b"\x01\x02\x03\x04")
        p2 = Patch(offset=2, data=b"\xaa\xbb")
        result = optimize([p1, p2])
        assert len(result) == 1
        assert result[0].offset == 0
        # Later patch (p2) wins on overlap
        assert result[0].data == b"\x01\x02\xaa\xbb"

    def test_optimize_disjoint(self):
        p1 = Patch(offset=0, data=b"\x01\x02")
        p2 = Patch(offset=10, data=b"\x03\x04")
        result = optimize([p1, p2])
        assert len(result) == 2
        assert result[0].offset == 0
        assert result[1].offset == 10

    def test_optimize_empty(self):
        result = optimize([])
        assert result == []
