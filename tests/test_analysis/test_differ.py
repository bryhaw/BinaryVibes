"""Tests for the binary diffing module."""

from binaryvibes.analysis.differ import Difference, DiffType, byte_diff, hex_dump_diff
from binaryvibes.core.binary import BinaryFile


def _make(data: bytes, name: str = "<test>") -> BinaryFile:
    return BinaryFile.from_bytes(data, name=name)


class TestByteDiffIdentical:
    def test_identical_binaries(self):
        data = b"\x00\x01\x02\x03\x04"
        report = byte_diff(_make(data), _make(data))
        assert report.is_identical
        assert report.total_differences == 0
        assert report.similarity == 1.0


class TestByteDiffModifications:
    def test_single_byte_change(self):
        a = _make(b"\x00\x01\x02\x03")
        b = _make(b"\x00\xff\x02\x03")
        report = byte_diff(a, b)
        assert report.total_differences == 1
        diff = report.differences[0]
        assert diff.diff_type == DiffType.MODIFIED
        assert diff.offset == 1
        assert diff.old_bytes == b"\x01"
        assert diff.new_bytes == b"\xff"

    def test_multiple_changes(self):
        a = _make(b"\x00\x01\x02\x03\x04\x05")
        b = _make(b"\xff\x01\x02\x03\xfe\x05")
        report = byte_diff(a, b)
        assert report.total_differences == 2
        assert report.differences[0].offset == 0
        assert report.differences[1].offset == 4

    def test_contiguous_changes(self):
        a = _make(b"\x00\x01\x02\x03\x04")
        b = _make(b"\x00\xaa\xbb\xcc\x04")
        report = byte_diff(a, b)
        assert report.total_differences == 1
        diff = report.differences[0]
        assert diff.offset == 1
        assert diff.length == 3
        assert diff.old_bytes == b"\x01\x02\x03"
        assert diff.new_bytes == b"\xaa\xbb\xcc"


class TestByteDiffSizeDifferences:
    def test_added_bytes(self):
        a = _make(b"\x00\x01")
        b = _make(b"\x00\x01\x02\x03")
        report = byte_diff(a, b)
        assert report.total_differences == 1
        diff = report.differences[0]
        assert diff.diff_type == DiffType.ADDED
        assert diff.old_bytes == b""
        assert diff.new_bytes == b"\x02\x03"

    def test_removed_bytes(self):
        a = _make(b"\x00\x01\x02\x03")
        b = _make(b"\x00\x01")
        report = byte_diff(a, b)
        assert report.total_differences == 1
        diff = report.differences[0]
        assert diff.diff_type == DiffType.REMOVED
        assert diff.old_bytes == b"\x02\x03"
        assert diff.new_bytes == b""

    def test_different_sizes_with_modifications(self):
        a = _make(b"\x00\x01\x02\x03")
        b = _make(b"\xff\x01")
        report = byte_diff(a, b)
        assert report.total_differences == 2
        # First: modification at offset 0
        assert report.differences[0].diff_type == DiffType.MODIFIED
        assert report.differences[0].offset == 0
        # Second: removed trailing bytes
        assert report.differences[1].diff_type == DiffType.REMOVED
        assert report.differences[1].offset == 2


class TestByteDiffEdgeCases:
    def test_empty_binaries(self):
        report = byte_diff(_make(b""), _make(b""))
        assert report.is_identical
        assert report.similarity == 1.0

    def test_one_empty(self):
        a = _make(b"")
        b = _make(b"\x01\x02\x03")
        report = byte_diff(a, b)
        assert report.total_differences == 1
        diff = report.differences[0]
        assert diff.diff_type == DiffType.ADDED
        assert diff.new_bytes == b"\x01\x02\x03"


class TestDifferenceStr:
    def test_difference_str(self):
        diff = Difference(
            offset=16,
            old_bytes=b"\xab",
            new_bytes=b"\xcd",
            diff_type=DiffType.MODIFIED,
        )
        s = str(diff)
        assert "0x00000010" in s
        assert "ab" in s
        assert "cd" in s
        assert "modified" in s


class TestDiffReport:
    def test_report_summary(self):
        a = _make(b"\x00\x01\x02")
        b = _make(b"\xff\x01\x02")
        report = byte_diff(a, b)
        summary = report.summary()
        assert "similar" in summary
        assert "1 regions" in summary

    def test_report_bytes_changed(self):
        a = _make(b"\x00\x01\x02\x03\x04\x05")
        b = _make(b"\xff\x01\xfe\x03\x04\x05")
        report = byte_diff(a, b)
        # Two single-byte modifications at offsets 0 and 2
        assert report.bytes_changed == 2

    def test_similarity_range(self):
        # Completely different
        a = _make(b"\x00" * 10)
        b = _make(b"\xff" * 10)
        report = byte_diff(a, b)
        assert 0.0 <= report.similarity <= 1.0

        # Partially similar
        a2 = _make(b"\x00\x01\x02\x03")
        b2 = _make(b"\x00\x01\xff\xff")
        report2 = byte_diff(a2, b2)
        assert 0.0 < report2.similarity < 1.0


class TestHexDumpDiff:
    def test_hex_dump_diff_identical(self):
        data = b"\x00\x01\x02\x03"
        result = hex_dump_diff(_make(data), _make(data))
        assert "identical" in result.lower()

    def test_hex_dump_diff_changes(self):
        a = _make(b"\x00\x01\x02\x03\x04\x05\x06\x07")
        b = _make(b"\x00\x01\xff\x03\x04\x05\x06\x07")
        result = hex_dump_diff(a, b)
        lines = result.strip().splitlines()
        assert len(lines) > 1
        assert "similar" in result
