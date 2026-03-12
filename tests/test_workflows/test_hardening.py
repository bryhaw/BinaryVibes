"""Tests for the hardening workflow."""

from __future__ import annotations

from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.hardening import BinaryHardener

_CODE_OFFSET = 120


class TestBinaryHardener:
    """Tests for BinaryHardener operations."""

    def test_nop_out(self, tiny_elf_binary: BinaryFile) -> None:
        """nop_out places NOP bytes (0x90) at the target offset."""
        h = BinaryHardener()
        result = h.nop_out(_CODE_OFFSET, 4).apply(tiny_elf_binary)
        patched = result.patched_binary.raw
        assert patched[_CODE_OFFSET : _CODE_OFFSET + 4] == b"\x90" * 4

    def test_force_return(self, tiny_elf_binary: BinaryFile) -> None:
        """force_return places 'mov eax, N; ret' at the target offset."""
        h = BinaryHardener()
        result = h.force_return(_CODE_OFFSET, 0).apply(tiny_elf_binary)
        patched = result.patched_binary.raw
        # Should contain RET (0xC3) within the patched region
        region = patched[_CODE_OFFSET : _CODE_OFFSET + 16]
        assert 0xC3 in region

    def test_redirect(self, tiny_elf_binary: BinaryFile) -> None:
        """redirect places a JMP (0xE9) at the target offset."""
        h = BinaryHardener()
        target = _CODE_OFFSET + 32
        result = h.redirect(_CODE_OFFSET, target).apply(tiny_elf_binary)
        patched = result.patched_binary.raw
        assert patched[_CODE_OFFSET] == 0xE9

    def test_inject_code(self, padded_binary: BinaryFile) -> None:
        """inject_code places custom assembly at the target offset."""
        h = BinaryHardener()
        offset = _CODE_OFFSET + 64  # NOP padding area
        result = h.inject_code(offset, "nop; nop; ret").apply(padded_binary)
        patched = result.patched_binary.raw
        # Should contain a RET (0xC3) at the inject site
        region = patched[offset : offset + 16]
        assert 0xC3 in region

    def test_fluent_api(self, tiny_elf_binary: BinaryFile) -> None:
        """Method chaining returns the BinaryHardener instance."""
        h = BinaryHardener()
        same = h.nop_out(_CODE_OFFSET, 2).force_return(_CODE_OFFSET + 10, 1)
        assert same is h

    def test_apply_multiple_ops(self, padded_binary: BinaryFile) -> None:
        """Three queued operations produce 3 entries in result.operations."""
        h = BinaryHardener()
        h.nop_out(_CODE_OFFSET + 32, 4, "disable A")
        h.nop_out(_CODE_OFFSET + 40, 4, "disable B")
        h.nop_out(_CODE_OFFSET + 48, 4, "disable C")
        result = h.apply(padded_binary)
        assert result.op_count == 3
        assert len(result.operations) == 3

    def test_result_summary(self, tiny_elf_binary: BinaryFile) -> None:
        """summary() returns a non-empty string with operation details."""
        h = BinaryHardener()
        result = h.nop_out(_CODE_OFFSET, 4, "kill code").apply(tiny_elf_binary)
        s = result.summary()
        assert isinstance(s, str)
        assert "kill code" in s
        assert "1 operations" in s or "1 operation" in s

    def test_result_op_count(self, tiny_elf_binary: BinaryFile) -> None:
        """op_count matches the number of queued operations."""
        h = BinaryHardener()
        h.nop_out(_CODE_OFFSET, 2)
        h.redirect(_CODE_OFFSET + 8, _CODE_OFFSET + 32)
        result = h.apply(tiny_elf_binary)
        assert result.op_count == 2

    def test_empty_apply(self, tiny_elf_binary: BinaryFile) -> None:
        """No operations → original binary unchanged."""
        h = BinaryHardener()
        result = h.apply(tiny_elf_binary)
        assert result.patched_binary.raw == tiny_elf_binary.raw
        assert result.op_count == 0

    def test_hardener_resets_after_apply(self, tiny_elf_binary: BinaryFile) -> None:
        """After apply(), the hardener can be reused with new operations."""
        h = BinaryHardener()
        h.nop_out(_CODE_OFFSET, 4)
        result1 = h.apply(tiny_elf_binary)
        assert result1.op_count == 1

        # Reuse: queue a different operation
        h.nop_out(_CODE_OFFSET, 2)
        result2 = h.apply(tiny_elf_binary)
        assert result2.op_count == 1  # Only the new operation
