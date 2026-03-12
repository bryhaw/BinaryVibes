"""Tests for the hooking workflow."""

from __future__ import annotations

import pytest

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.hooking import (
    detour_call,
    hook_function,
    hook_with_code,
    unhook_function,
)

# ELF64 header (64) + single program header (56) = 120 bytes before code
_CODE_OFFSET = 120


class TestHookFunction:
    """Tests for hook_function()."""

    def test_hook_function_places_jmp(self, tiny_elf_binary: BinaryFile) -> None:
        """Hook at code offset → JMP (0xE9) byte appears at target."""
        target = _CODE_OFFSET
        hook_off = _CODE_OFFSET + 64  # somewhere after the code
        result = hook_function(tiny_elf_binary, target, hook_off)

        assert result.patched_binary.raw[target] == 0xE9

    def test_hook_preserves_original_bytes(self, tiny_elf_binary: BinaryFile) -> None:
        """original_bytes in the Hook match the original binary."""
        target = _CODE_OFFSET
        hook_off = _CODE_OFFSET + 64
        original = tiny_elf_binary.raw[target : target + 5]

        result = hook_function(tiny_elf_binary, target, hook_off)
        hook = result.hooks[0]

        assert hook.original_bytes == original

    def test_unhook_restores_bytes(self, tiny_elf_binary: BinaryFile) -> None:
        """unhook_function restores the original bytes exactly."""
        target = _CODE_OFFSET
        hook_off = _CODE_OFFSET + 64
        original_raw = tiny_elf_binary.raw

        result = hook_function(tiny_elf_binary, target, hook_off)
        restored = unhook_function(result.patched_binary, result.hooks[0])

        assert restored.raw == original_raw

    def test_hook_result_count(self, tiny_elf_binary: BinaryFile) -> None:
        """HookResult.hook_count is 1 after a single hook."""
        result = hook_function(tiny_elf_binary, _CODE_OFFSET, _CODE_OFFSET + 64)
        assert result.hook_count == 1

    def test_hook_str_contains_addresses(self, tiny_elf_binary: BinaryFile) -> None:
        """Hook.__str__ includes both source and destination addresses."""
        result = hook_function(tiny_elf_binary, _CODE_OFFSET, _CODE_OFFSET + 64)
        s = str(result.hooks[0])
        assert hex(_CODE_OFFSET)[2:] in s
        assert hex(_CODE_OFFSET + 64)[2:] in s
        assert "→" in s

    def test_hook_unsupported_arch(self, tiny_elf_binary: BinaryFile) -> None:
        """Hooking with ARM64 raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="not yet supported"):
            hook_function(tiny_elf_binary, _CODE_OFFSET, _CODE_OFFSET + 64, arch=Arch.ARM64)

    def test_round_trip_hook_unhook(self, tiny_elf_binary: BinaryFile) -> None:
        """hook → unhook produces a binary identical to the original."""
        original = tiny_elf_binary.raw
        result = hook_function(tiny_elf_binary, _CODE_OFFSET, _CODE_OFFSET + 64)
        restored = unhook_function(result.patched_binary, result.hooks[0])
        assert restored.raw == original

    def test_hook_with_padded_binary(self, padded_binary: BinaryFile) -> None:
        """Hook using the NOP-padding area as the hook destination."""
        # Padded binary has code at _CODE_OFFSET then 256B of NOPs
        target = _CODE_OFFSET
        # NOP padding starts a few bytes after code; aim into the padding
        hook_off = _CODE_OFFSET + 32

        result = hook_function(padded_binary, target, hook_off)
        assert result.patched_binary.raw[target] == 0xE9
        assert result.hook_count == 1


class TestHookWithCode:
    """Tests for hook_with_code()."""

    def test_hook_with_code_injects_and_redirects(self, padded_binary: BinaryFile) -> None:
        """Inject code + redirect: both patches applied."""
        target = _CODE_OFFSET
        hook_off = _CODE_OFFSET + 64  # in NOP padding area
        asm = "nop; nop; nop; ret"

        result = hook_with_code(padded_binary, target, asm, hook_off)
        patched = result.patched_binary.raw

        # Trampoline at target
        assert patched[target] == 0xE9
        # Hook code at hook_off should contain a RET (0xC3) somewhere
        hook_region = patched[hook_off : hook_off + 16]
        assert 0xC3 in hook_region


class TestDetourCall:
    """Tests for detour_call()."""

    def test_detour_call_redirects(self, multi_func_binary: BinaryFile) -> None:
        """Find a CALL (E8) in multi_func binary and detour it."""
        raw = multi_func_binary.raw
        # Find first CALL instruction (0xE8) after code offset
        call_off = None
        for i in range(_CODE_OFFSET, len(raw) - 4):
            if raw[i] == 0xE8:
                call_off = i
                break
        assert call_off is not None, "No CALL instruction found in multi_func_binary"

        new_target = _CODE_OFFSET
        result = detour_call(multi_func_binary, call_off, new_target)
        assert result.raw[call_off] == 0xE8

    def test_detour_non_call_raises(self, tiny_elf_binary: BinaryFile) -> None:
        """Detour at a non-CALL byte raises ValueError."""
        # First byte of code is 0x48 (REX prefix for mov rax,...), not 0xE8
        with pytest.raises(ValueError, match="not a CALL"):
            detour_call(tiny_elf_binary, _CODE_OFFSET, _CODE_OFFSET + 32)

    def test_detour_unsupported_arch(self, multi_func_binary: BinaryFile) -> None:
        """Detour with ARM64 raises NotImplementedError."""
        with pytest.raises(NotImplementedError, match="not yet supported"):
            detour_call(multi_func_binary, _CODE_OFFSET, _CODE_OFFSET + 32, arch=Arch.ARM64)
