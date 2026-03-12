"""Function hooking workflow — redirect function calls without source code."""

from __future__ import annotations

from dataclasses import dataclass

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.synthesis.patcher import Patch, apply_patches

__all__ = [
    "Hook",
    "HookResult",
    "detour_call",
    "hook_function",
    "hook_with_code",
    "unhook_function",
]

# x86_64 JMP rel32 is 5 bytes: E9 <rel32>
_X86_64_JMP_SIZE = 5


@dataclass(frozen=True)
class Hook:
    """Describes a function hook."""

    target_offset: int  # Where the original function starts
    hook_offset: int  # Where our hook code lives
    original_bytes: bytes  # Saved original bytes (for unhooking)
    trampoline: Patch  # The JMP patch that redirects

    def __str__(self) -> str:
        return (
            f"Hook(0x{self.target_offset:x} → 0x{self.hook_offset:x}, "
            f"saved {len(self.original_bytes)}B)"
        )


@dataclass
class HookResult:
    """Result of applying hooks to a binary."""

    patched_binary: BinaryFile
    hooks: list[Hook]

    @property
    def hook_count(self) -> int:
        return len(self.hooks)


def _require_x86_64(arch: Arch, operation: str) -> None:
    if arch != Arch.X86_64:
        raise NotImplementedError(f"{operation} not yet supported for {arch.value}")


def _make_jmp_patch(source: int, target: int, description: str) -> Patch:
    """Build a 5-byte JMP rel32 patch."""
    displacement = target - (source + _X86_64_JMP_SIZE)
    jmp_bytes = b"\xe9" + displacement.to_bytes(4, byteorder="little", signed=True)
    return Patch(source, jmp_bytes, description)


def hook_function(
    binary: BinaryFile,
    target_offset: int,
    hook_offset: int,
    arch: Arch = Arch.X86_64,
) -> HookResult:
    """Hook a function by placing a JMP trampoline at *target_offset* → *hook_offset*.

    Args:
        binary: The binary to modify.
        target_offset: Byte offset of the function to hook.
        hook_offset: Byte offset where the hook code lives (or will be placed).
        arch: Target architecture.

    Returns:
        HookResult with patched binary and hook metadata.
    """
    _require_x86_64(arch, "Hooking")

    original_bytes = binary.raw[target_offset : target_offset + _X86_64_JMP_SIZE]
    trampoline_patch = _make_jmp_patch(
        target_offset,
        hook_offset,
        f"hook: 0x{target_offset:x} → 0x{hook_offset:x}",
    )

    patched_raw = apply_patches(binary, [trampoline_patch])
    name = f"{binary.path.name}_hooked" if binary.path else "hooked"
    patched_binary = BinaryFile.from_bytes(patched_raw, name=name)

    hook = Hook(target_offset, hook_offset, original_bytes, trampoline_patch)
    return HookResult(patched_binary, [hook])


def unhook_function(binary: BinaryFile, hook: Hook) -> BinaryFile:
    """Remove a hook by restoring the original bytes."""
    restore_patch = Patch(
        hook.target_offset,
        hook.original_bytes,
        f"unhook: 0x{hook.target_offset:x}",
    )
    patched_raw = apply_patches(binary, [restore_patch])
    return BinaryFile.from_bytes(patched_raw, name="unhooked")


def hook_with_code(
    binary: BinaryFile,
    target_offset: int,
    hook_asm: str,
    hook_offset: int,
    arch: Arch = Arch.X86_64,
) -> HookResult:
    """Hook a function and inject custom assembly code at *hook_offset*.

    This is the full workflow: inject code **and** redirect to it.

    Args:
        binary: Binary to modify.
        target_offset: Function to hook.
        hook_asm: Assembly code for the hook (should end with a JMP back or RET).
        hook_offset: Where to place the hook code.
        arch: Architecture.
    """
    _require_x86_64(arch, "Hooking")

    asm = Assembler(arch)
    hook_code = asm.assemble(hook_asm, hook_offset)

    original_bytes = binary.raw[target_offset : target_offset + _X86_64_JMP_SIZE]

    # Two patches: 1) inject hook code, 2) trampoline at target
    code_patch = Patch(hook_offset, hook_code, f"hook code at 0x{hook_offset:x}")
    trampoline_patch = _make_jmp_patch(
        target_offset,
        hook_offset,
        f"hook: 0x{target_offset:x} → 0x{hook_offset:x}",
    )

    patched_raw = apply_patches(binary, [code_patch, trampoline_patch])
    patched_binary = BinaryFile.from_bytes(patched_raw, name="hooked")

    hook = Hook(target_offset, hook_offset, original_bytes, trampoline_patch)
    return HookResult(patched_binary, [hook])


def detour_call(
    binary: BinaryFile,
    call_offset: int,
    new_target: int,
    arch: Arch = Arch.X86_64,
) -> BinaryFile:
    """Redirect an existing CALL instruction to a different target.

    Args:
        binary: Binary to modify.
        call_offset: Offset of the CALL instruction (must be a 5-byte ``E8`` call).
        new_target: New target offset.
        arch: Architecture.
    """
    _require_x86_64(arch, "Call detour")

    if binary.raw[call_offset] != 0xE8:
        raise ValueError(
            f"Byte at 0x{call_offset:x} is not a CALL (E8), got 0x{binary.raw[call_offset]:02x}"
        )

    displacement = new_target - (call_offset + 5)
    call_bytes = b"\xe8" + displacement.to_bytes(4, byteorder="little", signed=True)
    patch = Patch(
        call_offset,
        call_bytes,
        f"detour call at 0x{call_offset:x} → 0x{new_target:x}",
    )

    patched_raw = apply_patches(binary, [patch])
    return BinaryFile.from_bytes(patched_raw, name="detoured")
