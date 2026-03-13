"""Prompt templates and response parsing for LLM-driven binary synthesis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from binaryvibes.core.arch import Arch


@dataclass(frozen=True)
class AssemblyPlan:
    """Parsed LLM response containing an assembly plan."""

    arch: Arch
    assembly: str
    description: str


ARCH_CONTEXT = {
    Arch.X86_64: """Target: x86_64 (64-bit Intel/AMD, Linux)
Registers: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15
Calling convention: System V AMD64 — args in rdi, rsi, rdx, rcx, r8, r9; return in rax
Syscalls: syscall instruction, number in rax, args in rdi, rsi, rdx, r10, r8, r9
Key syscalls: exit=60 (rdi=code), write=1 (rdi=fd, rsi=buf, rdx=len), read=0
Address size: 64-bit, use RIP-relative addressing when possible
Stack: grows downward, 16-byte aligned before call""",
    Arch.X86_32: """Target: x86_32 (32-bit Intel/AMD, Linux)
Registers: eax, ebx, ecx, edx, esi, edi, ebp, esp
Calling convention: cdecl — args on stack right-to-left; return in eax
Syscalls: int 0x80, number in eax, args in ebx, ecx, edx, esi, edi
Key syscalls: exit=1 (ebx=code), write=4 (ebx=fd, ecx=buf, edx=len), read=3
Address size: 32-bit""",
    Arch.ARM64: """Target: ARM64 (AArch64, Linux)
Registers: x0-x30, sp, pc, xzr (zero register)
Calling convention: args in x0-x7; return in x0
Syscalls: svc #0, number in x8, args in x0-x5
Key syscalls: exit=93 (x0=code), write=64 (x0=fd, x1=buf, x2=len), read=63
Address size: 64-bit, fixed 4-byte instruction width""",
    Arch.ARM32: """Target: ARM32 (ARM, Linux)
Registers: r0-r12, sp (r13), lr (r14), pc (r15)
Calling convention: args in r0-r3; return in r0
Syscalls: svc #0, number in r7, args in r0-r5
Key syscalls: exit=1 (r0=code), write=4 (r0=fd, r1=buf, r2=len), read=3
Address size: 32-bit""",
}


SYSTEM_PROMPT = """You are an expert assembly language programmer working with the BinaryVibes \
framework. Your job is to write assembly code that will be assembled into a standalone Linux ELF \
binary.

CRITICAL RULES:
1. Write ONLY pure assembly instructions — no directives (.section, .global, .text, .data), \
no labels, no comments.
2. The code will be placed at the entry point of a minimal ELF binary. Execution starts at the \
first instruction.
3. The program MUST terminate by calling the exit syscall. Never let execution fall off the end.
4. Use ONLY instructions — no pseudo-ops, no macros, no preprocessor directives.
5. For string data, embed bytes directly using techniques like pushing values onto the stack.
6. Keep it simple and correct. Prefer straightforward implementations over clever tricks.
7. Each instruction goes on its own line.

{arch_context}

RESPONSE FORMAT — you MUST respond with ONLY a JSON object (no markdown fences, no extra text):
{{
  "arch": "{arch_name}",
  "assembly": "instruction1\\ninstruction2\\ninstruction3",
  "description": "Brief description of what the program does"
}}

The "assembly" field contains newline-separated assembly instructions. Nothing else."""


FEW_SHOT_EXAMPLES: dict[Arch, list[dict[str, str]]] = {
    Arch.X86_64: [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": "mov rax, 60\nmov rdi, 42\nsyscall",
                "description": "Exits with status code 42 using the exit syscall",
            }),
        },
        {
            "user": "a program that writes 'Hi' to stdout then exits",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": (
                    "mov rax, 1\nmov rdi, 1\nlea rsi, [rip+10]\nmov rdx, 2\nsyscall\n"
                    "mov rax, 60\nxor rdi, rdi\nsyscall\n.byte 0x48, 0x69"
                ),
                "description": "Writes 'Hi' to stdout using write syscall, then exits cleanly",
            }),
        },
    ],
    Arch.X86_32: [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "x86_32",
                "assembly": "mov eax, 1\nmov ebx, 42\nint 0x80",
                "description": "Exits with status code 42 using int 0x80 syscall",
            }),
        },
    ],
    Arch.ARM64: [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "arm64",
                "assembly": "mov x0, #42\nmov x8, #93\nsvc #0",
                "description": "Exits with status code 42 using svc syscall",
            }),
        },
    ],
    Arch.ARM32: [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "arm32",
                "assembly": "mov r0, #42\nmov r7, #1\nsvc #0",
                "description": "Exits with status code 42 using svc syscall",
            }),
        },
    ],
}


ERROR_RECOVERY_PROMPT = """The assembly code you provided failed to assemble with this error:

{error}

The problematic assembly was:
```
{assembly}
```

Please fix the assembly code and respond with the corrected JSON object. Remember:
- No directives (.section, .global, .text, .data)
- No labels
- No comments
- Only pure assembly instructions
- Must end with exit syscall
- Respond with ONLY the JSON object"""


ARCH_NAME_MAP: dict[str, Arch] = {
    "x86_64": Arch.X86_64,
    "x86_32": Arch.X86_32,
    "arm64": Arch.ARM64,
    "aarch64": Arch.ARM64,
    "arm32": Arch.ARM32,
    "arm": Arch.ARM32,
}


def build_messages(
    description: str,
    arch: Arch = Arch.X86_64,
) -> list[dict[str, str]]:
    """Build the message list for an LLM completion request.

    Args:
        description: Natural language description of what to build.
        arch: Target architecture.

    Returns:
        List of message dicts ready for LLMProvider.complete().
    """
    system = SYSTEM_PROMPT.format(
        arch_context=ARCH_CONTEXT[arch],
        arch_name=arch.value,
    )
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]

    for example in FEW_SHOT_EXAMPLES.get(arch, []):
        messages.append({"role": "user", "content": example["user"]})
        messages.append({"role": "assistant", "content": example["assistant"]})

    messages.append({"role": "user", "content": description})
    return messages


def build_error_recovery_messages(
    original_messages: list[dict[str, str]],
    assembly: str,
    error: str,
) -> list[dict[str, str]]:
    """Build messages for error recovery after assembly failure.

    Args:
        original_messages: The original message list (including LLM's failed response).
        assembly: The assembly code that failed.
        error: The error message from the assembler.

    Returns:
        Extended message list with error context.
    """
    recovery = ERROR_RECOVERY_PROMPT.format(error=error, assembly=assembly)
    return [*original_messages, {"role": "user", "content": recovery}]


def parse_llm_response(text: str, expected_arch: Arch | None = None) -> AssemblyPlan:
    """Parse an LLM response into an AssemblyPlan.

    Handles:
    - Clean JSON responses
    - JSON wrapped in markdown code fences
    - JSON embedded in surrounding text

    Args:
        text: Raw LLM response text.
        expected_arch: If provided, overrides the arch in the response.

    Returns:
        Parsed AssemblyPlan.

    Raises:
        ValueError: If the response cannot be parsed.
    """
    cleaned = text.strip()

    # Remove markdown code fences if present
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # Try to find a JSON object in the text
    json_match = re.search(r"\{[^{}]*\}", cleaned, re.DOTALL)
    if not json_match:
        raise ValueError(f"No JSON object found in LLM response: {text[:200]}")

    try:
        data = json.loads(json_match.group())
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in LLM response: {e}") from e

    assembly = data.get("assembly", "")
    if not assembly:
        raise ValueError("LLM response missing 'assembly' field")

    description = data.get("description", "No description provided")

    if expected_arch:
        arch = expected_arch
    else:
        arch_str = data.get("arch", "x86_64").lower().replace("-", "_")
        arch = ARCH_NAME_MAP.get(arch_str)
        if arch is None:
            raise ValueError(f"Unknown architecture in LLM response: {data.get('arch')}")

    return AssemblyPlan(arch=arch, assembly=assembly, description=description)
