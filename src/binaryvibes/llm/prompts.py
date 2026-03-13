"""Prompt templates and response parsing for LLM-driven binary synthesis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from binaryvibes.core.arch import Arch, BinaryFormat


@dataclass(frozen=True)
class AssemblyPlan:
    """Parsed LLM response containing an assembly plan."""

    arch: Arch
    assembly: str
    description: str


ARCH_CONTEXT: dict[tuple[Arch, BinaryFormat], str] = {
    # ── Linux ELF ──
    (Arch.X86_64, BinaryFormat.ELF): """Target: x86_64 (64-bit Intel/AMD, Linux)
Registers: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15
Calling convention: System V AMD64 — args in rdi, rsi, rdx, rcx, r8, r9; return in rax
Syscalls: syscall instruction, number in rax, args in rdi, rsi, rdx, r10, r8, r9
Key syscalls: exit=60 (rdi=code), write=1 (rdi=fd, rsi=buf, rdx=len), read=0
Address size: 64-bit, use RIP-relative addressing when possible
Stack: grows downward, 16-byte aligned before call""",

    (Arch.X86_32, BinaryFormat.ELF): """Target: x86_32 (32-bit Intel/AMD, Linux)
Registers: eax, ebx, ecx, edx, esi, edi, ebp, esp
Calling convention: cdecl — args on stack right-to-left; return in eax
Syscalls: int 0x80, number in eax, args in ebx, ecx, edx, esi, edi
Key syscalls: exit=1 (ebx=code), write=4 (ebx=fd, ecx=buf, edx=len), read=3
Address size: 32-bit""",

    (Arch.ARM64, BinaryFormat.ELF): """Target: ARM64 (AArch64, Linux)
Registers: x0-x30, sp, pc, xzr (zero register)
Calling convention: args in x0-x7; return in x0
Syscalls: svc #0, number in x8, args in x0-x5
Key syscalls: exit=93 (x0=code), write=64 (x0=fd, x1=buf, x2=len), read=63
Address size: 64-bit, fixed 4-byte instruction width""",

    (Arch.ARM32, BinaryFormat.ELF): """Target: ARM32 (ARM, Linux)
Registers: r0-r12, sp (r13), lr (r14), pc (r15)
Calling convention: args in r0-r3; return in r0
Syscalls: svc #0, number in r7, args in r0-r5
Key syscalls: exit=1 (r0=code), write=4 (r0=fd, r1=buf, r2=len), read=3
Address size: 32-bit""",

    # ── Windows PE ──
    (Arch.X86_64, BinaryFormat.PE): """Target: x86_64 (64-bit Intel/AMD, Windows)
Registers: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15
Calling convention: Microsoft x64 — args in rcx, rdx, r8, r9; return in rax
Shadow space: MUST reserve 32 bytes (sub rsp, 0x28) before any call
API functions are called via Import Address Table (IAT) at fixed addresses:
  ExitProcess:  load from [0x402000] then call — void ExitProcess(UINT uExitCode)
  GetStdHandle: load from [0x402008] then call — HANDLE GetStdHandle(DWORD nStdHandle)
  WriteFile:    load from [0x402010] then call — BOOL WriteFile(HANDLE, LPCVOID,
                 DWORD, LPDWORD, LPOVERLAPPED)
To call a function: mov rax, qword ptr [IAT_address]; call rax
Constants: STD_OUTPUT_HANDLE = -11 (0xFFFFFFFFFFFFFFF5)
IMPORTANT: Always call ExitProcess to terminate. Never use syscall on Windows.""",

    (Arch.X86_32, BinaryFormat.PE): """Target: x86_32 (32-bit Intel/AMD, Windows)
Registers: eax, ebx, ecx, edx, esi, edi, ebp, esp
Calling convention: stdcall — args pushed right-to-left on stack; callee cleans stack
API functions via IAT: push args right-to-left, then call [IAT_address]
  ExitProcess at [0x402000]: push exit_code; call [0x402000]
  GetStdHandle at [0x402004]: push -11; call [0x402004]
  WriteFile at [0x402008]: push 5 args right-to-left; call [0x402008]
IMPORTANT: Always call ExitProcess to terminate.""",

    # ── macOS Mach-O ──
    (Arch.X86_64, BinaryFormat.MACHO): """Target: x86_64 (64-bit Intel/AMD, macOS)
Registers: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15
Calling convention: System V AMD64 — args in rdi, rsi, rdx, rcx, r8, r9; return in rax
Syscalls: syscall instruction, number in rax = 0x2000000 | unix_number
  args in rdi, rsi, rdx, r10, r8, r9
Key syscalls: exit=0x2000001 (rdi=code), write=0x2000004 (rdi=fd, rsi=buf, rdx=len)
Address size: 64-bit, use RIP-relative addressing when possible
Stack: grows downward, 16-byte aligned before call""",

    (Arch.ARM64, BinaryFormat.MACHO): """Target: ARM64 (AArch64, macOS/Apple Silicon)
Registers: x0-x30, sp, pc, xzr (zero register)
Calling convention: args in x0-x7; return in x0
Syscalls: svc #0x80, number in x16, args in x0-x5
Key syscalls: exit=1 (x0=code), write=4 (x0=fd, x1=buf, x2=len)
Address size: 64-bit, fixed 4-byte instruction width""",
}


OS_INFO: dict[BinaryFormat, dict[str, str]] = {
    BinaryFormat.ELF: {"os_name": "Linux", "format_name": "ELF"},
    BinaryFormat.PE: {"os_name": "Windows", "format_name": "PE"},
    BinaryFormat.MACHO: {"os_name": "macOS", "format_name": "Mach-O"},
}

EXIT_INSTRUCTIONS: dict[tuple[Arch, BinaryFormat], str] = {
    (Arch.X86_64, BinaryFormat.ELF): "call exit syscall (mov rax,60; mov rdi,code; syscall)",
    (Arch.X86_64, BinaryFormat.PE): (
        "call ExitProcess via IAT (mov ecx,code; sub rsp,0x28; mov rax,[0x402000]; "
        "call rax)"
    ),
    (Arch.X86_64, BinaryFormat.MACHO): (
        "call exit syscall (mov rax,0x2000001; mov rdi,code; syscall)"
    ),
    (Arch.X86_32, BinaryFormat.ELF): "call exit via int 0x80 (mov eax,1; mov ebx,code; int 0x80)",
    (Arch.X86_32, BinaryFormat.PE): "call ExitProcess via IAT (push code; call [0x402000])",
    (Arch.ARM64, BinaryFormat.ELF): "call exit syscall (mov x0,code; mov x8,#93; svc #0)",
    (Arch.ARM64, BinaryFormat.MACHO): "call exit syscall (mov x0,code; mov x16,#1; svc #0x80)",
    (Arch.ARM32, BinaryFormat.ELF): "call exit syscall (mov r0,code; mov r7,#1; svc #0)",
}

SYSTEM_PROMPT = """You are an expert assembly language programmer working with the BinaryVibes \
framework. Your job is to write assembly code that will be assembled into a standalone \
{os_name} {format_name} binary.

CRITICAL RULES:
1. Write ONLY pure assembly instructions — no directives, no labels, no comments.
2. The code will be placed at the entry point of a minimal binary. Execution starts at the \
 first instruction.
3. The program MUST terminate properly: {exit_instruction}
4. Use ONLY instructions — no pseudo-ops, no macros, no preprocessor directives.
5. For string data, embed bytes directly using techniques like pushing values onto the stack.
6. Keep it simple and correct. Prefer straightforward implementations.
7. Each instruction goes on its own line.

{arch_context}

RESPONSE FORMAT — you MUST respond with ONLY a JSON object (no markdown fences, no extra text):
{{
  "arch": "{arch_name}",
  "assembly": "instruction1\\ninstruction2\\ninstruction3",
  "description": "Brief description of what the program does"
}}

The "assembly" field contains newline-separated assembly instructions. Nothing else."""


FEW_SHOT_EXAMPLES: dict[tuple[Arch, BinaryFormat], list[dict[str, str]]] = {
    # ── Linux ELF ──
    (Arch.X86_64, BinaryFormat.ELF): [
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
    (Arch.X86_32, BinaryFormat.ELF): [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "x86_32",
                "assembly": "mov eax, 1\nmov ebx, 42\nint 0x80",
                "description": "Exits with status code 42 using int 0x80 syscall",
            }),
        },
    ],
    (Arch.ARM64, BinaryFormat.ELF): [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "arm64",
                "assembly": "mov x0, #42\nmov x8, #93\nsvc #0",
                "description": "Exits with status code 42 using svc syscall",
            }),
        },
    ],
    (Arch.ARM32, BinaryFormat.ELF): [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "arm32",
                "assembly": "mov r0, #42\nmov r7, #1\nsvc #0",
                "description": "Exits with status code 42 using svc syscall",
            }),
        },
    ],

    # ── Windows PE ──
    (Arch.X86_64, BinaryFormat.PE): [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": "mov ecx, 42\nsub rsp, 0x28\nmov rax, qword ptr [0x402000]\ncall rax",
                "description": "Exits with code 42 via ExitProcess",
            }),
        },
    ],

    # ── macOS Mach-O ──
    (Arch.X86_64, BinaryFormat.MACHO): [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": "mov rax, 0x2000001\nmov rdi, 42\nsyscall",
                "description": "Exits with code 42 using macOS exit syscall",
            }),
        },
    ],
    (Arch.ARM64, BinaryFormat.MACHO): [
        {
            "user": "a program that exits with code 42",
            "assistant": json.dumps({
                "arch": "arm64",
                "assembly": "mov x0, #42\nmov x16, #1\nsvc #0x80",
                "description": "Exits with code 42 using macOS exit syscall",
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
    fmt: BinaryFormat = BinaryFormat.ELF,
) -> list[dict[str, str]]:
    """Build the message list for an LLM completion request.

    Args:
        description: Natural language description of what to build.
        arch: Target architecture.
        fmt: Target binary format (ELF, PE, or Mach-O).

    Returns:
        List of message dicts ready for LLMProvider.complete().
    """
    key = (arch, fmt)
    # Fall back to ELF context for unsupported arch+format combinations
    if key not in ARCH_CONTEXT:
        key = (arch, BinaryFormat.ELF)

    os_info = OS_INFO.get(fmt, OS_INFO[BinaryFormat.ELF])
    exit_instruction = EXIT_INSTRUCTIONS.get(
        (arch, fmt),
        EXIT_INSTRUCTIONS.get((arch, BinaryFormat.ELF), "terminate the program"),
    )

    system = SYSTEM_PROMPT.format(
        arch_context=ARCH_CONTEXT[key],
        arch_name=arch.value,
        os_name=os_info["os_name"],
        format_name=os_info["format_name"],
        exit_instruction=exit_instruction,
    )
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]

    examples = FEW_SHOT_EXAMPLES.get((arch, fmt))
    if examples is None:
        examples = FEW_SHOT_EXAMPLES.get((arch, BinaryFormat.ELF), [])
    for example in examples:
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
