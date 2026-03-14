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
    (Arch.X86_64, BinaryFormat.PE): """Target: x86_64 (64-bit, Windows PE)

CALLING CONVENTION (Microsoft x64):
  Args: rcx, rdx, r8, r9 (then stack). Return in rax.
  Shadow space: ALWAYS sub rsp, 0x28 before calls (32 bytes shadow + 8 align).
  Callee-saved: rbx, rbp, rdi, rsi, r12-r15. Caller-saved: rax, rcx, rdx, r8-r11.

API CALL PATTERN — load function pointer from IAT, then call:
  mov eax, IAT_ADDR    ; load IAT address into rax (32-bit mov zero-extends)
  mov rax, [rax]       ; dereference: load actual function pointer
  call rax             ; call the function

AVAILABLE WINDOWS API FUNCTIONS (kernel32.dll):
  ExitProcess(uExitCode)                          IAT: 0x402000
  GetStdHandle(nStdHandle) -> HANDLE               IAT: 0x402008
  WriteFile(hFile, lpBuf, nBytes, lpWritten, lpOv) IAT: 0x402010
  ReadFile(hFile, lpBuf, nBytes, lpRead, lpOv)     IAT: 0x402018
  CreateFileA(name, access, share, sa, disp, flags, tmpl) IAT: 0x402020
  CloseHandle(hObject)                             IAT: 0x402028
  GetFileSize(hFile, lpHigh) -> DWORD              IAT: 0x402030
  GetComputerNameA(lpBuf, lpnSize)                 IAT: 0x402038
  GetLocalTime(lpSystemTime)                       IAT: 0x402040
  GlobalMemoryStatusEx(lpBuffer)                   IAT: 0x402048
  GetCurrentProcessId() -> DWORD                   IAT: 0x402050
  GetCommandLineA() -> LPSTR                       IAT: 0x402058
  Sleep(dwMilliseconds)                            IAT: 0x402060
  GetProcessHeap() -> HANDLE                       IAT: 0x402068
  HeapAlloc(hHeap, dwFlags, dwBytes) -> LPVOID     IAT: 0x402070
  HeapFree(hHeap, dwFlags, lpMem) -> BOOL          IAT: 0x402078
  FindFirstFileA(lpFileName, lpFindData) -> HANDLE IAT: 0x402080
  FindNextFileA(hFind, lpFindData) -> BOOL         IAT: 0x402088
  FindClose(hFind) -> BOOL                         IAT: 0x402090
  SetConsoleTitleA(lpTitle) -> BOOL                IAT: 0x402098
  GetLastError() -> DWORD                          IAT: 0x4020A0
  lstrlenA(lpString) -> int                        IAT: 0x4020A8
  GetEnvironmentVariableA(name, buf, size) -> DWORD IAT: 0x4020B0
  GetTickCount64() -> ULONGLONG                    IAT: 0x4020B8
  GetCurrentDirectoryA(nBufLen, lpBuf) -> DWORD    IAT: 0x4020C0
  GetTempPathA(nBufLen, lpBuf) -> DWORD            IAT: 0x4020C8
  DeleteFileA(lpFileName) -> BOOL                  IAT: 0x4020D0
  CopyFileA(src, dst, failIfExists) -> BOOL        IAT: 0x4020D8
  CreateDirectoryA(pathName, secAttrs) -> BOOL      IAT: 0x4020E0

  --- user32.dll ---
  MessageBoxA(hWnd, text, caption, type) -> int  IAT: 0x4020F0
    Types: MB_OK=0, MB_OKCANCEL=1, MB_YESNO=4

  --- wininet.dll ---
  InternetOpenA(agent, accessType, proxy, bypass, flags) IAT: 0x402100
  InternetOpenUrlA(hInternet, url, headers, hdrLen, flags, ctx) IAT: 0x402108
  InternetReadFile(hFile, buf, bytesToRead, bytesRead) IAT: 0x402110
  InternetCloseHandle(hInternet) IAT: 0x402118

CONSTANTS:
  STD_INPUT_HANDLE  = -10 (0xFFFFFFFFFFFFFFF6)
  STD_OUTPUT_HANDLE = -11 (0xFFFFFFFFFFFFFFF5)
  GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000
  OPEN_EXISTING = 3, CREATE_ALWAYS = 2
  HEAP_ZERO_MEMORY = 0x08

PRE-DEFINED UTILITY FUNCTIONS — automatically available, just call them:
  __bv_print_str(rcx=pointer)     — print null-terminated string to stdout
  __bv_print_newline()            — print CR+LF
  __bv_print_num(rcx=value)       — print unsigned 64-bit decimal number
  __bv_get_stdout() -> rax        — get stdout handle
  __bv_write(rcx=buf, rdx=len)   — write bytes to stdout
  __bv_sleep(rcx=milliseconds)    — sleep, preserves all callee-saved regs
  __bv_open_file_read(rcx=filename_ptr) -> rax  — open file (returns -1 on failure)
  __bv_read_file(rcx=handle, rdx=buffer, r8=max_bytes) -> rax=bytes_read
  __bv_close_handle(rcx=handle)   — close file/handle
  __bv_msgbox(rcx=text, rdx=title)  — show a MessageBox (MB_OK)
  __bv_http_get(rcx=url, rdx=buffer, r8=max_size) -> rax=bytes_read
    Fetches URL via HTTP GET into buffer, null-terminates, returns bytes read (0=fail)
  __bv_get_computer_name(rcx=buffer) -> rax=1 success, 0 fail
    Fills buffer with computer name (buffer must be >=256 bytes)
  __bv_get_pid() -> rax=process_id
    Returns current process ID
  __bv_html_dashboard(rcx=body_text, rdx=filename_ptr)
    Wraps body text in a styled HTML page, writes to file, opens in browser.
    Use for any output that benefits from rich formatting.
    Example: fetch data, then call __bv_html_dashboard to display it beautifully.

  IMPORTANT: These helpers save and restore registers properly.
  Use callee-saved registers (rbx, r12-r15) for values that must survive across calls.

PROGRAM STRUCTURE:
1. Start with: sub rsp, 0x28 (align stack + shadow space for main)
2. Write your program logic — call helpers as needed
3. Put string data AFTER all code using: label: .asciz "text"
4. End with: xor ecx, ecx / mov eax, 0x402000 / mov rax, [rax] / call rax
5. Do NOT define any __bv_ functions — they are pre-defined""",

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
1. Labels, .asciz (null-terminated strings), and .byte directives ARE allowed and encouraged.
2. The code will be placed at the entry point of a minimal binary. Execution starts at the \
 first instruction.
3. The program MUST terminate properly: {exit_instruction}
4. No macros or preprocessor directives. Assembly instructions, labels, .asciz, and .byte are fine.
5. For string data, use labeled .asciz directives (e.g., msg: .asciz "Hello") placed AFTER all code.
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
                "assembly": (
                    "sub rsp, 0x28\nmov ecx, 42\n"
                    "mov eax, 0x402000\nmov rax, [rax]\ncall rax"
                ),
                "description": "Exits with code 42 via ExitProcess",
            }),
        },
        {
            "user": "a program that prints Hello World to the console",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": (
                    "sub rsp, 0x28\n"
                    "lea rcx, [rip+msg]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "xor ecx, ecx\n"
                    "mov eax, 0x402000\n"
                    "mov rax, [rax]\n"
                    "call rax\n"
                    'msg: .asciz "Hello, World!"'
                ),
                "description": "Prints Hello World using pre-defined helpers, then exits",
            }),
        },
        {
            "user": "print the value of the USERNAME environment variable",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": (
                    "sub rsp, 0x128\n"
                    "lea rcx, [rip+env_name]\n"
                    "lea rdx, [rsp+0x20]\n"
                    "mov r8, 256\n"
                    "mov eax, 0x4020B0\n"
                    "mov rax, [rax]\n"
                    "call rax\n"
                    "test eax, eax\n"
                    "jz done\n"
                    "lea rcx, [rsp+0x20]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "done:\n"
                    "xor ecx, ecx\n"
                    "mov eax, 0x402000\n"
                    "mov rax, [rax]\n"
                    "call rax\n"
                    'env_name: .asciz "USERNAME"'
                ),
                "description": "Reads USERNAME env var into stack buffer and prints it",
            }),
        },
        {
            "user": "read and print the contents of a file called data.txt",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": (
                    "sub rsp, 0x128\n"
                    "lea rcx, [rip+fname]\n"
                    "call __bv_open_file_read\n"
                    "cmp rax, -1\n"
                    "je fail\n"
                    "mov rbx, rax\n"
                    "mov rcx, rbx\n"
                    "lea rdx, [rsp+0x20]\n"
                    "mov r8, 256\n"
                    "call __bv_read_file\n"
                    "mov byte ptr [rsp+rax+0x20], 0\n"
                    "lea rcx, [rsp+0x20]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "mov rcx, rbx\n"
                    "call __bv_close_handle\n"
                    "xor ecx, ecx\n"
                    "jmp exit\n"
                    "fail:\n"
                    "lea rcx, [rip+errmsg]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "mov ecx, 1\n"
                    "exit:\n"
                    "mov eax, 0x402000\n"
                    "mov rax, [rax]\n"
                    "call rax\n"
                    'fname: .asciz "data.txt"\n'
                    'errmsg: .asciz "Error: could not open file"'
                ),
                "description": "Opens data.txt, reads 256 bytes, prints contents, handles errors",
            }),
        },
        {
            "user": "pop up a message box that says Hello",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": (
                    "sub rsp, 0x28\n"
                    "lea rcx, [rip+msg]\n"
                    "lea rdx, [rip+title]\n"
                    "call __bv_msgbox\n"
                    "xor ecx, ecx\n"
                    "mov eax, 0x402000\n"
                    "mov rax, [rax]\n"
                    "call rax\n"
                    'msg: .asciz "Hello from BinaryVibes!"\n'
                    'title: .asciz "Greeting"'
                ),
                "description": "Shows a MessageBox with Hello greeting, then exits",
            }),
        },
        {
            "user": "fetch http://example.com and print the response",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": (
                    "sub rsp, 0x228\n"
                    "lea rcx, [rip+url]\n"
                    "lea rdx, [rsp+0x20]\n"
                    "mov r8, 512\n"
                    "call __bv_http_get\n"
                    "test rax, rax\n"
                    "jz fail\n"
                    "lea rcx, [rsp+0x20]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "xor ecx, ecx\n"
                    "jmp done\n"
                    "fail:\n"
                    "lea rcx, [rip+errmsg]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "mov ecx, 1\n"
                    "done:\n"
                    "mov eax, 0x402000\n"
                    "mov rax, [rax]\n"
                    "call rax\n"
                    'url: .asciz "http://example.com"\n'
                    'errmsg: .asciz "Error: HTTP request failed"'
                ),
                "description": "Fetches example.com via HTTP and prints the response",
            }),
        },
        {
            "user": "fetch weather for Seattle and display it as an HTML dashboard",
            "assistant": json.dumps({
                "arch": "x86_64",
                "assembly": (
                    "sub rsp, 0x2028\n"
                    "lea rcx, [rip+url]\n"
                    "lea rdx, [rsp+0x20]\n"
                    "mov r8, 8000\n"
                    "call __bv_http_get\n"
                    "test rax, rax\n"
                    "jz fail\n"
                    "lea rcx, [rsp+0x20]\n"
                    "lea rdx, [rip+fname]\n"
                    "call __bv_html_dashboard\n"
                    "lea rcx, [rip+donemsg]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "xor ecx, ecx\n"
                    "jmp exit\n"
                    "fail:\n"
                    "lea rcx, [rip+errmsg]\n"
                    "call __bv_print_str\n"
                    "call __bv_print_newline\n"
                    "mov ecx, 1\n"
                    "exit:\n"
                    "mov eax, 0x402000\n"
                    "mov rax, [rax]\n"
                    "call rax\n"
                    'url: .asciz "http://wttr.in/Seattle?format=4"\n'
                    'fname: .asciz "weather.html"\n'
                    'donemsg: .asciz "Dashboard opened in browser!"\n'
                    'errmsg: .asciz "Error: could not fetch weather"'
                ),
                "description": "Fetches Seattle weather and displays as styled HTML dashboard",
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
- Labels and .asciz/.byte directives are allowed
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
        raise ValueError(
            f"No JSON object found in LLM response (first 100 chars): {text[:100]!r}"
        )

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
