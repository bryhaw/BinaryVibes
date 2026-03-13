"""Pre-baked runtime helpers for Windows PE binaries.

These assembly routines are automatically appended to LLM-generated code
so the LLM can call them without having to define them.

IAT address reference (ImageBase 0x400000 + .idata RVA 0x2000):
  ExitProcess      0x402000    GetStdHandle     0x402008
  WriteFile        0x402010    ReadFile         0x402018
  CreateFileA      0x402020    CloseHandle      0x402028
  Sleep            0x402060    lstrlenA         0x4020A8
  MessageBoxA      0x4020F0
  InternetOpenA    0x402100    InternetOpenUrlA 0x402108
  InternetReadFile 0x402110    InternetCloseHandle 0x402118
"""

from __future__ import annotations

# Runtime helper assembly - appended after the LLM's code.
# The LLM's code MUST call ExitProcess before execution reaches these.
# Uses __bv_ prefix to avoid label conflicts with LLM-generated code.

PE_RUNTIME_ASM = """
__bv_print_str:
  push rbx
  push rsi
  sub rsp, 0x38
  mov rsi, rcx
  mov eax, 0x4020A8
  mov rax, [rax]
  call rax
  mov rbx, rax
  mov ecx, -11
  mov eax, 0x402008
  mov rax, [rax]
  call rax
  mov rcx, rax
  mov rdx, rsi
  mov r8, rbx
  lea r9, [rsp+0x30]
  mov qword ptr [rsp+0x20], 0
  mov eax, 0x402010
  mov rax, [rax]
  call rax
  add rsp, 0x38
  pop rsi
  pop rbx
  ret

__bv_print_newline:
  sub rsp, 0x38
  mov word ptr [rsp+0x30], 0x0A0D
  mov ecx, -11
  mov eax, 0x402008
  mov rax, [rax]
  call rax
  mov rcx, rax
  lea rdx, [rsp+0x30]
  mov r8, 2
  lea r9, [rsp+0x28]
  mov qword ptr [rsp+0x20], 0
  mov eax, 0x402010
  mov rax, [rax]
  call rax
  add rsp, 0x38
  ret

__bv_print_num:
  push rbx
  push rsi
  push rdi
  sub rsp, 0x40
  mov rbx, rcx
  lea rdi, [rsp+0x30]
  add rdi, 20
  mov byte ptr [rdi], 0
  test rbx, rbx
  jnz __bv_pn_loop
  dec rdi
  mov byte ptr [rdi], 0x30
  jmp __bv_pn_done
__bv_pn_loop:
  test rbx, rbx
  jz __bv_pn_done
  xor edx, edx
  mov rax, rbx
  mov rcx, 10
  div rcx
  add dl, 0x30
  dec rdi
  mov byte ptr [rdi], dl
  mov rbx, rax
  jmp __bv_pn_loop
__bv_pn_done:
  mov rcx, rdi
  call __bv_print_str
  add rsp, 0x40
  pop rdi
  pop rsi
  pop rbx
  ret

__bv_get_stdout:
  sub rsp, 0x28
  mov ecx, -11
  mov eax, 0x402008
  mov rax, [rax]
  call rax
  add rsp, 0x28
  ret

__bv_write:
  push rbx
  push rsi
  sub rsp, 0x48
  mov rsi, rcx
  mov rbx, rdx
  mov ecx, -11
  mov eax, 0x402008
  mov rax, [rax]
  call rax
  mov rcx, rax
  mov rdx, rsi
  mov r8, rbx
  lea r9, [rsp+0x40]
  mov qword ptr [rsp+0x20], 0
  mov eax, 0x402010
  mov rax, [rax]
  call rax
  add rsp, 0x48
  pop rsi
  pop rbx
  ret

__bv_sleep:
  push rbx
  sub rsp, 0x20
  mov eax, 0x402060
  mov rax, [rax]
  call rax
  add rsp, 0x20
  pop rbx
  ret

__bv_open_file_read:
  push rbx
  sub rsp, 0x40
  mov r9, 0
  mov qword ptr [rsp+0x20], 3
  mov qword ptr [rsp+0x28], 0x80
  mov qword ptr [rsp+0x30], 0
  mov rdx, 0x80000000
  mov r8, 1
  mov eax, 0x402020
  mov rax, [rax]
  call rax
  add rsp, 0x40
  pop rbx
  ret

__bv_read_file:
  push rbx
  push rsi
  sub rsp, 0x48
  mov rbx, rcx
  mov rsi, rdx
  lea r9, [rsp+0x40]
  mov qword ptr [rsp+0x20], 0
  mov rcx, rbx
  mov rdx, rsi
  mov eax, 0x402018
  mov rax, [rax]
  call rax
  mov eax, dword ptr [rsp+0x40]
  add rsp, 0x48
  pop rsi
  pop rbx
  ret

__bv_close_handle:
  sub rsp, 0x28
  mov eax, 0x402028
  mov rax, [rax]
  call rax
  add rsp, 0x28
  ret

__bv_msgbox:
  sub rsp, 0x28
  mov r8, rdx
  mov rdx, rcx
  xor ecx, ecx
  xor r9d, r9d
  mov eax, 0x4020F0
  mov rax, [rax]
  call rax
  add rsp, 0x28
  ret

__bv_http_get:
  push rbx
  push rsi
  push rdi
  push r12
  push r13
  sub rsp, 0x58
  mov r12, rcx
  mov r13, rdx
  mov rbx, r8

  lea rcx, [rip+__bv_ua]
  xor edx, edx
  xor r8d, r8d
  xor r9d, r9d
  mov qword ptr [rsp+0x20], 0
  mov eax, 0x402100
  mov rax, [rax]
  call rax
  test rax, rax
  jz __bv_hg_fail
  mov rsi, rax

  mov rcx, rsi
  mov rdx, r12
  xor r8d, r8d
  xor r9d, r9d
  mov qword ptr [rsp+0x20], 0
  mov qword ptr [rsp+0x28], 0
  mov eax, 0x402108
  mov rax, [rax]
  call rax
  test rax, rax
  jz __bv_hg_close_inet
  mov rdi, rax

  xor r12d, r12d
__bv_hg_read_loop:
  mov rcx, rdi
  lea rdx, [r13+r12]
  mov r8, rbx
  sub r8, r12
  jbe __bv_hg_read_done
  lea r9, [rsp+0x50]
  mov eax, 0x402110
  mov rax, [rax]
  call rax
  test eax, eax
  jz __bv_hg_read_done
  mov eax, dword ptr [rsp+0x50]
  test eax, eax
  jz __bv_hg_read_done
  add r12, rax
  jmp __bv_hg_read_loop

__bv_hg_read_done:
  mov byte ptr [r13+r12], 0
  mov rcx, rdi
  mov eax, 0x402118
  mov rax, [rax]
  call rax

__bv_hg_close_inet:
  mov rcx, rsi
  mov eax, 0x402118
  mov rax, [rax]
  call rax
  mov rax, r12
  jmp __bv_hg_ret

__bv_hg_fail:
  xor eax, eax

__bv_hg_ret:
  add rsp, 0x58
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbx
  ret

__bv_ua: .asciz "BinaryVibes/1.0"
"""
