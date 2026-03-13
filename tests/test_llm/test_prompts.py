"""Tests for LLM prompt system."""

from __future__ import annotations

import json

import pytest

from binaryvibes.core.arch import Arch, BinaryFormat
from binaryvibes.llm.prompts import (
    ARCH_CONTEXT,
    AssemblyPlan,
    build_error_recovery_messages,
    build_messages,
    parse_llm_response,
)


class TestAssemblyPlan:
    def test_frozen(self):
        plan = AssemblyPlan(arch=Arch.X86_64, assembly="nop", description="test")
        with pytest.raises(AttributeError):
            plan.arch = Arch.ARM64

    def test_fields(self):
        plan = AssemblyPlan(
            arch=Arch.ARM64, assembly="mov x0, #0", description="zero x0"
        )
        assert plan.arch == Arch.ARM64
        assert plan.assembly == "mov x0, #0"
        assert plan.description == "zero x0"


class TestBuildMessages:
    def test_default_x86_64(self):
        msgs = build_messages("exit with code 42")
        assert msgs[0]["role"] == "system"
        assert "x86_64" in msgs[0]["content"]
        assert msgs[-1]["role"] == "user"
        assert msgs[-1]["content"] == "exit with code 42"

    def test_includes_few_shot(self):
        msgs = build_messages("test", arch=Arch.X86_64)
        # System + at least 2 few-shot pairs + user
        assert len(msgs) >= 5
        roles = [m["role"] for m in msgs]
        assert roles[0] == "system"
        assert roles[-1] == "user"

    def test_arm64_context(self):
        msgs = build_messages("test", arch=Arch.ARM64)
        assert "ARM64" in msgs[0]["content"] or "AArch64" in msgs[0]["content"]

    def test_all_architectures_have_context(self):
        for arch in Arch:
            assert (arch, BinaryFormat.ELF) in ARCH_CONTEXT

    def test_pe_prompt_contains_windows(self):
        msgs = build_messages("exit 42", Arch.X86_64, BinaryFormat.PE)
        assert "Windows" in msgs[0]["content"]
        assert "ExitProcess" in msgs[0]["content"]

    def test_macho_prompt_contains_macos(self):
        msgs = build_messages("exit 42", Arch.X86_64, BinaryFormat.MACHO)
        assert "macOS" in msgs[0]["content"]
        assert "0x2000001" in msgs[0]["content"]

    def test_elf_backward_compat(self):
        msgs = build_messages("exit 42")
        assert "Linux" in msgs[0]["content"]

    def test_unsupported_combo_falls_back_to_elf(self):
        msgs = build_messages("exit 42", Arch.ARM32, BinaryFormat.PE)
        assert "ARM32" in msgs[0]["content"] or "ARM" in msgs[0]["content"]


class TestBuildErrorRecoveryMessages:
    def test_appends_error_context(self):
        original = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "build something"},
            {"role": "assistant", "content": '{"assembly": "bad instruction"}'},
        ]
        result = build_error_recovery_messages(
            original, "bad instruction", "unknown mnemonic"
        )
        assert len(result) == 4
        assert result[-1]["role"] == "user"
        assert "unknown mnemonic" in result[-1]["content"]
        assert "bad instruction" in result[-1]["content"]


class TestParseLLMResponse:
    def test_clean_json(self):
        response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nmov rdi, 0\nsyscall",
            "description": "exit cleanly",
        })
        plan = parse_llm_response(response)
        assert plan.arch == Arch.X86_64
        assert "mov rax, 60" in plan.assembly
        assert plan.description == "exit cleanly"

    def test_json_in_markdown_fences(self):
        response = (
            '```json\n{"arch": "arm64", "assembly": '
            '"mov x0, #42\\nmov x8, #93\\nsvc #0", '
            '"description": "exit 42"}\n```'
        )
        plan = parse_llm_response(response)
        assert plan.arch == Arch.ARM64
        assert "mov x0, #42" in plan.assembly

    def test_json_with_surrounding_text(self):
        response = (
            'Here is the code:\n'
            '{"arch": "x86_64", "assembly": "nop", "description": "nop"}\n'
            'Hope this helps!'
        )
        plan = parse_llm_response(response)
        assert plan.arch == Arch.X86_64

    def test_expected_arch_override(self):
        response = json.dumps({
            "arch": "arm64",
            "assembly": "mov rax, 60\nsyscall",
            "description": "test",
        })
        plan = parse_llm_response(response, expected_arch=Arch.X86_64)
        assert plan.arch == Arch.X86_64

    def test_no_json_raises(self):
        with pytest.raises(ValueError, match="No JSON"):
            parse_llm_response("This is just plain text with no JSON")

    def test_missing_assembly_raises(self):
        response = json.dumps({"arch": "x86_64", "description": "test"})
        with pytest.raises(ValueError, match="missing 'assembly'"):
            parse_llm_response(response)

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="No JSON"):
            parse_llm_response("not json at all {{{")

    def test_unknown_arch_raises(self):
        response = json.dumps({
            "arch": "mips64",
            "assembly": "nop",
            "description": "test",
        })
        with pytest.raises(ValueError, match="Unknown architecture"):
            parse_llm_response(response)

    def test_arch_aliases(self):
        for alias, expected in [("aarch64", Arch.ARM64), ("arm", Arch.ARM32)]:
            response = json.dumps({
                "arch": alias,
                "assembly": "nop",
                "description": "test",
            })
            plan = parse_llm_response(response)
            assert plan.arch == expected

    def test_default_description(self):
        response = json.dumps({"arch": "x86_64", "assembly": "nop"})
        plan = parse_llm_response(response)
        assert plan.description == "No description provided"
