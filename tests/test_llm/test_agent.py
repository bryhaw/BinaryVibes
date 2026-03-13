"""Tests for LLM-driven build agent."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from binaryvibes.core.arch import Arch, BinaryFormat
from binaryvibes.llm.agent import BuildAgent, BuildResult, _entry_point
from binaryvibes.llm.provider import LLMError, LLMResponse
from binaryvibes.synthesis.generator import (
    DEFAULT_BASE_ADDR,
    ELF32_EHDR_SIZE,
    ELF32_PHDR_SIZE,
    ELF64_EHDR_SIZE,
    ELF64_PHDR_SIZE,
)


def _mock_provider(responses: list[str]) -> MagicMock:
    """Create a mock LLMProvider returning given responses in sequence."""
    provider = MagicMock()
    provider.complete.side_effect = [
        LLMResponse(content=r, model="test-model") for r in responses
    ]
    return provider


class TestEntryPoint:
    def test_x86_64(self):
        assert (
            _entry_point(Arch.X86_64)
            == DEFAULT_BASE_ADDR + ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        )

    def test_x86_32(self):
        assert (
            _entry_point(Arch.X86_32)
            == DEFAULT_BASE_ADDR + ELF32_EHDR_SIZE + ELF32_PHDR_SIZE
        )

    def test_arm64(self):
        assert (
            _entry_point(Arch.ARM64)
            == DEFAULT_BASE_ADDR + ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        )


class TestBuildAgent:
    def test_build_exit_42_x86_64(self):
        """Full pipeline: LLM returns valid x86_64 assembly → binary built."""
        llm_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nmov rdi, 42\nsyscall",
            "description": "Exits with code 42",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_64, verify=False)
        result = agent.build("a program that exits with code 42")

        assert isinstance(result, BuildResult)
        assert result.arch == Arch.X86_64
        assert result.assembly == "mov rax, 60\nmov rdi, 42\nsyscall"
        assert result.description == "Exits with code 42"
        assert result.binary is not None
        assert len(result.binary.raw) > 0
        assert result.retries_used == 0
        assert result.llm_model == "test-model"

    def test_build_exit_42_x86_32(self):
        """Full pipeline for x86_32 architecture."""
        llm_response = json.dumps({
            "arch": "x86_32",
            "assembly": "mov eax, 1\nmov ebx, 42\nint 0x80",
            "description": "Exits with code 42 (32-bit)",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_32, fmt=BinaryFormat.ELF, verify=False)
        result = agent.build("a program that exits with code 42")

        assert result.arch == Arch.X86_32
        assert result.binary is not None
        assert not result.verified  # x86_32 not supported by emulator

    def test_build_with_verification_x86_64(self):
        """Verify emulation runs and reports results."""
        from binaryvibes.verify.emulator import EmulationResult

        mock_emu_result = EmulationResult(
            instructions_executed=3, error=None
        )
        mock_emulator = MagicMock()
        mock_emulator.run.return_value = mock_emu_result

        llm_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nmov rdi, 42\nsyscall",
            "description": "Exit 42",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_64, verify=True)

        with patch(
            "binaryvibes.llm.agent.Emulator", return_value=mock_emulator
        ):
            result = agent.build("exit 42")

        assert result.emulation_result is not None
        assert result.emulation_result.instructions_executed > 0

    def test_build_no_verification(self):
        """Verify emulation is skipped when verify=False."""
        llm_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nmov rdi, 0\nsyscall",
            "description": "Exit 0",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_64, verify=False)
        result = agent.build("exit 0")

        assert not result.verified
        assert result.emulation_result is None

    def test_retry_on_parse_failure(self):
        """Agent retries when LLM returns unparseable response."""
        bad_response = "I don't understand, here's some text without JSON"
        good_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nxor rdi, rdi\nsyscall",
            "description": "Exit 0",
        })
        provider = _mock_provider([bad_response, good_response])
        agent = BuildAgent(
            provider, arch=Arch.X86_64, max_retries=3, verify=False
        )
        result = agent.build("exit 0")

        assert result.retries_used == 1
        assert result.assembly == "mov rax, 60\nxor rdi, rdi\nsyscall"

    def test_retry_on_assembly_failure(self):
        """Agent retries when assembly fails."""
        bad_asm = json.dumps({
            "arch": "x86_64",
            "assembly": "completely_invalid_instruction",
            "description": "Bad asm",
        })
        good_asm = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nxor rdi, rdi\nsyscall",
            "description": "Exit 0",
        })
        provider = _mock_provider([bad_asm, good_asm])
        agent = BuildAgent(
            provider, arch=Arch.X86_64, max_retries=3, verify=False
        )
        result = agent.build("exit 0")

        assert result.retries_used == 1

    def test_all_retries_exhausted(self):
        """Agent raises LLMError when all retries fail."""
        bad_response = "no json here"
        provider = _mock_provider([bad_response] * 4)  # 1 + 3 retries
        agent = BuildAgent(
            provider, arch=Arch.X86_64, max_retries=3, verify=False
        )

        with pytest.raises(LLMError, match="Failed to produce valid assembly"):
            agent.build("something impossible")

    def test_zero_retries(self):
        """Agent with max_retries=0 fails immediately on bad response."""
        bad_response = "invalid"
        provider = _mock_provider([bad_response])
        agent = BuildAgent(
            provider, arch=Arch.X86_64, max_retries=0, verify=False
        )

        with pytest.raises(LLMError):
            agent.build("test")

    def test_binary_is_valid_elf(self):
        """Generated binary starts with ELF magic."""
        llm_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nxor rdi, rdi\nsyscall",
            "description": "Exit 0",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_64, fmt=BinaryFormat.ELF, verify=False)
        result = agent.build("exit 0")

        assert result.binary.raw[:4] == b"\x7fELF"


class TestBuildResult:
    def test_frozen(self):
        """BuildResult is immutable."""
        from binaryvibes.synthesis.generator import BinaryBuilder

        binary = (
            BinaryBuilder().set_arch(Arch.X86_64).add_code(b"\xc3").build()
        )
        result = BuildResult(
            binary=binary,
            assembly="ret",
            arch=Arch.X86_64,
            fmt=BinaryFormat.ELF,
            description="return",
            verified=False,
        )
        with pytest.raises(AttributeError):
            result.verified = True


class TestBuildAgentWithFormat:
    def test_build_pe_format(self):
        """Build with PE format produces valid PE."""
        llm_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov ecx, 42\nsub rsp, 0x28\nmov rax, qword ptr [0x402000]\ncall rax",
            "description": "Exits with code 42 via ExitProcess",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_64, fmt=BinaryFormat.PE, verify=False)
        result = agent.build("exit 42")
        assert result.binary.raw[:2] == b"MZ"
        assert result.fmt == BinaryFormat.PE

    def test_build_macho_format(self):
        """Build with Mach-O format produces valid Mach-O."""
        llm_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 0x2000001\nmov rdi, 42\nsyscall",
            "description": "Exits with code 42 (macOS)",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_64, fmt=BinaryFormat.MACHO, verify=False)
        result = agent.build("exit 42")
        import struct
        magic = struct.unpack("<I", result.binary.raw[:4])[0]
        assert magic == 0xFEEDFACF
        assert result.fmt == BinaryFormat.MACHO

    def test_build_result_has_format(self):
        """BuildResult includes format field."""
        llm_response = json.dumps({
            "arch": "x86_64",
            "assembly": "mov rax, 60\nmov rdi, 0\nsyscall",
            "description": "exit",
        })
        provider = _mock_provider([llm_response])
        agent = BuildAgent(provider, arch=Arch.X86_64, fmt=BinaryFormat.ELF, verify=False)
        result = agent.build("exit 0")
        assert result.fmt == BinaryFormat.ELF
