"""LLM-driven binary synthesis agent."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from binaryvibes.core.arch import Arch, BinaryFormat, detect_native_format
from binaryvibes.core.binary import BinaryFile
from binaryvibes.llm.prompts import (
    AssemblyPlan,
    build_error_recovery_messages,
    build_messages,
    parse_llm_response,
)
from binaryvibes.llm.provider import LLMError, LLMProvider
from binaryvibes.synthesis.assembler import Assembler
from binaryvibes.synthesis.generator import (
    DEFAULT_BASE_ADDR,
    ELF32_EHDR_SIZE,
    ELF32_PHDR_SIZE,
    ELF64_EHDR_SIZE,
    ELF64_PHDR_SIZE,
    BinaryBuilder,
)
from binaryvibes.verify.emulator import EmulationResult, Emulator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BuildResult:
    """Result of an LLM-driven binary build."""

    binary: BinaryFile
    assembly: str
    arch: Arch
    fmt: BinaryFormat
    description: str
    verified: bool
    emulation_result: EmulationResult | None = None
    llm_model: str = ""
    retries_used: int = 0


def _entry_point(arch: Arch, fmt: BinaryFormat = BinaryFormat.ELF) -> int:
    """Compute entry point address for the given architecture and format."""
    if fmt == BinaryFormat.PE:
        from binaryvibes.synthesis.pe import PE_CODE_RVA, PE_IMAGE_BASE

        return PE_IMAGE_BASE + PE_CODE_RVA
    elif fmt == BinaryFormat.MACHO:
        from binaryvibes.synthesis.macho import MACHO_CODE_VA

        return MACHO_CODE_VA.get(arch, 0x100001000)
    else:  # ELF
        if arch in (Arch.X86_64, Arch.ARM64):
            return DEFAULT_BASE_ADDR + ELF64_EHDR_SIZE + ELF64_PHDR_SIZE
        elif arch == Arch.X86_32:
            return DEFAULT_BASE_ADDR + ELF32_EHDR_SIZE + ELF32_PHDR_SIZE
        return DEFAULT_BASE_ADDR


class BuildAgent:
    """Orchestrates LLM → Assembly → Binary → Verify pipeline.

    Example::

        from binaryvibes.llm.provider import create_provider
        provider = create_provider()
        agent = BuildAgent(provider)
        result = agent.build("a program that exits with code 42")
        result.binary.write("output.bin")
    """

    def __init__(
        self,
        provider: LLMProvider,
        arch: Arch = Arch.X86_64,
        fmt: BinaryFormat | None = None,
        max_retries: int = 3,
        verify: bool = True,
    ):
        self.provider = provider
        self.arch = arch
        self.fmt = fmt or detect_native_format()
        self.max_retries = max_retries
        self.verify = verify

    def build(self, description: str) -> BuildResult:
        """Build a binary from a natural language description.

        Args:
            description: What the program should do (e.g. "exits with code 42").

        Returns:
            BuildResult with the generated binary and metadata.

        Raises:
            LLMError: If the LLM fails to produce valid assembly after retries.
        """
        messages = build_messages(description, self.arch, self.fmt)
        plan: AssemblyPlan | None = None
        last_error = ""
        retries_used = 0
        llm_model = ""

        for attempt in range(1 + self.max_retries):
            # Get assembly from LLM
            logger.info("LLM attempt %d for: %s", attempt + 1, description)
            response = self.provider.complete(messages)
            llm_model = response.model

            # Parse the response
            try:
                plan = parse_llm_response(response.content, expected_arch=self.arch)
            except ValueError as e:
                last_error = str(e)
                logger.warning("Failed to parse LLM response (attempt %d): %s", attempt + 1, e)
                messages = [
                    *messages,
                    {"role": "assistant", "content": response.content},
                    {
                        "role": "user",
                        "content": (
                            f"Your response was not valid JSON: {e}. "
                            "Please respond with ONLY the JSON object."
                        ),
                    },
                ]
                retries_used += 1
                continue

            # Append PE runtime helpers if targeting Windows PE
            assembly = plan.assembly
            if self.fmt == BinaryFormat.PE:
                from binaryvibes.llm.pe_runtime import PE_RUNTIME_ASM

                assembly = assembly + "\n" + PE_RUNTIME_ASM

            # Try to assemble
            try:
                entry = _entry_point(plan.arch, self.fmt)
                assembler = Assembler(plan.arch)
                code = assembler.assemble(assembly, base_addr=entry)
            except Exception as e:
                last_error = str(e)
                logger.warning("Assembly failed (attempt %d): %s", attempt + 1, e)
                messages = [*messages, {"role": "assistant", "content": response.content}]
                messages = build_error_recovery_messages(messages, plan.assembly, str(e))
                retries_used += 1
                continue

            # Build the binary
            builder = BinaryBuilder()
            binary = builder.set_arch(plan.arch).set_format(self.fmt).add_code(code).build()

            # Optionally verify via emulation
            emulation_result = None
            verified = False
            if self.verify and plan.arch in (Arch.X86_64, Arch.ARM64):
                try:
                    emulator = Emulator(plan.arch)
                    emulation_result = emulator.run(code, base=entry)
                    verified = emulation_result.error is None
                    if not verified:
                        logger.warning("Emulation error: %s", emulation_result.error)
                except Exception as e:
                    logger.warning("Emulation setup failed: %s", e)

            return BuildResult(
                binary=binary,
                assembly=plan.assembly,
                arch=plan.arch,
                fmt=self.fmt,
                description=plan.description,
                verified=verified,
                emulation_result=emulation_result,
                llm_model=llm_model,
                retries_used=retries_used,
            )

        # All retries exhausted
        raise LLMError(
            f"Failed to produce valid assembly after {self.max_retries + 1} attempts. "
            f"Last error: {last_error}"
        )
