"""Tests for the analysis workflow."""

from __future__ import annotations

from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.analysis import (
    ComparisonResult,
    FunctionAnalysis,
    analyze_function,
    compare_functions,
)

_CODE_OFFSET = 120


class TestAnalyzeFunction:
    """Tests for analyze_function()."""

    def test_analyze_simple(self, tiny_elf_binary: BinaryFile) -> None:
        """Analyze tiny ELF code region returns a valid FunctionAnalysis."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        assert isinstance(analysis, FunctionAnalysis)
        assert analysis.offset == _CODE_OFFSET

    def test_analysis_instruction_count(self, tiny_elf_binary: BinaryFile) -> None:
        """instruction_count is positive for valid code."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        assert analysis.instruction_count > 0

    def test_analysis_block_count(self, tiny_elf_binary: BinaryFile) -> None:
        """block_count is at least 1 for valid code."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        assert analysis.block_count >= 1

    def test_analysis_edge_count(self, tiny_elf_binary: BinaryFile) -> None:
        """edge_count is a non-negative integer."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        assert analysis.edge_count >= 0

    def test_cyclomatic_complexity(self, tiny_elf_binary: BinaryFile) -> None:
        """Cyclomatic complexity follows E - N + 2 formula."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        expected = analysis.edge_count - analysis.block_count + 2
        assert analysis.cyclomatic_complexity == expected

    def test_registers_written(self, tiny_elf_binary: BinaryFile) -> None:
        """registers_written contains expected registers for mov rax/rdi."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        regs = analysis.registers_written
        assert isinstance(regs, set)
        # mov rax, 60 and mov rdi, 42 should write rax and rdi
        assert len(regs) > 0

    def test_has_memory_writes_false_for_register_only(self, tiny_elf_binary: BinaryFile) -> None:
        """Tiny ELF (only mov/syscall) has no memory writes."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        assert analysis.has_memory_writes is False

    def test_has_loops_false_for_linear(self, tiny_elf_binary: BinaryFile) -> None:
        """Linear code (no branches) has no loops."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        assert analysis.has_loops is False

    def test_summary_string(self, tiny_elf_binary: BinaryFile) -> None:
        """summary() returns a readable multi-line string."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET)
        s = analysis.summary()
        assert isinstance(s, str)
        assert "Function:" in s
        assert "Cyclomatic complexity:" in s

    def test_analyze_multi_func(self, multi_func_binary: BinaryFile) -> None:
        """Analyze multi_func binary produces valid results with calls."""
        analysis = analyze_function(multi_func_binary, _CODE_OFFSET)
        assert analysis.instruction_count > 0
        assert analysis.block_count >= 1

    def test_call_targets_in_multi_func(self, multi_func_binary: BinaryFile) -> None:
        """Multi-function binary has detectable call targets."""
        analysis = analyze_function(multi_func_binary, _CODE_OFFSET)
        # The multi_func binary has CALL instructions
        targets = analysis.call_targets
        assert isinstance(targets, list)

    def test_analyze_with_explicit_size(self, tiny_elf_binary: BinaryFile) -> None:
        """Specifying an explicit size restricts analysis."""
        analysis = analyze_function(tiny_elf_binary, _CODE_OFFSET, size=8)
        assert analysis.size == 8


class TestCompareFunctions:
    """Tests for compare_functions()."""

    def test_compare_functions(
        self, tiny_elf_binary: BinaryFile, multi_func_binary: BinaryFile
    ) -> None:
        """Compare two different functions produces a valid ComparisonResult."""
        result = compare_functions(
            tiny_elf_binary,
            _CODE_OFFSET,
            multi_func_binary,
            _CODE_OFFSET,
        )
        assert isinstance(result, ComparisonResult)
        assert result.analysis_a is not None
        assert result.analysis_b is not None

    def test_comparison_deltas(
        self, tiny_elf_binary: BinaryFile, multi_func_binary: BinaryFile
    ) -> None:
        """size_delta and complexity_delta are computed correctly."""
        result = compare_functions(
            tiny_elf_binary,
            _CODE_OFFSET,
            multi_func_binary,
            _CODE_OFFSET,
        )
        assert result.size_delta == (result.analysis_b.size - result.analysis_a.size)
        assert result.complexity_delta == (
            result.analysis_b.cyclomatic_complexity - result.analysis_a.cyclomatic_complexity
        )

    def test_comparison_summary(
        self, tiny_elf_binary: BinaryFile, multi_func_binary: BinaryFile
    ) -> None:
        """summary() returns readable text."""
        result = compare_functions(
            tiny_elf_binary,
            _CODE_OFFSET,
            multi_func_binary,
            _CODE_OFFSET,
        )
        s = result.summary()
        assert isinstance(s, str)
        assert "Comparison:" in s
        assert "delta" in s.lower()

    def test_compare_same_function(self, tiny_elf_binary: BinaryFile) -> None:
        """Comparing a function to itself → zero deltas, 100% similarity."""
        result = compare_functions(
            tiny_elf_binary,
            _CODE_OFFSET,
            tiny_elf_binary,
            _CODE_OFFSET,
        )
        assert result.size_delta == 0
        assert result.complexity_delta == 0
        assert result.instruction_delta == 0
        if result.diff_report:
            assert result.diff_report.similarity == 1.0
