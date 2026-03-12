"""Comprehensive tests for the Binary Pattern Language."""

from __future__ import annotations

from binaryvibes.analysis.disassembler import Disassembler, Instruction
from binaryvibes.analysis.patterns import (
    COMMON_PATTERNS,
    Pattern,
    PatternElement,
    PatternMatcher,
    WildcardGap,
)
from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler

BASE = 0x400000


def _asm_dis(code: str) -> list[Instruction]:
    """Assemble *code* then disassemble back to instructions."""
    asm = Assembler(Arch.X86_64)
    dis = Disassembler(Arch.X86_64)
    return dis.disassemble(asm.assemble(code, BASE), BASE)


# ======================================================================
# Pattern.parse
# ======================================================================


class TestPatternParse:
    def test_parse_simple(self):
        pat = Pattern.parse("mov ?dst, ?src")
        assert len(pat.elements) == 1
        elem = pat.elements[0]
        assert isinstance(elem, PatternElement)
        assert elem.mnemonic == "mov"
        assert elem.operands == ["?dst", "?src"]

    def test_parse_multi(self):
        pat = Pattern.parse("push rbp ; mov rbp, rsp")
        assert len(pat.elements) == 2
        e0, e1 = pat.elements
        assert isinstance(e0, PatternElement)
        assert e0.mnemonic == "push"
        assert e0.operands == ["rbp"]
        assert isinstance(e1, PatternElement)
        assert e1.mnemonic == "mov"
        assert e1.operands == ["rbp", "rsp"]

    def test_parse_wildcard_gap(self):
        pat = Pattern.parse("call ?f ; ... ; ret")
        assert len(pat.elements) == 3
        assert isinstance(pat.elements[0], PatternElement)
        assert isinstance(pat.elements[1], WildcardGap)
        assert isinstance(pat.elements[2], PatternElement)
        gap = pat.elements[1]
        assert gap.min_gap == 0
        assert gap.max_gap == 10

    def test_parse_star(self):
        pat = Pattern.parse("* ; ret")
        assert len(pat.elements) == 2
        star = pat.elements[0]
        assert isinstance(star, PatternElement)
        # Star = PatternElement(mnemonic=None, operands=None) — matches anything
        assert star.mnemonic is None
        assert star.operands is None
        assert pat.elements[1].mnemonic == "ret"

    def test_parse_preserves_source(self):
        src = "xor ?r, ?r"
        pat = Pattern.parse(src)
        assert pat.source == src

    def test_parse_no_operands(self):
        pat = Pattern.parse("ret")
        assert len(pat.elements) == 1
        elem = pat.elements[0]
        assert elem.mnemonic == "ret"
        assert elem.operands is None


# ======================================================================
# PatternElement.matches
# ======================================================================


class TestPatternElementMatches:
    def test_element_matches_exact(self):
        elem = PatternElement(mnemonic="mov", operands=["rax", "rbx"])
        instr = Instruction(address=0, mnemonic="mov", op_str="rax, rbx", raw=b"", size=3)
        bindings: dict[str, str] = {}
        assert elem.matches(instr, bindings) is True

    def test_element_wildcard_capture(self):
        elem = PatternElement(mnemonic="push", operands=["?reg"])
        instr = Instruction(address=0, mnemonic="push", op_str="rbp", raw=b"", size=1)
        bindings: dict[str, str] = {}
        assert elem.matches(instr, bindings) is True
        assert bindings["reg"] == "rbp"

    def test_element_wildcard_backref(self):
        """?reg used twice must match the same value both times."""
        elem = PatternElement(mnemonic="xor", operands=["?reg", "?reg"])
        instr = Instruction(address=0, mnemonic="xor", op_str="eax, eax", raw=b"", size=2)
        bindings: dict[str, str] = {}
        assert elem.matches(instr, bindings) is True
        assert bindings["reg"] == "eax"

    def test_element_wildcard_backref_mismatch(self):
        """?reg used twice must fail if operands differ."""
        elem = PatternElement(mnemonic="xor", operands=["?reg", "?reg"])
        instr = Instruction(address=0, mnemonic="xor", op_str="eax, ebx", raw=b"", size=2)
        bindings: dict[str, str] = {}
        assert elem.matches(instr, bindings) is False

    def test_element_no_match_mnemonic(self):
        elem = PatternElement(mnemonic="mov", operands=["rax", "rbx"])
        instr = Instruction(address=0, mnemonic="add", op_str="rax, rbx", raw=b"", size=3)
        bindings: dict[str, str] = {}
        assert elem.matches(instr, bindings) is False

    def test_element_no_match_operand_count(self):
        elem = PatternElement(mnemonic="mov", operands=["rax", "rbx"])
        instr = Instruction(address=0, mnemonic="mov", op_str="rax", raw=b"", size=3)
        bindings: dict[str, str] = {}
        assert elem.matches(instr, bindings) is False

    def test_star_element_matches_anything(self):
        """PatternElement(None, None) matches any instruction."""
        star = PatternElement()
        instr = Instruction(address=0, mnemonic="nop", op_str="", raw=b"", size=1)
        bindings: dict[str, str] = {}
        assert star.matches(instr, bindings) is True

    def test_mnemonic_only_match(self):
        """Element with operands=None matches any operand string."""
        elem = PatternElement(mnemonic="ret")
        instr = Instruction(address=0, mnemonic="ret", op_str="", raw=b"", size=1)
        bindings: dict[str, str] = {}
        assert elem.matches(instr, bindings) is True


# ======================================================================
# PatternMatcher.search
# ======================================================================


class TestPatternMatcherSearch:
    def test_xor_self_zero(self):
        """Find 'xor ?reg, ?reg' (self-zeroing idiom) in code with 2 hits."""
        instrs = _asm_dis("xor eax, eax; nop; xor ecx, ecx; ret")
        pat = Pattern.parse("xor ?reg, ?reg")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, pat)
        assert len(matches) == 2
        assert matches[0].bindings["reg"] == "eax"
        assert matches[1].bindings["reg"] == "ecx"

    def test_no_match(self):
        instrs = _asm_dis("nop; nop; ret")
        pat = Pattern.parse("xor ?reg, ?reg")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, pat)
        assert matches == []

    def test_single_instruction_pattern(self):
        instrs = _asm_dis("nop; ret; nop; ret")
        pat = Pattern.parse("ret")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, pat)
        assert len(matches) == 2
        for m in matches:
            assert m.instructions[0].mnemonic == "ret"

    def test_multi_instruction_pattern(self):
        """Function prologue: push rbp ; mov rbp, rsp."""
        instrs = _asm_dis("push rbp; mov rbp, rsp; nop; ret")
        pat = Pattern.parse("push rbp ; mov rbp, rsp")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, pat)
        assert len(matches) == 1
        assert len(matches[0].instructions) == 2
        assert matches[0].instructions[0].mnemonic == "push"
        assert matches[0].instructions[1].mnemonic == "mov"

    def test_wildcard_gap(self):
        """'mov rax, ?val ; ... ; ret' should match with filler instructions."""
        instrs = _asm_dis("mov rax, 42; nop; nop; ret")
        pat = Pattern.parse("mov rax, ?val ; ... ; ret")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, pat)
        assert len(matches) == 1
        m = matches[0]
        assert m.bindings["val"] is not None
        assert m.instructions[-1].mnemonic == "ret"
        # Gap means instructions between mov and ret are included
        assert len(m.instructions) == 4

    def test_search_first(self):
        instrs = _asm_dis("xor eax, eax; nop; xor ecx, ecx; ret")
        pat = Pattern.parse("xor ?reg, ?reg")
        matcher = PatternMatcher()
        m = matcher.search_first(instrs, pat)
        assert m is not None
        assert m.bindings["reg"] == "eax"

    def test_search_first_no_match(self):
        instrs = _asm_dis("nop; ret")
        pat = Pattern.parse("call ?f")
        matcher = PatternMatcher()
        assert matcher.search_first(instrs, pat) is None

    def test_match_properties(self):
        """start_addr, end_addr, and bindings are populated correctly."""
        instrs = _asm_dis("nop; xor eax, eax; ret")
        pat = Pattern.parse("xor ?reg, ?reg")
        matcher = PatternMatcher()
        m = matcher.search_first(instrs, pat)
        assert m is not None
        assert m.start_addr >= BASE
        assert m.end_addr > m.start_addr
        assert m.bindings["reg"] == "eax"
        assert m.start_index == 1
        assert m.end_index == 2

    def test_non_overlapping(self):
        """Consecutive 'nop; nop' should not produce overlapping matches."""
        instrs = _asm_dis("nop; nop; nop; nop; ret")
        pat = Pattern.parse("nop ; nop")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, pat)
        # 4 nops → non-overlapping pairs: indices [0,1] and [2,3]
        assert len(matches) == 2
        assert matches[0].end_index <= matches[1].start_index

    def test_match_str_representation(self):
        instrs = _asm_dis("xor eax, eax; ret")
        pat = Pattern.parse("xor ?reg, ?reg")
        matcher = PatternMatcher()
        m = matcher.search_first(instrs, pat)
        assert m is not None
        s = str(m)
        assert "Match(" in s
        assert "reg=eax" in s


# ======================================================================
# COMMON_PATTERNS
# ======================================================================


class TestCommonPatterns:
    EXPECTED_KEYS = frozenset(
        {
            "call_and_check",
            "function_prologue",
            "function_epilogue",
            "self_zero",
            "nop_sled",
            "stack_canary_check",
        }
    )

    def test_common_patterns_exist(self):
        for key in self.EXPECTED_KEYS:
            assert key in COMMON_PATTERNS, f"Missing COMMON_PATTERNS key: {key}"

    def test_common_patterns_are_pattern_instances(self):
        for key, pat in COMMON_PATTERNS.items():
            assert isinstance(pat, Pattern), f"{key} is not a Pattern"

    def test_self_zero_common(self):
        """COMMON_PATTERNS['self_zero'] finds xor-self patterns."""
        instrs = _asm_dis("nop; xor eax, eax; nop; xor ecx, ecx; ret")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, COMMON_PATTERNS["self_zero"])
        assert len(matches) == 2
        regs = {m.bindings["reg"] for m in matches}
        assert "eax" in regs
        assert "ecx" in regs

    def test_function_prologue_common(self):
        instrs = _asm_dis("push rbp; mov rbp, rsp; nop; ret")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, COMMON_PATTERNS["function_prologue"])
        assert len(matches) == 1

    def test_function_epilogue_common(self):
        instrs = _asm_dis("nop; pop rbp; ret")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, COMMON_PATTERNS["function_epilogue"])
        assert len(matches) == 1

    def test_nop_sled_common(self):
        instrs = _asm_dis("nop; nop; nop; ret")
        matcher = PatternMatcher()
        matches = matcher.search(instrs, COMMON_PATTERNS["nop_sled"])
        assert len(matches) == 1
