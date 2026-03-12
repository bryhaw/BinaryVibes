"""Binary Pattern Language — semantic grep for binary code.

A domain-specific pattern matching language that matches on semantic
patterns in disassembled instruction sequences, not just raw bytes.

Pattern syntax (elements separated by " ; "):
    "mov ?dst, ?src"          — match mov with capture wildcards
    "call ?func"              — match any call, bind target
    "*"                       — match any single instruction
    "..."                     — match 0-10 instructions (wildcard gap)
    "xor ?reg, ?reg"          — xor with same register (self-zeroing idiom)
    "call ?f ; test eax, eax ; je ?label" — call-and-check pattern
"""

from __future__ import annotations

from dataclasses import dataclass, field

from binaryvibes.analysis.disassembler import Instruction


@dataclass(frozen=True)
class PatternElement:
    """A single element in a pattern — matches one instruction.

    Operand wildcards: ``?name`` captures any operand and binds it to *name*.
    If ``?name`` appears again later in the same pattern the actual operand
    must equal the previously bound value (back-reference).
    Literal operands must match exactly.
    """

    mnemonic: str | None = None
    operands: list[str] | None = None

    def matches(self, instruction: Instruction, bindings: dict[str, str]) -> bool:
        """Check if *instruction* matches this element, updating *bindings*."""
        if self.mnemonic is not None and self.mnemonic != instruction.mnemonic:
            return False

        if self.operands is not None:
            actual_ops = [op.strip() for op in instruction.op_str.split(",") if op.strip()]
            if len(self.operands) != len(actual_ops):
                return False
            for pat_op, actual_op in zip(self.operands, actual_ops, strict=True):
                if pat_op.startswith("?"):
                    name = pat_op[1:]
                    if name in bindings:
                        if bindings[name] != actual_op:
                            return False
                    else:
                        bindings[name] = actual_op
                elif pat_op != actual_op:
                    return False
        return True


@dataclass(frozen=True)
class WildcardGap:
    """Matches any sequence of *min_gap* to *max_gap* instructions."""

    min_gap: int = 0
    max_gap: int = 10


@dataclass(frozen=True)
class Pattern:
    """A sequence of pattern elements that matches a code pattern.

    Elements are separated by ``" ; "`` (semicolon with surrounding spaces).
    ``*`` matches any single instruction.
    ``...`` matches 0-10 instructions (wildcard gap).
    ``?name`` inside operands is a capture wildcard.
    """

    elements: tuple[PatternElement | WildcardGap, ...]
    source: str = ""

    @classmethod
    def parse(cls, pattern_str: str) -> Pattern:
        """Parse a pattern string into a :class:`Pattern`."""
        parts = [p.strip() for p in pattern_str.split(";")]
        elements: list[PatternElement | WildcardGap] = []
        for part in parts:
            if part == "...":
                elements.append(WildcardGap(min_gap=0, max_gap=10))
            elif part == "*":
                elements.append(PatternElement())
            else:
                tokens = part.split(None, 1)
                mnemonic = tokens[0] if tokens else None
                operands = None
                if len(tokens) > 1:
                    operands = [op.strip() for op in tokens[1].split(",")]
                elements.append(PatternElement(mnemonic=mnemonic, operands=operands))
        return cls(elements=tuple(elements), source=pattern_str)


@dataclass
class Match:
    """A successful pattern match result."""

    start_index: int
    end_index: int
    instructions: list[Instruction]
    bindings: dict[str, str] = field(default_factory=dict)

    @property
    def start_addr(self) -> int:
        return self.instructions[0].address if self.instructions else 0

    @property
    def end_addr(self) -> int:
        if self.instructions:
            last = self.instructions[-1]
            return last.address + last.size
        return 0

    def __str__(self) -> str:
        addr_range = f"0x{self.start_addr:08x}-0x{self.end_addr:08x}"
        binds = ", ".join(f"{k}={v}" for k, v in self.bindings.items())
        return f"Match({addr_range}, bindings={{{binds}}})"


class PatternMatcher:
    """Searches instruction sequences for pattern matches."""

    def search(self, instructions: list[Instruction], pattern: Pattern) -> list[Match]:
        """Find all non-overlapping matches of *pattern* in *instructions*."""
        matches: list[Match] = []
        i = 0
        while i < len(instructions):
            result = self._try_match(instructions, i, pattern)
            if result is not None:
                matches.append(result)
                i = result.end_index
            else:
                i += 1
        return matches

    def search_first(self, instructions: list[Instruction], pattern: Pattern) -> Match | None:
        """Find the first match of *pattern*."""
        for i in range(len(instructions)):
            result = self._try_match(instructions, i, pattern)
            if result is not None:
                return result
        return None

    def _try_match(
        self,
        instructions: list[Instruction],
        start: int,
        pattern: Pattern,
    ) -> Match | None:
        """Try to match *pattern* starting at index *start*."""
        bindings: dict[str, str] = {}
        end_idx = self._match_recursive(instructions, start, 0, pattern.elements, bindings)
        if end_idx is not None:
            return Match(start, end_idx, instructions[start:end_idx], bindings)
        return None

    def _match_recursive(
        self,
        instructions: list[Instruction],
        instr_idx: int,
        elem_idx: int,
        elements: tuple[PatternElement | WildcardGap, ...],
        bindings: dict[str, str],
    ) -> int | None:
        """Recursive matching with backtracking. Returns end index or ``None``."""
        if elem_idx >= len(elements):
            return instr_idx

        elem = elements[elem_idx]

        if isinstance(elem, WildcardGap):
            for gap in range(elem.min_gap, elem.max_gap + 1):
                next_instr = instr_idx + gap
                if next_instr > len(instructions):
                    break
                saved = dict(bindings)
                result = self._match_recursive(
                    instructions, next_instr, elem_idx + 1, elements, bindings
                )
                if result is not None:
                    return result
                bindings.clear()
                bindings.update(saved)
            return None

        # PatternElement — must match current instruction
        if instr_idx >= len(instructions):
            return None

        saved = dict(bindings)
        if elem.matches(instructions[instr_idx], bindings):
            result = self._match_recursive(
                instructions, instr_idx + 1, elem_idx + 1, elements, bindings
            )
            if result is not None:
                return result

        bindings.clear()
        bindings.update(saved)
        return None


# ---------------------------------------------------------------------------
# Pre-built common patterns ("standard library")
# ---------------------------------------------------------------------------

COMMON_PATTERNS: dict[str, Pattern] = {
    "call_and_check": Pattern.parse("call ?func ; test eax, eax ; je ?label"),
    "function_prologue": Pattern.parse("push rbp ; mov rbp, rsp"),
    "function_epilogue": Pattern.parse("pop rbp ; ret"),
    "self_zero": Pattern.parse("xor ?reg, ?reg"),
    "nop_sled": Pattern.parse("nop ; nop ; nop"),
    "stack_canary_check": Pattern.parse(
        "mov ?reg, qword ptr fs:[0x28] ; ... ; xor ?reg, qword ptr fs:[0x28]"
    ),
}
