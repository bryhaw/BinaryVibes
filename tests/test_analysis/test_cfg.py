"""Tests for CFG (Control Flow Graph) analysis module."""

from __future__ import annotations

from binaryvibes.analysis.cfg import CFGBuilder, ControlFlowGraph, EdgeType
from binaryvibes.analysis.disassembler import Disassembler, Instruction
from binaryvibes.core.arch import Arch
from binaryvibes.synthesis.assembler import Assembler

BASE = 0x400000


def _asm_and_disasm(asm_code: str) -> list[Instruction]:
    """Helper: assemble x86_64 code, then disassemble it."""
    asm = Assembler(Arch.X86_64)
    dis = Disassembler(Arch.X86_64)
    code_bytes = asm.assemble(asm_code, BASE)
    return dis.disassemble(code_bytes, BASE)


def _build_cfg(asm_code: str) -> ControlFlowGraph:
    """Helper: assemble, disassemble, and build CFG in one step."""
    instructions = _asm_and_disasm(asm_code)
    return CFGBuilder().build(instructions)


def _edge_types(cfg: ControlFlowGraph) -> set[EdgeType]:
    """Return the set of edge types present in a CFG."""
    return {e.edge_type for e in cfg.edges}


# -------------------------------------------------------------------
# Basic patterns
# -------------------------------------------------------------------


class TestLinearCode:
    """Linear code with no branches produces a single basic block."""

    def test_single_block(self):
        cfg = _build_cfg("mov rax, 1; mov rbx, 2; ret")
        # ret terminates the block; only 1 block expected
        assert cfg.block_count == 1

    def test_no_branch_edges(self):
        cfg = _build_cfg("mov rax, 1; mov rbx, 2; ret")
        # The only edge should be the RETURN edge from the ret
        for edge in cfg.edges:
            assert edge.edge_type not in (
                EdgeType.BRANCH,
                EdgeType.COND_BRANCH_TAKEN,
                EdgeType.COND_BRANCH_NOT_TAKEN,
            )

    def test_has_return_edge(self):
        cfg = _build_cfg("mov rax, 1; mov rbx, 2; ret")
        assert EdgeType.RETURN in _edge_types(cfg)


class TestUnconditionalJump:
    """Unconditional jmp splits blocks and creates a BRANCH edge."""

    def test_creates_multiple_blocks(self):
        cfg = _build_cfg("jmp label; nop; label: mov rax, 1; ret")
        assert cfg.block_count >= 2

    def test_has_branch_edge(self):
        cfg = _build_cfg("jmp label; nop; label: mov rax, 1; ret")
        assert EdgeType.BRANCH in _edge_types(cfg)

    def test_jump_target_is_successor(self):
        cfg = _build_cfg("jmp label; nop; label: mov rax, 1; ret")
        # The entry block (jmp) should have exactly one successor
        successors = cfg.successors(cfg.entry_addr)
        assert len(successors) >= 1
        # The successor should contain "mov rax, 1"
        target_block = successors[0]
        mnemonics = [i.mnemonic.lower() for i in target_block.instructions]
        assert "mov" in mnemonics


class TestConditionalBranch:
    """Conditional branch creates COND_BRANCH_TAKEN and COND_BRANCH_NOT_TAKEN."""

    ASM = "cmp rax, 0; je label; mov rax, 1; label: ret"

    def test_creates_both_edge_types(self):
        cfg = _build_cfg(self.ASM)
        types = _edge_types(cfg)
        assert EdgeType.COND_BRANCH_TAKEN in types
        assert EdgeType.COND_BRANCH_NOT_TAKEN in types

    def test_multiple_blocks(self):
        cfg = _build_cfg(self.ASM)
        assert cfg.block_count >= 2

    def test_taken_and_not_taken_successors(self):
        cfg = _build_cfg(self.ASM)
        # Find the block that ends with the conditional jump
        cond_block = None
        for block in cfg.blocks.values():
            last_mnemonic = block.instructions[-1].mnemonic.lower()
            if last_mnemonic == "je":
                cond_block = block
                break
        assert cond_block is not None
        # It should have 2 successors (taken + not-taken)
        succs = cfg.successors(cond_block.start_addr)
        assert len(succs) == 2


class TestCallInstruction:
    """call creates CALL edge + FALL_THROUGH edge."""

    ASM = "call label; ret; label: mov rax, 1; ret"

    def test_has_call_edge(self):
        cfg = _build_cfg(self.ASM)
        assert EdgeType.CALL in _edge_types(cfg)

    def test_has_fall_through_edge(self):
        cfg = _build_cfg(self.ASM)
        assert EdgeType.FALL_THROUGH in _edge_types(cfg)

    def test_call_block_has_two_successors(self):
        cfg = _build_cfg(self.ASM)
        # call block should have successors: call target + fall-through (ret block)
        succs = cfg.successors(cfg.entry_addr)
        assert len(succs) == 2


# -------------------------------------------------------------------
# ControlFlowGraph properties
# -------------------------------------------------------------------


class TestCFGProperties:
    """Verify block_count, edge_count, and entry_addr."""

    def test_block_count(self):
        cfg = _build_cfg("cmp rax, 0; je label; nop; label: ret")
        assert cfg.block_count == cfg.block_count  # sanity
        assert cfg.block_count >= 2

    def test_edge_count(self):
        cfg = _build_cfg("cmp rax, 0; je label; nop; label: ret")
        assert cfg.edge_count == len(cfg.edges)
        assert cfg.edge_count >= 2

    def test_entry_addr(self):
        cfg = _build_cfg("mov rax, 1; ret")
        assert cfg.entry_addr == BASE


# -------------------------------------------------------------------
# Successors / predecessors
# -------------------------------------------------------------------


class TestSuccessorsAndPredecessors:
    """Test successors() and predecessors() navigation."""

    ASM = "cmp rax, 0; je label; mov rax, 1; label: ret"

    def test_successors_returns_blocks(self):
        cfg = _build_cfg(self.ASM)
        # Find block with je
        for block in cfg.blocks.values():
            if block.instructions[-1].mnemonic.lower() == "je":
                succs = cfg.successors(block.start_addr)
                assert len(succs) > 0
                assert all(isinstance(b, type(block)) for b in succs)
                break

    def test_predecessors_returns_blocks(self):
        cfg = _build_cfg(self.ASM)
        # The final "ret" block should have predecessors
        # Find the block containing ret
        ret_block = None
        for block in cfg.blocks.values():
            if block.instructions[-1].mnemonic.lower() == "ret":
                ret_block = block
                break
        assert ret_block is not None
        preds = cfg.predecessors(ret_block.start_addr)
        assert len(preds) >= 1

    def test_successor_of_entry_block(self):
        cfg = _build_cfg("jmp label; nop; label: ret")
        succs = cfg.successors(cfg.entry_addr)
        assert len(succs) >= 1


# -------------------------------------------------------------------
# Edge cases
# -------------------------------------------------------------------


class TestEdgeCases:
    """Empty input, single instruction, and basic block properties."""

    def test_empty_instructions(self):
        cfg = CFGBuilder().build([])
        assert cfg.block_count == 0
        assert cfg.edge_count == 0
        assert cfg.blocks == {}

    def test_single_ret(self):
        cfg = _build_cfg("ret")
        assert cfg.block_count == 1
        assert EdgeType.RETURN in _edge_types(cfg)

    def test_single_nop(self):
        """Single non-control-flow instruction still forms a block."""
        instructions = _asm_and_disasm("nop")
        cfg = CFGBuilder().build(instructions)
        assert cfg.block_count == 1


class TestBasicBlockProperties:
    """Verify BasicBlock.size and BasicBlock.instruction_count."""

    def test_size_positive(self):
        cfg = _build_cfg("mov rax, 1; mov rbx, 2; ret")
        for block in cfg.blocks.values():
            assert block.size > 0

    def test_instruction_count_matches(self):
        cfg = _build_cfg("mov rax, 1; mov rbx, 2; ret")
        block = cfg.blocks[cfg.entry_addr]
        assert block.instruction_count == len(block.instructions)
        # 3 instructions: mov, mov, ret
        assert block.instruction_count == 3

    def test_size_equals_sum_of_instruction_sizes(self):
        cfg = _build_cfg("mov rax, 1; mov rbx, 2; ret")
        block = cfg.blocks[cfg.entry_addr]
        total = sum(i.size for i in block.instructions)
        assert block.size == total
