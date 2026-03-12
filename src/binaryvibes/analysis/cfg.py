"""Control Flow Graph analysis for disassembled binaries."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar

from binaryvibes.analysis.disassembler import Instruction


class EdgeType(Enum):
    """Classification of control-flow edges between basic blocks."""

    FALL_THROUGH = "fall_through"
    BRANCH = "branch"
    COND_BRANCH_TAKEN = "cond_taken"
    COND_BRANCH_NOT_TAKEN = "cond_not_taken"
    CALL = "call"
    RETURN = "return"


@dataclass(frozen=True)
class Edge:
    """A directed edge in the control-flow graph."""

    source: int
    target: int
    edge_type: EdgeType


@dataclass
class BasicBlock:
    """A maximal sequence of instructions with single entry and single exit."""

    start_addr: int
    end_addr: int
    instructions: list[Instruction] = field(default_factory=list)
    successor_addrs: list[int] = field(default_factory=list)
    predecessor_addrs: list[int] = field(default_factory=list)

    @property
    def size(self) -> int:
        return self.end_addr - self.start_addr

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)


@dataclass
class ControlFlowGraph:
    """A control-flow graph composed of basic blocks and edges."""

    blocks: dict[int, BasicBlock]
    edges: list[Edge]
    entry_addr: int

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def successors(self, addr: int) -> list[BasicBlock]:
        """Return successor blocks of the block starting at *addr*."""
        block = self.blocks[addr]
        return [self.blocks[sa] for sa in block.successor_addrs if sa in self.blocks]

    def predecessors(self, addr: int) -> list[BasicBlock]:
        """Return predecessor blocks of the block starting at *addr*."""
        block = self.blocks[addr]
        return [self.blocks[pa] for pa in block.predecessor_addrs if pa in self.blocks]


_HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")


class CFGBuilder:
    """Builds a CFG from a list of disassembled instructions."""

    UNCONDITIONAL_JUMPS: ClassVar[set[str]] = {"jmp", "jmpq"}
    CONDITIONAL_JUMPS: ClassVar[set[str]] = {
        "je",
        "jz",
        "jne",
        "jnz",
        "jg",
        "jge",
        "jl",
        "jle",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jns",
        "js",
        "jo",
        "jno",
        "jp",
        "jnp",
        "jcxz",
        "jecxz",
        "jrcxz",
    }
    CALL_MNEMONICS: ClassVar[set[str]] = {"call", "callq"}
    RETURN_MNEMONICS: ClassVar[set[str]] = {"ret", "retq", "retn"}

    # Union of all control-flow-altering mnemonics (excluding calls)
    _BRANCH_MNEMONICS: ClassVar[set[str]] = UNCONDITIONAL_JUMPS | CONDITIONAL_JUMPS

    def build(self, instructions: list[Instruction]) -> ControlFlowGraph:
        """Build a CFG from disassembled instructions."""
        if not instructions:
            entry = 0
            return ControlFlowGraph(blocks={}, edges=[], entry_addr=entry)

        entry = instructions[0].address
        leaders = self._find_leaders(instructions)
        blocks = self._form_blocks(instructions, leaders)
        edges = self._build_edges(blocks)
        self._link_predecessors(blocks, edges)

        return ControlFlowGraph(blocks=blocks, edges=edges, entry_addr=entry)

    # ------------------------------------------------------------------
    # Step 1: Identify leader addresses
    # ------------------------------------------------------------------

    def _find_leaders(self, instructions: list[Instruction]) -> set[int]:
        leaders: set[int] = set()
        addr_set = {insn.address for insn in instructions}

        # First instruction is always a leader
        leaders.add(instructions[0].address)

        for idx, insn in enumerate(instructions):
            mnemonic = insn.mnemonic.lower()
            is_branch = mnemonic in self._BRANCH_MNEMONICS
            is_call = mnemonic in self.CALL_MNEMONICS
            is_ret = mnemonic in self.RETURN_MNEMONICS

            if is_branch or is_call or is_ret:
                # Instruction following a control-flow change is a leader
                if idx + 1 < len(instructions):
                    leaders.add(instructions[idx + 1].address)

                # Branch/call target is a leader (if within our address space)
                if is_branch or is_call:
                    target = self._parse_branch_target(insn.op_str)
                    if target is not None and target in addr_set:
                        leaders.add(target)

        return leaders

    # ------------------------------------------------------------------
    # Step 2: Form basic blocks from leaders
    # ------------------------------------------------------------------

    def _form_blocks(
        self,
        instructions: list[Instruction],
        leaders: set[int],
    ) -> dict[int, BasicBlock]:
        blocks: dict[int, BasicBlock] = {}
        current_insns: list[Instruction] = []
        current_start: int | None = None

        for insn in instructions:
            if insn.address in leaders and current_insns:
                # Flush previous block
                block = self._make_block(current_start, current_insns)  # type: ignore[arg-type]
                blocks[block.start_addr] = block
                current_insns = []
                current_start = None

            if current_start is None:
                current_start = insn.address
            current_insns.append(insn)

        # Flush last block
        if current_insns and current_start is not None:
            block = self._make_block(current_start, current_insns)
            blocks[block.start_addr] = block

        return blocks

    @staticmethod
    def _make_block(start: int, insns: list[Instruction]) -> BasicBlock:
        last = insns[-1]
        return BasicBlock(
            start_addr=start,
            end_addr=last.address + last.size,
            instructions=list(insns),
        )

    # ------------------------------------------------------------------
    # Step 3: Classify edges and populate successor lists
    # ------------------------------------------------------------------

    def _build_edges(self, blocks: dict[int, BasicBlock]) -> list[Edge]:
        edges: list[Edge] = []
        sorted_addrs = sorted(blocks)

        for i, addr in enumerate(sorted_addrs):
            block = blocks[addr]
            last_insn = block.instructions[-1]
            mnemonic = last_insn.mnemonic.lower()
            fall_through = sorted_addrs[i + 1] if i + 1 < len(sorted_addrs) else None

            if mnemonic in self.UNCONDITIONAL_JUMPS:
                target = self._parse_branch_target(last_insn.op_str)
                if target is not None and target in blocks:
                    edges.append(Edge(addr, target, EdgeType.BRANCH))
                    block.successor_addrs.append(target)

            elif mnemonic in self.CONDITIONAL_JUMPS:
                target = self._parse_branch_target(last_insn.op_str)
                if target is not None and target in blocks:
                    edges.append(Edge(addr, target, EdgeType.COND_BRANCH_TAKEN))
                    block.successor_addrs.append(target)
                if fall_through is not None:
                    edges.append(Edge(addr, fall_through, EdgeType.COND_BRANCH_NOT_TAKEN))
                    block.successor_addrs.append(fall_through)

            elif mnemonic in self.CALL_MNEMONICS:
                target = self._parse_branch_target(last_insn.op_str)
                if target is not None and target in blocks:
                    edges.append(Edge(addr, target, EdgeType.CALL))
                    block.successor_addrs.append(target)
                if fall_through is not None:
                    edges.append(Edge(addr, fall_through, EdgeType.FALL_THROUGH))
                    block.successor_addrs.append(fall_through)

            elif mnemonic in self.RETURN_MNEMONICS:
                # Return exits the function; no intra-function successor
                edges.append(Edge(addr, 0, EdgeType.RETURN))

            else:
                # Normal instruction → fall-through to next block
                if fall_through is not None:
                    edges.append(Edge(addr, fall_through, EdgeType.FALL_THROUGH))
                    block.successor_addrs.append(fall_through)

        return edges

    # ------------------------------------------------------------------
    # Step 4: Back-fill predecessor lists
    # ------------------------------------------------------------------

    @staticmethod
    def _link_predecessors(blocks: dict[int, BasicBlock], edges: list[Edge]) -> None:
        for edge in edges:
            if edge.edge_type == EdgeType.RETURN:
                continue
            target_block = blocks.get(edge.target)
            if target_block is not None and edge.source not in target_block.predecessor_addrs:
                target_block.predecessor_addrs.append(edge.source)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_branch_target(op_str: str) -> int | None:
        """Extract a hex address from a Capstone operand string."""
        m = _HEX_RE.search(op_str)
        if m is None:
            return None
        return int(m.group(1), 16)
