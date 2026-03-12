"""Cross-format symbol resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import lief

from binaryvibes.core.binary import BinaryFile


class SymbolType(Enum):
    """Classification of a symbol's type."""

    FUNCTION = "function"
    OBJECT = "object"
    UNKNOWN = "unknown"


class SymbolBinding(Enum):
    """Visibility / linkage of a symbol."""

    LOCAL = "local"
    GLOBAL = "global"
    WEAK = "weak"


@dataclass(frozen=True)
class Symbol:
    """A resolved symbol from any binary format."""

    name: str
    address: int
    sym_type: SymbolType
    binding: SymbolBinding
    section_name: str = ""

    def __str__(self) -> str:
        return f"0x{self.address:08x} {self.binding.value:6s} {self.sym_type.value:8s} {self.name}"


@dataclass
class SymbolTable:
    """Collection of symbols with lookup helpers."""

    symbols: list[Symbol] = field(default_factory=list)

    def by_name(self, name: str) -> Symbol | None:
        """Look up symbol by exact name."""
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None

    def by_address(self, address: int) -> list[Symbol]:
        """Find all symbols at a given address."""
        return [s for s in self.symbols if s.address == address]

    def filter_type(self, sym_type: SymbolType) -> list[Symbol]:
        """Return all symbols of a given type."""
        return [s for s in self.symbols if s.sym_type == sym_type]

    def filter_binding(self, binding: SymbolBinding) -> list[Symbol]:
        """Return all symbols with a given binding."""
        return [s for s in self.symbols if s.binding == binding]

    @property
    def functions(self) -> list[Symbol]:
        """Shortcut for filter_type(FUNCTION)."""
        return self.filter_type(SymbolType.FUNCTION)

    @property
    def imports(self) -> list[Symbol]:
        """Symbols with address 0 (imported, not yet resolved)."""
        return [s for s in self.symbols if s.address == 0]

    @property
    def exports(self) -> list[Symbol]:
        """Non-local symbols with non-zero address."""
        return [s for s in self.symbols if s.address != 0 and s.binding != SymbolBinding.LOCAL]


def resolve_symbols(binary: BinaryFile) -> SymbolTable:
    """Extract symbols from a binary file using LIEF."""
    parsed = binary.lief  # May raise ValueError if unparseable

    if isinstance(parsed, lief.ELF.Binary):
        return _resolve_elf_symbols(parsed)
    elif isinstance(parsed, lief.PE.Binary):
        return _resolve_pe_symbols(parsed)
    elif isinstance(parsed, lief.MachO.Binary):
        return _resolve_macho_symbols(parsed)
    else:
        return SymbolTable()


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

_ELF_TYPE_MAP: dict[lief.ELF.Symbol.TYPE, SymbolType] = {
    lief.ELF.Symbol.TYPE.FUNC: SymbolType.FUNCTION,
    lief.ELF.Symbol.TYPE.OBJECT: SymbolType.OBJECT,
}

_ELF_BINDING_MAP: dict[lief.ELF.Symbol.BINDING, SymbolBinding] = {
    lief.ELF.Symbol.BINDING.GLOBAL: SymbolBinding.GLOBAL,
    lief.ELF.Symbol.BINDING.LOCAL: SymbolBinding.LOCAL,
    lief.ELF.Symbol.BINDING.WEAK: SymbolBinding.WEAK,
}


def _resolve_elf_symbols(elf: lief.ELF.Binary) -> SymbolTable:
    """Extract symbols from ELF binary."""
    symbols: list[Symbol] = []
    seen: set[tuple[str, int]] = set()

    for sym in elf.symbols:
        if not sym.name:
            continue
        key = (sym.name, sym.value)
        if key in seen:
            continue
        seen.add(key)

        section_name = ""
        try:
            if sym.shndx > 0 and sym.shndx < 0xFF00:
                section_name = sym.section.name
        except Exception:
            pass

        symbols.append(
            Symbol(
                name=sym.name,
                address=sym.value,
                sym_type=_ELF_TYPE_MAP.get(sym.type, SymbolType.UNKNOWN),
                binding=_ELF_BINDING_MAP.get(sym.binding, SymbolBinding.GLOBAL),
                section_name=section_name,
            )
        )

    return SymbolTable(symbols=symbols)


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------


def _resolve_pe_symbols(pe: lief.PE.Binary) -> SymbolTable:
    """Extract symbols from PE binary."""
    symbols: list[Symbol] = []

    for lib in pe.imports:
        for entry in lib.entries:
            name = f"ord#{entry.ordinal}" if entry.is_ordinal else entry.name
            if not name:
                continue
            symbols.append(
                Symbol(
                    name=name,
                    address=0,
                    sym_type=SymbolType.FUNCTION,
                    binding=SymbolBinding.GLOBAL,
                    section_name=lib.name,
                )
            )

    if pe.has_exports:
        for exp in pe.get_export().entries:
            name = exp.name if exp.name else f"ord#{exp.ordinal}"
            symbols.append(
                Symbol(
                    name=name,
                    address=exp.address,
                    sym_type=SymbolType.FUNCTION,
                    binding=SymbolBinding.GLOBAL,
                )
            )

    return SymbolTable(symbols=symbols)


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

_MACHO_TEXT_SECTIONS = frozenset(("__text", "__stubs", "__stub_helper"))
_MACHO_DATA_SECTIONS = frozenset(("__data", "__bss", "__common"))


def _resolve_macho_symbols(macho: lief.MachO.Binary) -> SymbolTable:
    """Extract symbols from Mach-O binary."""
    symbols: list[Symbol] = []

    # Build section list for n_sect → name lookup (n_sect is 1-based)
    sections = list(macho.sections)

    for sym in macho.symbols:
        if not sym.name:
            continue

        binding = SymbolBinding.GLOBAL if sym.is_external else SymbolBinding.LOCAL

        sym_type = SymbolType.UNKNOWN
        section_name = ""

        n_sect = sym.numberof_sections
        if 0 < n_sect <= len(sections):
            sec = sections[n_sect - 1]
            section_name = sec.name
            if section_name in _MACHO_TEXT_SECTIONS:
                sym_type = SymbolType.FUNCTION
            elif section_name in _MACHO_DATA_SECTIONS:
                sym_type = SymbolType.OBJECT

        symbols.append(
            Symbol(
                name=sym.name,
                address=sym.value,
                sym_type=sym_type,
                binding=binding,
                section_name=section_name,
            )
        )

    return SymbolTable(symbols=symbols)
