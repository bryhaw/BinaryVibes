"""Tests for the symbol resolution module."""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock

import lief
import pytest

from binaryvibes.analysis.symbols import (
    Symbol,
    SymbolBinding,
    SymbolTable,
    SymbolType,
    _resolve_elf_symbols,
    _resolve_macho_symbols,
    _resolve_pe_symbols,
    resolve_symbols,
)
from binaryvibes.core.binary import BinaryFile

# ── Helpers ─────────────────────────────────────────────────────────


def _make_test_table() -> SymbolTable:
    return SymbolTable(
        symbols=[
            Symbol("main", 0x401000, SymbolType.FUNCTION, SymbolBinding.GLOBAL, ".text"),
            Symbol("printf", 0x0, SymbolType.FUNCTION, SymbolBinding.GLOBAL, ""),
            Symbol("data_var", 0x402000, SymbolType.OBJECT, SymbolBinding.LOCAL, ".data"),
            Symbol("helper", 0x401100, SymbolType.FUNCTION, SymbolBinding.WEAK, ".text"),
        ]
    )


# ── Enum tests ──────────────────────────────────────────────────────


class TestSymbolType:
    def test_values(self):
        assert SymbolType.FUNCTION.value == "function"
        assert SymbolType.OBJECT.value == "object"
        assert SymbolType.UNKNOWN.value == "unknown"

    def test_members(self):
        assert set(SymbolType) == {
            SymbolType.FUNCTION,
            SymbolType.OBJECT,
            SymbolType.UNKNOWN,
        }


class TestSymbolBinding:
    def test_values(self):
        assert SymbolBinding.LOCAL.value == "local"
        assert SymbolBinding.GLOBAL.value == "global"
        assert SymbolBinding.WEAK.value == "weak"

    def test_members(self):
        assert set(SymbolBinding) == {
            SymbolBinding.LOCAL,
            SymbolBinding.GLOBAL,
            SymbolBinding.WEAK,
        }


# ── Symbol dataclass tests ─────────────────────────────────────────


class TestSymbol:
    def test_creation(self):
        sym = Symbol("foo", 0x1000, SymbolType.FUNCTION, SymbolBinding.GLOBAL, ".text")
        assert sym.name == "foo"
        assert sym.address == 0x1000
        assert sym.sym_type == SymbolType.FUNCTION
        assert sym.binding == SymbolBinding.GLOBAL
        assert sym.section_name == ".text"

    def test_default_section_name(self):
        sym = Symbol("bar", 0x0, SymbolType.UNKNOWN, SymbolBinding.LOCAL)
        assert sym.section_name == ""

    def test_frozen(self):
        sym = Symbol("baz", 0x2000, SymbolType.OBJECT, SymbolBinding.WEAK)
        with pytest.raises(AttributeError):
            sym.name = "changed"  # type: ignore[misc]

    def test_str_formatting(self):
        sym = Symbol("main", 0x401000, SymbolType.FUNCTION, SymbolBinding.GLOBAL, ".text")
        result = str(sym)
        assert "0x00401000" in result
        assert "global" in result
        assert "function" in result
        assert "main" in result

    def test_str_zero_address(self):
        sym = Symbol("printf", 0x0, SymbolType.FUNCTION, SymbolBinding.GLOBAL)
        result = str(sym)
        assert "0x00000000" in result
        assert "printf" in result


# ── SymbolTable tests ──────────────────────────────────────────────


class TestSymbolTableByName:
    def test_found(self):
        table = _make_test_table()
        sym = table.by_name("main")
        assert sym is not None
        assert sym.name == "main"
        assert sym.address == 0x401000

    def test_not_found(self):
        table = _make_test_table()
        assert table.by_name("nonexistent") is None


class TestSymbolTableByAddress:
    def test_found(self):
        table = _make_test_table()
        results = table.by_address(0x401000)
        assert len(results) == 1
        assert results[0].name == "main"

    def test_multiple_at_same_address(self):
        table = SymbolTable(
            symbols=[
                Symbol("a", 0x1000, SymbolType.FUNCTION, SymbolBinding.GLOBAL),
                Symbol("b", 0x1000, SymbolType.FUNCTION, SymbolBinding.WEAK),
            ]
        )
        results = table.by_address(0x1000)
        assert len(results) == 2
        names = {s.name for s in results}
        assert names == {"a", "b"}

    def test_not_found(self):
        table = _make_test_table()
        assert table.by_address(0xDEADBEEF) == []


class TestSymbolTableFilterType:
    def test_filter_function(self):
        table = _make_test_table()
        funcs = table.filter_type(SymbolType.FUNCTION)
        assert len(funcs) == 3
        assert all(s.sym_type == SymbolType.FUNCTION for s in funcs)

    def test_filter_object(self):
        table = _make_test_table()
        objs = table.filter_type(SymbolType.OBJECT)
        assert len(objs) == 1
        assert objs[0].name == "data_var"

    def test_filter_unknown_empty(self):
        table = _make_test_table()
        assert table.filter_type(SymbolType.UNKNOWN) == []


class TestSymbolTableFilterBinding:
    def test_filter_global(self):
        table = _make_test_table()
        globals_ = table.filter_binding(SymbolBinding.GLOBAL)
        assert len(globals_) == 2
        names = {s.name for s in globals_}
        assert names == {"main", "printf"}

    def test_filter_local(self):
        table = _make_test_table()
        locals_ = table.filter_binding(SymbolBinding.LOCAL)
        assert len(locals_) == 1
        assert locals_[0].name == "data_var"

    def test_filter_weak(self):
        table = _make_test_table()
        weak = table.filter_binding(SymbolBinding.WEAK)
        assert len(weak) == 1
        assert weak[0].name == "helper"


class TestSymbolTableProperties:
    def test_functions(self):
        table = _make_test_table()
        funcs = table.functions
        assert len(funcs) == 3
        names = {s.name for s in funcs}
        assert names == {"main", "printf", "helper"}

    def test_imports(self):
        """Imports are symbols with address == 0."""
        table = _make_test_table()
        imps = table.imports
        assert len(imps) == 1
        assert imps[0].name == "printf"
        assert imps[0].address == 0

    def test_exports(self):
        """Exports are non-local symbols with non-zero address."""
        table = _make_test_table()
        exps = table.exports
        # main (GLOBAL, 0x401000) and helper (WEAK, 0x401100)
        assert len(exps) == 2
        names = {s.name for s in exps}
        assert names == {"main", "helper"}


# ── Empty SymbolTable ──────────────────────────────────────────────


class TestEmptySymbolTable:
    def test_by_name(self):
        table = SymbolTable()
        assert table.by_name("anything") is None

    def test_by_address(self):
        table = SymbolTable()
        assert table.by_address(0x1000) == []

    def test_filter_type(self):
        table = SymbolTable()
        assert table.filter_type(SymbolType.FUNCTION) == []

    def test_filter_binding(self):
        table = SymbolTable()
        assert table.filter_binding(SymbolBinding.GLOBAL) == []

    def test_functions(self):
        table = SymbolTable()
        assert table.functions == []

    def test_imports(self):
        table = SymbolTable()
        assert table.imports == []

    def test_exports(self):
        table = SymbolTable()
        assert table.exports == []


# ── resolve_symbols integration ────────────────────────────────────


class TestResolveSymbols:
    def test_tiny_elf_returns_symbol_table(self, tiny_elf_binary):
        """Minimal ELF with no symbols → valid but likely empty table."""
        result = resolve_symbols(tiny_elf_binary)
        assert isinstance(result, SymbolTable)
        assert isinstance(result.symbols, list)

    def test_tiny_elf_operations_safe(self, tiny_elf_binary):
        """All table operations work even on a minimal binary."""
        table = resolve_symbols(tiny_elf_binary)
        assert table.by_name("nonexistent") is None
        assert table.by_address(0) == [] or isinstance(table.by_address(0), list)
        assert isinstance(table.functions, list)
        assert isinstance(table.imports, list)
        assert isinstance(table.exports, list)


# ── Short aliases for LIEF enum types ──────────────────────────────

_FUNC = lief.ELF.Symbol.TYPE.FUNC
_OBJ = lief.ELF.Symbol.TYPE.OBJECT
_GBIND = lief.ELF.Symbol.BINDING.GLOBAL
_LBIND = lief.ELF.Symbol.BINDING.LOCAL
_WBIND = lief.ELF.Symbol.BINDING.WEAK

# ── Mock helpers ───────────────────────────────────────────────────


def _mock_elf_symbol(
    name: str,
    value: int,
    sym_type=lief.ELF.Symbol.TYPE.FUNC,
    binding=lief.ELF.Symbol.BINDING.GLOBAL,
    shndx: int = 1,
    section_name: str = ".text",
    section_raises: bool = False,
):
    """Create a mock LIEF ELF symbol."""
    sym = MagicMock()
    sym.name = name
    sym.value = value
    sym.type = sym_type
    sym.binding = binding
    sym.shndx = shndx
    if section_raises:
        type(sym).section = PropertyMock(side_effect=Exception("no section"))
    else:
        sec = MagicMock()
        sec.name = section_name
        sym.section = sec
    return sym


def _mock_elf_binary(symbols):
    """Create a mock LIEF ELF.Binary with given symbols."""
    elf = MagicMock(spec=lief.ELF.Binary)
    elf.symbols = symbols
    # Make isinstance checks work
    elf.__class__ = lief.ELF.Binary
    return elf


def _mock_pe_import_entry(name: str, is_ordinal: bool = False, ordinal: int = 0):
    """Create a mock PE import entry."""
    entry = MagicMock()
    entry.name = name
    entry.is_ordinal = is_ordinal
    entry.ordinal = ordinal
    return entry


def _mock_pe_export_entry(name: str, address: int, ordinal: int = 0):
    """Create a mock PE export entry."""
    entry = MagicMock()
    entry.name = name
    entry.address = address
    entry.ordinal = ordinal
    return entry


def _mock_macho_symbol(
    name: str,
    value: int,
    is_external: bool = True,
    numberof_sections: int = 0,
):
    """Create a mock LIEF MachO symbol."""
    sym = MagicMock()
    sym.name = name
    sym.value = value
    sym.is_external = is_external
    sym.numberof_sections = numberof_sections
    return sym


# ── _resolve_elf_symbols direct tests ─────────────────────────────


class TestResolveElfSymbolsDirect:
    def test_basic_function_symbol(self):
        syms = [
            _mock_elf_symbol("main", 0x401000, _FUNC, _GBIND),
        ]
        elf = _mock_elf_binary(syms)
        table = _resolve_elf_symbols(elf)
        assert len(table.symbols) == 1
        s = table.symbols[0]
        assert s.name == "main"
        assert s.address == 0x401000
        assert s.sym_type == SymbolType.FUNCTION
        assert s.binding == SymbolBinding.GLOBAL
        assert s.section_name == ".text"

    def test_object_symbol(self):
        syms = [
            _mock_elf_symbol(
                "my_var",
                0x602000,
                _OBJ,
                _LBIND,
                section_name=".data",
            ),
        ]
        table = _resolve_elf_symbols(_mock_elf_binary(syms))
        s = table.symbols[0]
        assert s.sym_type == SymbolType.OBJECT
        assert s.binding == SymbolBinding.LOCAL
        assert s.section_name == ".data"

    def test_weak_binding(self):
        syms = [
            _mock_elf_symbol("weak_fn", 0x401100, _FUNC, _WBIND),
        ]
        table = _resolve_elf_symbols(_mock_elf_binary(syms))
        assert table.symbols[0].binding == SymbolBinding.WEAK

    def test_unknown_type_defaults_to_unknown(self):
        sym = _mock_elf_symbol("mystery", 0x500000)
        sym.type = MagicMock()  # Not in _ELF_TYPE_MAP
        table = _resolve_elf_symbols(_mock_elf_binary([sym]))
        assert table.symbols[0].sym_type == SymbolType.UNKNOWN

    def test_unknown_binding_defaults_to_global(self):
        sym = _mock_elf_symbol("mystery", 0x500000)
        sym.binding = MagicMock()  # Not in _ELF_BINDING_MAP
        table = _resolve_elf_symbols(_mock_elf_binary([sym]))
        assert table.symbols[0].binding == SymbolBinding.GLOBAL

    def test_empty_name_skipped(self):
        syms = [
            _mock_elf_symbol("", 0x401000),
            _mock_elf_symbol("real", 0x402000),
        ]
        table = _resolve_elf_symbols(_mock_elf_binary(syms))
        assert len(table.symbols) == 1
        assert table.symbols[0].name == "real"

    def test_duplicate_name_address_deduplicated(self):
        syms = [
            _mock_elf_symbol("dup", 0x401000),
            _mock_elf_symbol("dup", 0x401000),
        ]
        table = _resolve_elf_symbols(_mock_elf_binary(syms))
        assert len(table.symbols) == 1

    def test_same_name_different_address_kept(self):
        syms = [
            _mock_elf_symbol("overloaded", 0x401000),
            _mock_elf_symbol("overloaded", 0x402000),
        ]
        table = _resolve_elf_symbols(_mock_elf_binary(syms))
        assert len(table.symbols) == 2

    def test_section_name_with_special_shndx(self):
        """shndx >= 0xFF00 (special sections) → no section name."""
        sym = _mock_elf_symbol("special", 0x401000, shndx=0xFF00)
        table = _resolve_elf_symbols(_mock_elf_binary([sym]))
        assert table.symbols[0].section_name == ""

    def test_section_name_shndx_zero(self):
        """shndx == 0 (SHN_UNDEF) → no section name."""
        sym = _mock_elf_symbol("undef", 0x0, shndx=0)
        table = _resolve_elf_symbols(_mock_elf_binary([sym]))
        assert table.symbols[0].section_name == ""

    def test_section_access_raises(self):
        """If accessing sym.section raises, section_name stays empty."""
        sym = _mock_elf_symbol("broken_sec", 0x401000, shndx=5, section_raises=True)
        table = _resolve_elf_symbols(_mock_elf_binary([sym]))
        assert table.symbols[0].section_name == ""
        assert table.symbols[0].name == "broken_sec"

    def test_multiple_symbols_mixed(self):
        syms = [
            _mock_elf_symbol("func1", 0x401000, _FUNC, _GBIND),
            _mock_elf_symbol("var1", 0x602000, _OBJ, _LBIND, section_name=".bss"),
            _mock_elf_symbol("weak_sym", 0x401100, _FUNC, _WBIND),
            _mock_elf_symbol("", 0x0),  # skipped
            _mock_elf_symbol("imported", 0x0, _FUNC, _GBIND, shndx=0),
        ]
        table = _resolve_elf_symbols(_mock_elf_binary(syms))
        assert len(table.symbols) == 4
        assert table.by_name("func1") is not None
        assert table.by_name("var1") is not None
        assert table.by_name("weak_sym") is not None
        assert table.by_name("imported") is not None

    def test_no_symbols_returns_empty_table(self):
        table = _resolve_elf_symbols(_mock_elf_binary([]))
        assert len(table.symbols) == 0


# ── _resolve_pe_symbols direct tests ──────────────────────────────


class TestResolvePeSymbolsDirect:
    def test_import_by_name(self):
        entry = _mock_pe_import_entry("CreateFileW", is_ordinal=False)
        lib = MagicMock()
        lib.name = "kernel32.dll"
        lib.entries = [entry]

        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = [lib]
        pe.has_exports = False

        table = _resolve_pe_symbols(pe)
        assert len(table.symbols) == 1
        s = table.symbols[0]
        assert s.name == "CreateFileW"
        assert s.address == 0
        assert s.sym_type == SymbolType.FUNCTION
        assert s.binding == SymbolBinding.GLOBAL
        assert s.section_name == "kernel32.dll"

    def test_import_by_ordinal(self):
        entry = _mock_pe_import_entry("", is_ordinal=True, ordinal=42)
        lib = MagicMock()
        lib.name = "user32.dll"
        lib.entries = [entry]

        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = [lib]
        pe.has_exports = False

        table = _resolve_pe_symbols(pe)
        assert len(table.symbols) == 1
        assert table.symbols[0].name == "ord#42"

    def test_import_empty_name_non_ordinal_skipped(self):
        entry = _mock_pe_import_entry("", is_ordinal=False)
        lib = MagicMock()
        lib.name = "lib.dll"
        lib.entries = [entry]

        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = [lib]
        pe.has_exports = False

        table = _resolve_pe_symbols(pe)
        assert len(table.symbols) == 0

    def test_exports_with_name(self):
        exp = _mock_pe_export_entry("MyExport", 0x10000, ordinal=1)

        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = []
        pe.has_exports = True
        export_obj = MagicMock()
        export_obj.entries = [exp]
        pe.get_export.return_value = export_obj

        table = _resolve_pe_symbols(pe)
        assert len(table.symbols) == 1
        s = table.symbols[0]
        assert s.name == "MyExport"
        assert s.address == 0x10000
        assert s.sym_type == SymbolType.FUNCTION
        assert s.binding == SymbolBinding.GLOBAL

    def test_exports_without_name_uses_ordinal(self):
        exp = _mock_pe_export_entry("", 0x20000, ordinal=99)

        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = []
        pe.has_exports = True
        export_obj = MagicMock()
        export_obj.entries = [exp]
        pe.get_export.return_value = export_obj

        table = _resolve_pe_symbols(pe)
        assert table.symbols[0].name == "ord#99"

    def test_imports_and_exports_combined(self):
        imp_entry = _mock_pe_import_entry("ReadFile")
        lib = MagicMock()
        lib.name = "kernel32.dll"
        lib.entries = [imp_entry]

        exp_entry = _mock_pe_export_entry("DllMain", 0x1000)

        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = [lib]
        pe.has_exports = True
        export_obj = MagicMock()
        export_obj.entries = [exp_entry]
        pe.get_export.return_value = export_obj

        table = _resolve_pe_symbols(pe)
        assert len(table.symbols) == 2
        assert table.by_name("ReadFile") is not None
        assert table.by_name("DllMain") is not None

    def test_no_imports_no_exports(self):
        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = []
        pe.has_exports = False

        table = _resolve_pe_symbols(pe)
        assert len(table.symbols) == 0

    def test_multiple_libraries(self):
        lib1 = MagicMock()
        lib1.name = "kernel32.dll"
        lib1.entries = [_mock_pe_import_entry("WriteFile")]

        lib2 = MagicMock()
        lib2.name = "user32.dll"
        lib2.entries = [_mock_pe_import_entry("MessageBoxA"), _mock_pe_import_entry("ShowWindow")]

        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = [lib1, lib2]
        pe.has_exports = False

        table = _resolve_pe_symbols(pe)
        assert len(table.symbols) == 3
        names = {s.name for s in table.symbols}
        assert names == {"WriteFile", "MessageBoxA", "ShowWindow"}


# ── _resolve_macho_symbols direct tests ───────────────────────────


class TestResolveMachoSymbolsDirect:
    def _mock_macho_binary(self, symbols, sections=None):
        macho = MagicMock(spec=lief.MachO.Binary)
        macho.__class__ = lief.MachO.Binary
        macho.symbols = symbols
        if sections is None:
            sections = []
        macho.sections = sections
        return macho

    def _mock_section(self, name: str):
        sec = MagicMock()
        sec.name = name
        return sec

    def test_external_symbol_text_section(self):
        sections = [self._mock_section("__text")]
        sym = _mock_macho_symbol("_main", 0x100000, is_external=True, numberof_sections=1)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert len(table.symbols) == 1
        s = table.symbols[0]
        assert s.name == "_main"
        assert s.address == 0x100000
        assert s.sym_type == SymbolType.FUNCTION
        assert s.binding == SymbolBinding.GLOBAL
        assert s.section_name == "__text"

    def test_local_symbol(self):
        sym = _mock_macho_symbol("_local_fn", 0x100100, is_external=False, numberof_sections=0)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym]))
        assert table.symbols[0].binding == SymbolBinding.LOCAL

    def test_data_section_maps_to_object(self):
        sections = [self._mock_section("__text"), self._mock_section("__data")]
        sym = _mock_macho_symbol("_my_data", 0x200000, is_external=True, numberof_sections=2)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert table.symbols[0].sym_type == SymbolType.OBJECT
        assert table.symbols[0].section_name == "__data"

    def test_bss_section_maps_to_object(self):
        sections = [self._mock_section("__bss")]
        sym = _mock_macho_symbol("_bss_var", 0x300000, numberof_sections=1)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert table.symbols[0].sym_type == SymbolType.OBJECT

    def test_common_section_maps_to_object(self):
        sections = [self._mock_section("__common")]
        sym = _mock_macho_symbol("_common_var", 0x300000, numberof_sections=1)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert table.symbols[0].sym_type == SymbolType.OBJECT

    def test_stubs_section_maps_to_function(self):
        sections = [self._mock_section("__stubs")]
        sym = _mock_macho_symbol("_stub_fn", 0x100200, numberof_sections=1)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert table.symbols[0].sym_type == SymbolType.FUNCTION

    def test_stub_helper_section_maps_to_function(self):
        sections = [self._mock_section("__stub_helper")]
        sym = _mock_macho_symbol("_helper", 0x100300, numberof_sections=1)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert table.symbols[0].sym_type == SymbolType.FUNCTION

    def test_unknown_section_maps_to_unknown(self):
        sections = [self._mock_section("__objc_classlist")]
        sym = _mock_macho_symbol("_objc_thing", 0x400000, numberof_sections=1)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert table.symbols[0].sym_type == SymbolType.UNKNOWN

    def test_no_section_maps_to_unknown(self):
        sym = _mock_macho_symbol("_nosect", 0x0, numberof_sections=0)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym]))
        assert table.symbols[0].sym_type == SymbolType.UNKNOWN
        assert table.symbols[0].section_name == ""

    def test_nsect_out_of_range(self):
        sections = [self._mock_section("__text")]
        sym = _mock_macho_symbol("_bad_sect", 0x100000, numberof_sections=5)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym], sections))
        assert table.symbols[0].sym_type == SymbolType.UNKNOWN
        assert table.symbols[0].section_name == ""

    def test_empty_name_skipped(self):
        sym = _mock_macho_symbol("", 0x100000)
        table = _resolve_macho_symbols(self._mock_macho_binary([sym]))
        assert len(table.symbols) == 0

    def test_no_symbols(self):
        table = _resolve_macho_symbols(self._mock_macho_binary([]))
        assert len(table.symbols) == 0

    def test_multiple_symbols_mixed(self):
        sections = [self._mock_section("__text"), self._mock_section("__data")]
        syms = [
            _mock_macho_symbol("_func1", 0x100000, is_external=True, numberof_sections=1),
            _mock_macho_symbol("_data1", 0x200000, is_external=False, numberof_sections=2),
            _mock_macho_symbol("_import", 0x0, is_external=True, numberof_sections=0),
        ]
        table = _resolve_macho_symbols(self._mock_macho_binary(syms, sections))
        assert len(table.symbols) == 3
        assert table.by_name("_func1").sym_type == SymbolType.FUNCTION
        assert table.by_name("_data1").sym_type == SymbolType.OBJECT
        assert table.by_name("_import").sym_type == SymbolType.UNKNOWN


# ── resolve_symbols dispatch tests ────────────────────────────────


class TestResolveSymbolsDispatch:
    def _make_binary(self, lief_obj):
        bf = MagicMock(spec=BinaryFile)
        bf.lief = lief_obj
        return bf

    def test_dispatches_to_elf(self):
        elf = _mock_elf_binary([_mock_elf_symbol("test_fn", 0x401000)])
        bf = self._make_binary(elf)
        table = resolve_symbols(bf)
        assert isinstance(table, SymbolTable)
        assert len(table.symbols) == 1
        assert table.symbols[0].name == "test_fn"

    def test_dispatches_to_pe(self):
        pe = MagicMock(spec=lief.PE.Binary)
        pe.__class__ = lief.PE.Binary
        pe.imports = []
        pe.has_exports = False
        bf = self._make_binary(pe)
        table = resolve_symbols(bf)
        assert isinstance(table, SymbolTable)
        assert len(table.symbols) == 0

    def test_dispatches_to_macho(self):
        macho = MagicMock(spec=lief.MachO.Binary)
        macho.__class__ = lief.MachO.Binary
        macho.symbols = []
        macho.sections = []
        bf = self._make_binary(macho)
        table = resolve_symbols(bf)
        assert isinstance(table, SymbolTable)
        assert len(table.symbols) == 0

    def test_unknown_format_returns_empty(self):
        unknown = MagicMock()
        # Not ELF, PE, or MachO
        unknown.__class__ = type("SomethingElse", (), {})
        bf = self._make_binary(unknown)
        table = resolve_symbols(bf)
        assert isinstance(table, SymbolTable)
        assert len(table.symbols) == 0

    def test_lief_raises_value_error(self):
        bf = MagicMock(spec=BinaryFile)
        type(bf).lief = PropertyMock(side_effect=ValueError("LIEF could not parse"))
        with pytest.raises(ValueError, match="LIEF could not parse"):
            resolve_symbols(bf)


# ── from_bytes with unparseable data ──────────────────────────────


class TestResolveSymbolsFromBytes:
    def test_garbage_data_raises(self):
        bf = BinaryFile.from_bytes(b"\x00\x01\x02\x03garbage", name="garbage.bin")
        with pytest.raises(ValueError, match="LIEF could not parse"):
            resolve_symbols(bf)

    def test_empty_bytes_raises(self):
        bf = BinaryFile.from_bytes(b"", name="empty.bin")
        with pytest.raises(ValueError, match="LIEF could not parse"):
            resolve_symbols(bf)


# ── SymbolTable with mixed imports/exports/locals ─────────────────


class TestSymbolTableMixed:
    def test_mixed_imports_exports_locals(self):
        table = SymbolTable(
            symbols=[
                Symbol("imp1", 0x0, SymbolType.FUNCTION, SymbolBinding.GLOBAL, "lib.dll"),
                Symbol("imp2", 0x0, SymbolType.FUNCTION, SymbolBinding.GLOBAL, "lib.dll"),
                Symbol("exp1", 0x1000, SymbolType.FUNCTION, SymbolBinding.GLOBAL, ".text"),
                Symbol("exp2", 0x2000, SymbolType.OBJECT, SymbolBinding.WEAK, ".data"),
                Symbol("local1", 0x3000, SymbolType.FUNCTION, SymbolBinding.LOCAL, ".text"),
                Symbol("local2", 0x4000, SymbolType.OBJECT, SymbolBinding.LOCAL, ".data"),
            ]
        )
        assert len(table.imports) == 2
        assert {s.name for s in table.imports} == {"imp1", "imp2"}
        assert len(table.exports) == 2
        assert {s.name for s in table.exports} == {"exp1", "exp2"}
        locals_ = table.filter_binding(SymbolBinding.LOCAL)
        assert len(locals_) == 2
        assert {s.name for s in locals_} == {"local1", "local2"}

    def test_local_with_zero_address_is_import_not_export(self):
        sym = Symbol("local_imp", 0x0, SymbolType.FUNCTION, SymbolBinding.LOCAL)
        table = SymbolTable(symbols=[sym])
        assert len(table.imports) == 1
        assert len(table.exports) == 0

    def test_global_with_nonzero_address_is_export(self):
        sym = Symbol("global_exp", 0x5000, SymbolType.FUNCTION, SymbolBinding.GLOBAL)
        table = SymbolTable(symbols=[sym])
        assert len(table.imports) == 0
        assert len(table.exports) == 1

    def test_weak_with_nonzero_address_is_export(self):
        sym = Symbol("weak_exp", 0x6000, SymbolType.FUNCTION, SymbolBinding.WEAK)
        table = SymbolTable(symbols=[sym])
        assert len(table.exports) == 1


# ── ELF type/binding mapping edge cases ───────────────────────────


class TestElfMappingEdgeCases:
    def test_all_elf_type_mappings(self):
        """Verify each ELF type maps correctly."""
        for elf_type, expected in [
            (lief.ELF.Symbol.TYPE.FUNC, SymbolType.FUNCTION),
            (lief.ELF.Symbol.TYPE.OBJECT, SymbolType.OBJECT),
        ]:
            sym = _mock_elf_symbol("s", 0x1000, sym_type=elf_type)
            table = _resolve_elf_symbols(_mock_elf_binary([sym]))
            assert table.symbols[0].sym_type == expected, f"Failed for {elf_type}"

    def test_all_elf_binding_mappings(self):
        """Verify each ELF binding maps correctly."""
        for elf_bind, expected in [
            (lief.ELF.Symbol.BINDING.GLOBAL, SymbolBinding.GLOBAL),
            (lief.ELF.Symbol.BINDING.LOCAL, SymbolBinding.LOCAL),
            (lief.ELF.Symbol.BINDING.WEAK, SymbolBinding.WEAK),
        ]:
            sym = _mock_elf_symbol("s", 0x1000, binding=elf_bind)
            table = _resolve_elf_symbols(_mock_elf_binary([sym]))
            assert table.symbols[0].binding == expected, f"Failed for {elf_bind}"
