"""Tests for BinaryVibes CLI commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from binaryvibes.cli.main import cli


def _run(*args: str) -> object:
    """Invoke the CLI and return the result."""
    return CliRunner().invoke(cli, list(args))


# ── Top-level CLI tests ─────────────────────────────────────────────


def test_cli_version():
    result = _run("--version")
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_cli_help():
    result = _run("--help")
    assert result.exit_code == 0
    assert "BinaryVibes" in result.output


# ── info command ────────────────────────────────────────────────────


def test_info_command(tiny_elf: Path):
    result = _run("info", str(tiny_elf))
    assert result.exit_code == 0
    assert "x86_64" in result.output
    assert "bytes" in result.output


def test_info_nonexistent():
    result = _run("info", "nonexistent_file")
    assert result.exit_code != 0


def test_info_help():
    result = _run("info", "--help")
    assert result.exit_code == 0


# ── disasm command ──────────────────────────────────────────────────


def test_disasm_command(tiny_elf: Path):
    result = _run("disasm", str(tiny_elf), "-o", "0", "-n", "10")
    assert result.exit_code == 0
    assert result.output.strip() != ""


def test_disasm_with_arch(tiny_elf: Path):
    result = _run("disasm", str(tiny_elf), "-a", "x86_64")
    assert result.exit_code == 0


def test_disasm_zero_count(tiny_elf: Path):
    result = _run("disasm", str(tiny_elf), "-n", "0")
    assert result.exit_code == 0
    lines = [
        line
        for line in result.output.strip().splitlines()
        if not line.startswith("The current binary")
    ]
    assert lines == []


def test_disasm_help():
    result = _run("disasm", "--help")
    assert result.exit_code == 0


# ── build command ───────────────────────────────────────────────────


def test_build_command_missing_api_key(monkeypatch):
    """bv build should fail gracefully when no API key is configured."""
    monkeypatch.delenv("BV_LLM_API_KEY", raising=False)
    monkeypatch.delenv("BV_LLM_PROVIDER", raising=False)
    result = _run("build", "a program that exits with code 42")
    assert result.exit_code == 1
    assert "API key" in result.output or "Configuration error" in result.output
