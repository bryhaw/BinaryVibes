"""Tests for expanded BinaryVibes CLI commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from binaryvibes.cli.main import cli

runner = CliRunner()


def _run(*args: str):
    """Invoke the CLI and return the result."""
    return runner.invoke(cli, list(args))


# ── assemble command ────────────────────────────────────────────────


def test_assemble_nop():
    result = _run("assemble", "nop")
    assert result.exit_code == 0
    # nop assembles to 0x90 on x86_64
    output = result.output.strip()
    assert len(output) > 0
    # Output should be valid hex
    int(output, 16)


def test_assemble_with_arch():
    result = _run("assemble", "nop", "--arch", "x86_64")
    assert result.exit_code == 0
    assert result.output.strip() != ""


def test_assemble_invalid():
    result = _run("assemble", "invalid_xyz_not_real_instruction")
    assert result.exit_code != 0


def test_assemble_help():
    result = _run("assemble", "--help")
    assert result.exit_code == 0
    assert "assemble" in result.output.lower() or "asm" in result.output.lower()


# ── patch command ───────────────────────────────────────────────────


def test_patch_command(tiny_elf: Path, tmp_path: Path):
    output_file = tmp_path / "patched_elf"
    result = _run(
        "patch",
        str(tiny_elf),
        "--offset",
        "0",
        "--hex",
        "90",
        "--output",
        str(output_file),
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert output_file.stat().st_size > 0


def test_patch_help():
    result = _run("patch", "--help")
    assert result.exit_code == 0
    assert "patch" in result.output.lower() or "hex" in result.output.lower()


# ── emulate command ─────────────────────────────────────────────────


def test_emulate_command(tiny_elf: Path):
    result = _run(
        "emulate",
        str(tiny_elf),
        "--offset",
        "0",
        "--count",
        "20",
    )
    assert result.exit_code == 0
    assert "Registers" in result.output or "register" in result.output.lower()


def test_emulate_help():
    result = _run("emulate", "--help")
    assert result.exit_code == 0
    assert "emulate" in result.output.lower()


# ── cfg command ─────────────────────────────────────────────────────


def test_cfg_command(tiny_elf: Path):
    result = _run("cfg", str(tiny_elf), "--offset", "0", "--count", "20")
    assert result.exit_code == 0
    assert "Block" in result.output or "BB" in result.output or "block" in result.output.lower()


def test_cfg_help():
    result = _run("cfg", "--help")
    assert result.exit_code == 0
    assert "cfg" in result.output.lower() or "block" in result.output.lower()


# ── symbols command ─────────────────────────────────────────────────


def test_symbols_command(tiny_elf: Path):
    result = _run("symbols", str(tiny_elf))
    assert result.exit_code == 0
    # The tiny ELF has no symbols, so we expect "No symbols found."
    assert "symbol" in result.output.lower() or "Name" in result.output


def test_symbols_help():
    result = _run("symbols", "--help")
    assert result.exit_code == 0
    assert "symbol" in result.output.lower()


# ── diff command ────────────────────────────────────────────────────


def test_diff_identical(tiny_elf: Path):
    result = _run("diff", str(tiny_elf), str(tiny_elf))
    assert result.exit_code == 0
    assert "identical" in result.output.lower()


def test_diff_help():
    result = _run("diff", "--help")
    assert result.exit_code == 0
    assert "diff" in result.output.lower() or "compare" in result.output.lower()


# ── generate command ────────────────────────────────────────────────


def test_generate_command(tmp_path: Path):
    output_file = tmp_path / "generated_bin"
    result = _run(
        "generate",
        "--asm",
        "nop",
        "--output",
        str(output_file),
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert output_file.stat().st_size > 0
    assert "Generated" in result.output


def test_generate_help():
    result = _run("generate", "--help")
    assert result.exit_code == 0
    assert "generate" in result.output.lower()
