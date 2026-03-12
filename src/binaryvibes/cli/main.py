"""BinaryVibes CLI."""

from __future__ import annotations

import click

from binaryvibes.core.arch import Arch


@click.group()
@click.version_option()
def cli() -> None:
    """BinaryVibes — direct binary manipulation toolkit."""


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def info(path: str) -> None:
    """Display metadata for a binary file."""
    from binaryvibes.core.binary import BinaryFile

    bf = BinaryFile.from_path(path)
    click.echo(f"Path:   {bf.path}")
    click.echo(f"Size:   {len(bf.raw)} bytes")
    click.echo(f"Format: {bf.format_name}")
    click.echo(f"Arch:   {bf.arch.value if bf.arch else 'unknown'}")


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--offset", "-o", default=0, help="Start offset in the binary")
@click.option("--count", "-n", default=50, help="Max number of bytes to disassemble")
@click.option("--arch", "-a", default="x86_64", type=click.Choice([a.value for a in Arch]))
def disasm(path: str, offset: int, count: int, arch: str) -> None:
    """Disassemble a region of a binary."""
    from binaryvibes.analysis.disassembler import Disassembler
    from binaryvibes.core.binary import BinaryFile

    bf = BinaryFile.from_path(path)
    target_arch = Arch(arch) if arch else bf.arch
    if target_arch is None:
        click.echo("Could not detect architecture. Use --arch.", err=True)
        raise SystemExit(1)
    dis = Disassembler(target_arch)
    code = bf.raw[offset : offset + count]
    for insn in dis.disassemble(code, base_addr=offset):
        click.echo(insn)


@cli.command()
@click.argument("asm")
@click.option("--arch", "-a", default="x86_64", type=click.Choice([a.value for a in Arch]))
@click.option("--base-addr", "-b", default=0, help="Base address for assembly")
def assemble(asm: str, arch: str, base_addr: int) -> None:
    """Assemble mnemonics to hex bytes."""
    from binaryvibes.synthesis.assembler import Assembler

    try:
        assembler = Assembler(Arch(arch))
        code = assembler.assemble(asm, base_addr=base_addr)
        click.echo(code.hex())
    except Exception as exc:
        click.echo(f"Assembly error: {exc}", err=True)
        raise SystemExit(1) from None


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--offset", "-o", required=True, type=str, help="Offset to patch (hex or decimal)")
@click.option("--hex", "hex_data", required=True, help="Hex string of bytes to write")
@click.option("--output", "-O", required=True, type=click.Path(), help="Output file path")
def patch(path: str, offset: str, hex_data: str, output: str) -> None:
    """Apply a hex patch to a binary."""
    from binaryvibes.core.binary import BinaryFile
    from binaryvibes.synthesis.patcher import Patch, apply_patches

    try:
        patch_offset = int(offset, 0)
        patch_bytes = bytes.fromhex(hex_data)
    except ValueError as exc:
        click.echo(f"Invalid input: {exc}", err=True)
        raise SystemExit(1) from None

    try:
        bf = BinaryFile.from_path(path)
        p = Patch(offset=patch_offset, data=patch_bytes, description="CLI patch")
        result = apply_patches(bf, [p])
        with open(output, "wb") as f:
            f.write(result)
        click.echo(f"Patched {len(patch_bytes)} bytes at offset {offset} → {output}")
    except Exception as exc:
        click.echo(f"Patch error: {exc}", err=True)
        raise SystemExit(1) from None


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--offset", "-o", default=0, help="Start offset in the binary")
@click.option("--count", "-n", default=100, help="Number of bytes to emulate")
@click.option("--arch", "-a", default="x86_64", type=click.Choice([a.value for a in Arch]))
@click.option("--max-instructions", "-m", default=1000, help="Max instructions to execute")
def emulate(path: str, offset: int, count: int, arch: str, max_instructions: int) -> None:
    """Run a code region through the emulator."""
    from binaryvibes.core.binary import BinaryFile
    from binaryvibes.verify.emulator import Emulator

    try:
        bf = BinaryFile.from_path(path)
        code = bf.raw[offset : offset + count]
        emu = Emulator(Arch(arch))
        result = emu.run(code, base=offset or 0x400000, max_instructions=max_instructions)
        if result.error:
            click.echo(f"Emulation error: {result.error}", err=True)
        click.echo(f"Instructions executed: {result.instructions_executed}")
        click.echo("Registers:")
        for reg, val in sorted(result.final_registers.items()):
            click.echo(f"  {reg}: 0x{val:x}")
    except Exception as exc:
        click.echo(f"Emulation failed: {exc}", err=True)
        raise SystemExit(1) from None


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--offset", "-o", default=0, help="Start offset in the binary")
@click.option("--count", "-n", default=200, help="Number of bytes to analyse")
@click.option("--arch", "-a", default="x86_64", type=click.Choice([a.value for a in Arch]))
def cfg(path: str, offset: int, count: int, arch: str) -> None:
    """Show basic blocks for a code region."""
    from binaryvibes.analysis.cfg import CFGBuilder
    from binaryvibes.analysis.disassembler import Disassembler
    from binaryvibes.core.binary import BinaryFile

    try:
        bf = BinaryFile.from_path(path)
        target_arch = Arch(arch)
        dis = Disassembler(target_arch)
        code = bf.raw[offset : offset + count]
        instructions = list(dis.disassemble(code, base_addr=offset))
        builder = CFGBuilder()
        graph = builder.build(instructions)
        click.echo(f"Blocks: {graph.block_count}  Edges: {graph.edge_count}")
        for addr in sorted(graph.blocks):
            block = graph.blocks[addr]
            click.echo(
                f"  BB 0x{block.start_addr:x}-0x{block.end_addr:x} "
                f"({block.instruction_count} insns) → "
                f"{[f'0x{s:x}' for s in block.successor_addrs]}"
            )
        for edge in graph.edges:
            click.echo(f"  Edge 0x{edge.source:x} → 0x{edge.target:x} [{edge.edge_type.value}]")
    except Exception as exc:
        click.echo(f"CFG build error: {exc}", err=True)
        raise SystemExit(1) from None


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def symbols(path: str) -> None:
    """List symbols in a binary."""
    from binaryvibes.analysis.symbols import resolve_symbols
    from binaryvibes.core.binary import BinaryFile

    try:
        bf = BinaryFile.from_path(path)
        table = resolve_symbols(bf)
        if not table.symbols:
            click.echo("No symbols found.")
            return
        click.echo(f"{'Name':<40} {'Address':>18} {'Type':<10} {'Binding':<8}")
        click.echo("-" * 80)
        for sym in table.symbols:
            click.echo(
                f"{sym.name:<40} 0x{sym.address:016x} "
                f"{sym.sym_type.value:<10} {sym.binding.value:<8}"
            )
    except Exception as exc:
        click.echo(f"Symbol resolution error: {exc}", err=True)
        raise SystemExit(1) from None


@cli.command()
@click.argument("path_a", type=click.Path(exists=True))
@click.argument("path_b", type=click.Path(exists=True))
def diff(path_a: str, path_b: str) -> None:
    """Compare two binaries."""
    from binaryvibes.analysis.differ import hex_dump_diff
    from binaryvibes.core.binary import BinaryFile

    try:
        a = BinaryFile.from_path(path_a)
        b = BinaryFile.from_path(path_b)
        output = hex_dump_diff(a, b)
        click.echo(output)
    except Exception as exc:
        click.echo(f"Diff error: {exc}", err=True)
        raise SystemExit(1) from None


@cli.command()
@click.option("--arch", "-a", default="x86_64", type=click.Choice([a.value for a in Arch]))
@click.option("--asm", required=True, help="Assembly instructions for the binary")
@click.option("--output", "-O", required=True, type=click.Path(), help="Output file path")
def generate(arch: str, asm: str, output: str) -> None:
    """Generate a minimal binary from assembly."""
    from binaryvibes.synthesis.assembler import Assembler
    from binaryvibes.synthesis.generator import BinaryBuilder

    try:
        target_arch = Arch(arch)
        assembler = Assembler(target_arch)
        code = assembler.assemble(asm)
        builder = BinaryBuilder()
        bf = builder.set_arch(target_arch).add_code(code).build()
        with open(output, "wb") as f:
            f.write(bf.raw)
        click.echo(f"Generated {len(bf.raw)} byte binary → {output}")
    except Exception as exc:
        click.echo(f"Generate error: {exc}", err=True)
        raise SystemExit(1) from None
