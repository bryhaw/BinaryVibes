"""Security audit workflow — find potential vulnerabilities in binaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from binaryvibes.analysis.cfg import CFGBuilder
from binaryvibes.analysis.disassembler import Disassembler
from binaryvibes.analysis.patterns import Pattern, PatternMatcher
from binaryvibes.analysis.symbols import resolve_symbols
from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    DANGEROUS_IMPORT = "dangerous_import"
    UNCHECKED_CALL = "unchecked_call"
    NOP_SLED = "nop_sled"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    COMPLEXITY = "complexity"


@dataclass(frozen=True)
class Finding:
    """A single audit finding."""

    category: FindingCategory
    severity: Severity
    offset: int
    description: str
    recommendation: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.value:8s}] 0x{self.offset:08x} {self.description}"


@dataclass
class AuditReport:
    """Complete audit report for a binary."""

    binary_name: str
    binary_size: int
    arch: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def by_category(self, category: FindingCategory) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        parts = [f"Audit of {self.binary_name} ({self.binary_size}B, {self.arch})"]
        parts.append(f"Total findings: {self.finding_count}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                parts.append(f"  {sev}: {counts[sev]}")
        return "\n".join(parts)

    def detailed_report(self) -> str:
        lines = [self.summary(), "", "--- Findings ---"]
        for sev in Severity:
            findings = self.by_severity(sev)
            if findings:
                lines.append(f"\n{sev.value.upper()}:")
                for f in findings:
                    lines.append(f"  {f}")
                    if f.recommendation:
                        lines.append(f"    → {f.recommendation}")
        return "\n".join(lines)


# Known dangerous C library functions
DANGEROUS_IMPORTS: dict[str, tuple[Severity, str, str]] = {
    "gets": (Severity.CRITICAL, "Buffer overflow — no bounds checking", "Replace with fgets()"),
    "strcpy": (Severity.HIGH, "Buffer overflow if src > dst", "Use strncpy() or strlcpy()"),
    "strcat": (Severity.HIGH, "Buffer overflow if combined > dst", "Use strncat() or strlcat()"),
    "sprintf": (
        Severity.HIGH,
        "Buffer overflow — no length limit",
        "Use snprintf()",
    ),
    "scanf": (Severity.MEDIUM, "Buffer overflow with %s", "Use width specifier or fgets()"),
    "system": (Severity.MEDIUM, "Command injection risk", "Use execve() with validated args"),
    "exec": (Severity.MEDIUM, "Command execution", "Validate all arguments"),
    "mktemp": (Severity.MEDIUM, "Race condition (TOCTOU)", "Use mkstemp()"),
    "tmpnam": (Severity.MEDIUM, "Race condition", "Use tmpfile() or mkstemp()"),
    "rand": (
        Severity.LOW,
        "Weak PRNG — not suitable for crypto",
        "Use getrandom() or /dev/urandom",
    ),
    "srand": (Severity.LOW, "Weak PRNG seeding", "Use getrandom()"),
}


def audit_binary(
    binary: BinaryFile,
    arch: Arch | None = None,
    *,
    check_imports: bool = True,
    check_patterns: bool = True,
    check_cfg: bool = True,
    code_offset: int = 0,
    code_size: int | None = None,
) -> AuditReport:
    """Run a security audit on a binary.

    Args:
        binary: Binary to audit.
        arch: Architecture (auto-detected if *None*).
        check_imports: Check for dangerous imported functions.
        check_patterns: Check for suspicious code patterns.
        check_cfg: Check control flow complexity.
        code_offset: Start of code to analyse (byte offset in *raw*).
        code_size: Size of code region (*None* = rest of binary).
    """
    detected_arch = arch or binary.arch or Arch.X86_64
    report = AuditReport(
        binary_name=str(binary.path) if binary.path else "unknown",
        binary_size=len(binary.raw),
        arch=detected_arch.value,
    )

    if check_imports:
        _check_dangerous_imports(binary, report)

    if check_patterns:
        _check_patterns(binary, detected_arch, report, code_offset, code_size)

    if check_cfg:
        _check_cfg_complexity(binary, detected_arch, report, code_offset, code_size)

    # Sort findings by severity (critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    report.findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return report


# ------------------------------------------------------------------
# Internal checkers
# ------------------------------------------------------------------


def _check_dangerous_imports(binary: BinaryFile, report: AuditReport) -> None:
    """Check for known dangerous imported functions."""
    try:
        symbols = resolve_symbols(binary)
    except (ValueError, Exception):
        return

    for sym in symbols.imports:
        name = sym.name.lstrip("_")  # Handle _gets vs gets
        if name in DANGEROUS_IMPORTS:
            sev, desc, rec = DANGEROUS_IMPORTS[name]
            report.findings.append(
                Finding(
                    category=FindingCategory.DANGEROUS_IMPORT,
                    severity=sev,
                    offset=sym.address,
                    description=f"Dangerous import: {sym.name} — {desc}",
                    recommendation=rec,
                )
            )


def _check_patterns(
    binary: BinaryFile,
    arch: Arch,
    report: AuditReport,
    code_offset: int,
    code_size: int | None,
) -> None:
    """Check for suspicious code patterns (NOP sleds, unchecked calls)."""
    dis = Disassembler(arch)
    end = code_offset + code_size if code_size else len(binary.raw)
    code = binary.raw[code_offset:end]
    if not code:
        return

    base_addr = code_offset
    instructions = dis.disassemble(code, base_addr)
    if not instructions:
        return

    matcher = PatternMatcher()

    # NOP sled — 5+ consecutive NOPs may be a shellcode landing zone
    nop_pattern = Pattern.parse("nop ; nop ; nop ; nop ; nop")
    for m in matcher.search(instructions, nop_pattern):
        report.findings.append(
            Finding(
                category=FindingCategory.NOP_SLED,
                severity=Severity.MEDIUM,
                offset=m.start_addr,
                description=(
                    f"NOP sled detected ({m.end_index - m.start_index}+ NOPs at 0x{m.start_addr:x})"
                ),
                recommendation="Investigate — may be padding or shellcode landing zone",
            )
        )

    # Call without checking return value
    for i, instr in enumerate(instructions):
        if instr.mnemonic in ("call", "callq") and i + 1 < len(instructions):
            next_instr = instructions[i + 1]
            if next_instr.mnemonic not in ("test", "cmp", "je", "jz", "jne", "jnz"):
                report.findings.append(
                    Finding(
                        category=FindingCategory.UNCHECKED_CALL,
                        severity=Severity.LOW,
                        offset=instr.address,
                        description=f"Call at 0x{instr.address:x} — return value not checked",
                        recommendation="Verify return value is intentionally ignored",
                    )
                )


def _check_cfg_complexity(
    binary: BinaryFile,
    arch: Arch,
    report: AuditReport,
    code_offset: int,
    code_size: int | None,
) -> None:
    """Flag high cyclomatic complexity (many branches)."""
    dis = Disassembler(arch)
    end = code_offset + code_size if code_size else len(binary.raw)
    code = binary.raw[code_offset:end]
    if not code:
        return

    instructions = dis.disassemble(code, code_offset)
    if not instructions:
        return

    cfg = CFGBuilder().build(instructions)

    if cfg.edge_count > 20:
        report.findings.append(
            Finding(
                category=FindingCategory.COMPLEXITY,
                severity=Severity.INFO,
                offset=code_offset,
                description=f"High complexity: {cfg.block_count} blocks, {cfg.edge_count} edges",
                recommendation="Consider reviewing complex control flow for logic errors",
            )
        )
