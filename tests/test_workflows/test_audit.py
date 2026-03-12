"""Tests for the audit workflow."""

from __future__ import annotations

from binaryvibes.core.arch import Arch
from binaryvibes.core.binary import BinaryFile
from binaryvibes.workflows.audit import (
    AuditReport,
    Finding,
    FindingCategory,
    Severity,
    audit_binary,
)

_CODE_OFFSET = 120


class TestAuditBinary:
    """Tests for audit_binary()."""

    def test_audit_vuln_binary_finds_nop_sled(self, vuln_binary: BinaryFile) -> None:
        """Audit of vuln_elf finds a NOP sled pattern."""
        report = audit_binary(vuln_binary, code_offset=_CODE_OFFSET)
        nop_findings = report.by_category(FindingCategory.NOP_SLED)
        assert len(nop_findings) >= 1

    def test_audit_finds_unchecked_call(self, vuln_binary: BinaryFile) -> None:
        """Audit of vuln_elf finds unchecked call patterns."""
        report = audit_binary(vuln_binary, code_offset=_CODE_OFFSET)
        unchecked = report.by_category(FindingCategory.UNCHECKED_CALL)
        assert len(unchecked) >= 1

    def test_audit_clean_binary_minimal_findings(self, tiny_elf_binary: BinaryFile) -> None:
        """Tiny ELF (no calls, no NOP sleds) has minimal findings."""
        report = audit_binary(tiny_elf_binary, code_offset=_CODE_OFFSET)
        # Tiny binary has just mov/syscall — no NOP sleds or unchecked calls
        nop_findings = report.by_category(FindingCategory.NOP_SLED)
        unchecked = report.by_category(FindingCategory.UNCHECKED_CALL)
        assert len(nop_findings) == 0
        assert len(unchecked) == 0

    def test_audit_with_code_offset(self, vuln_binary: BinaryFile) -> None:
        """Specifying code_offset targets the correct region."""
        report = audit_binary(vuln_binary, code_offset=_CODE_OFFSET)
        assert report.binary_size == len(vuln_binary.raw)
        assert report.finding_count >= 0  # no crash

    def test_audit_empty_binary(self) -> None:
        """Binary with no meaningful code produces no crash."""
        empty = BinaryFile.from_bytes(b"\x00" * 16, name="empty")
        report = audit_binary(empty, Arch.X86_64, code_offset=0)
        assert isinstance(report, AuditReport)


class TestAuditReport:
    """Tests for AuditReport methods."""

    def test_report_summary(self, vuln_binary: BinaryFile) -> None:
        """summary() returns a non-empty descriptive string."""
        report = audit_binary(vuln_binary, code_offset=_CODE_OFFSET)
        s = report.summary()
        assert isinstance(s, str)
        assert len(s) > 0
        assert "Audit" in s

    def test_report_detailed(self, vuln_binary: BinaryFile) -> None:
        """detailed_report() includes findings section."""
        report = audit_binary(vuln_binary, code_offset=_CODE_OFFSET)
        d = report.detailed_report()
        assert "Findings" in d

    def test_report_by_severity(self, vuln_binary: BinaryFile) -> None:
        """by_severity() filters correctly for each severity level."""
        report = audit_binary(vuln_binary, code_offset=_CODE_OFFSET)
        for sev in Severity:
            filtered = report.by_severity(sev)
            assert all(f.severity == sev for f in filtered)

    def test_report_by_category(self, vuln_binary: BinaryFile) -> None:
        """by_category() filters correctly for each category."""
        report = audit_binary(vuln_binary, code_offset=_CODE_OFFSET)
        for cat in FindingCategory:
            filtered = report.by_category(cat)
            assert all(f.category == cat for f in filtered)


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_str_contains_severity_and_offset(self) -> None:
        """Finding.__str__ includes severity label and hex offset."""
        f = Finding(
            category=FindingCategory.NOP_SLED,
            severity=Severity.MEDIUM,
            offset=0x400,
            description="test finding",
        )
        s = str(f)
        assert "medium" in s
        assert "00000400" in s
        assert "test finding" in s
