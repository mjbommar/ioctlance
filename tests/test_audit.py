#!/usr/bin/env python3
"""Tests for the vulnerability audit system."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess
from datetime import datetime

from ioctlance.audit import VulnerabilityAuditor, BatchAuditor, ReportGenerator
from ioctlance.audit.auditor import AuditResult, AuditClassification
from ioctlance.audit.batch_auditor import BatchAuditConfig, BatchAuditSummary
from ioctlance.audit.report_generator import TechnicalReport, ReportMetadata, ReportSeverity


class TestVulnerabilityAuditor:
    """Test the VulnerabilityAuditor class."""

    @pytest.fixture
    def auditor(self):
        """Create an auditor instance."""
        return VulnerabilityAuditor(verbose=False)

    @pytest.fixture
    def sample_vulnerability(self):
        """Sample vulnerability data."""
        return {
            "title": "Buffer Overflow - Stack Corruption",
            "description": "Stack buffer overflow via IOCTL 0x222003",
            "eval": {"IoControlCode": "0x222003", "SystemBuffer": "0x41414141", "InputBufferLength": "0x1000"},
            "others": {"severity": "CRITICAL", "type": "buffer_overflow"},
        }

    def test_audit_result_model(self):
        """Test AuditResult model validation."""
        result = AuditResult(
            classification=AuditClassification.TRUE_POSITIVE,
            confidence=95,
            reasoning="Clear buffer overflow without bounds checking",
            evidence={"vulnerable_address": "0x1400"},
            constraints=["InputBufferLength > 0x100"],
        )

        assert result.classification == AuditClassification.TRUE_POSITIVE
        assert result.confidence == 95
        assert "vulnerable_address" in result.evidence
        assert len(result.constraints) == 1

    @patch("subprocess.run")
    def test_audit_true_positive(self, mock_run, auditor, sample_vulnerability):
        """Test auditing a true positive vulnerability."""
        # Mock Claude Code output
        claude_output = json.dumps(
            {
                "classification": "TRUE_POSITIVE",
                "confidence": 90,
                "evidence": {
                    "vulnerable_address": "0x1400",
                    "ioctl_handler": "0x1200",
                    "vulnerable_instruction": "call memcpy",
                },
                "reasoning": "No bounds checking before memcpy",
                "constraints": [],
                "mitigations": [],
            }
        )

        mock_run.return_value = Mock(stdout=claude_output, stderr="", returncode=0)

        # Run audit
        driver_path = Path("test_driver.sys")
        result = auditor.audit(driver_path, sample_vulnerability)

        # Verify result
        assert result.classification == AuditClassification.TRUE_POSITIVE
        assert result.confidence == 90
        assert result.vulnerable_address == "0x1400"
        assert "memcpy" in result.reasoning

    @patch("subprocess.run")
    def test_audit_false_positive(self, mock_run, auditor):
        """Test auditing a false positive (NULL pointer dereference)."""
        vuln = {
            "title": "Buffer Overflow - Controllable PC",
            "eval": {
                "IoControlCode": "0x232c08",
                "SystemBuffer": "0x0",  # NULL buffer
            },
            "others": {"type": "unconstrained_state"},
        }

        claude_output = json.dumps(
            {
                "classification": "FALSE_POSITIVE",
                "confidence": 95,
                "reasoning": "NULL pointer dereference, not buffer overflow",
                "evidence": {"mem_read_address": "0x8"},
                "constraints": ["SystemBuffer == NULL"],
            }
        )

        mock_run.return_value = Mock(stdout=claude_output, returncode=0)

        result = auditor.audit(Path("driver.sys"), vuln)

        assert result.classification == AuditClassification.FALSE_POSITIVE
        assert result.confidence == 95
        assert "NULL pointer" in result.reasoning

    @patch("subprocess.run")
    def test_audit_timeout(self, mock_run, auditor, sample_vulnerability):
        """Test audit timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired("claude", 300)

        result = auditor.audit(Path("driver.sys"), sample_vulnerability, timeout=300)

        assert result.classification == AuditClassification.ERROR
        assert result.confidence == 0
        assert "timed out" in result.reasoning

    @patch("subprocess.run")
    def test_audit_parse_error(self, mock_run, auditor, sample_vulnerability):
        """Test handling of malformed Claude output."""
        mock_run.return_value = Mock(stdout="Not valid JSON output TRUE_POSITIVE", returncode=0)

        result = auditor.audit(Path("driver.sys"), sample_vulnerability)

        # Should still extract classification from text
        assert result.classification == AuditClassification.TRUE_POSITIVE
        assert result.confidence == 25  # Low confidence due to parse error


class TestBatchAuditor:
    """Test the BatchAuditor class."""

    @pytest.fixture
    def batch_auditor(self):
        """Create a batch auditor instance."""
        config = BatchAuditConfig(parallel_workers=1, timeout_per_audit=60, skip_likely_false_positives=True)
        return BatchAuditor(config)

    @pytest.fixture
    def sample_batch_results(self, tmp_path):
        """Create a sample batch_results.jsonl file."""
        results_file = tmp_path / "batch_results.jsonl"

        data = [
            {
                "type": "driver_result",
                "data": {
                    "path": "/path/to/driver1.sys",
                    "vulnerabilities": [
                        {
                            "title": "Buffer Overflow",
                            "eval": {"IoControlCode": "0x222003"},
                            "others": {"severity": "CRITICAL", "type": "buffer_overflow"},
                        }
                    ],
                },
            },
            {
                "type": "driver_result",
                "data": {
                    "path": "/path/to/driver2.sys",
                    "vulnerabilities": [
                        {
                            "title": "NULL Pointer Dereference",
                            "eval": {"IoControlCode": "0x232c08", "SystemBuffer": "0x0"},
                            "others": {"severity": "HIGH", "type": "unconstrained_state"},
                            "description": "NULL pointer misclassified",
                        }
                    ],
                },
            },
        ]

        with open(results_file, "w") as f:
            for item in data:
                f.write(json.dumps(item) + "\n")

        return results_file

    def test_load_vulnerabilities(self, batch_auditor, sample_batch_results):
        """Test loading vulnerabilities from JSONL."""
        vulns = batch_auditor._load_vulnerabilities(sample_batch_results)

        assert len(vulns) == 2
        assert vulns[0]["title"] == "Buffer Overflow"
        assert vulns[1]["title"] == "NULL Pointer Dereference"
        assert all("driver_path" in v for v in vulns)

    def test_filter_likely_false_positives(self, batch_auditor):
        """Test filtering of likely false positives."""
        vulns = [
            {"title": "Buffer Overflow", "others": {"type": "buffer_overflow"}, "eval": {"SystemBuffer": "0x41414141"}},
            {
                "title": "Buffer Overflow - NULL",
                "description": "NULL pointer issue",
                "others": {"type": "unconstrained_state"},
                "eval": {"SystemBuffer": "0x0"},
            },
        ]

        filtered = batch_auditor._apply_filters(vulns)

        # Should filter out NULL pointer false positive
        assert len(filtered) == 1
        assert filtered[0]["title"] == "Buffer Overflow"

    def test_filter_by_severity(self, batch_auditor):
        """Test severity filtering."""
        batch_auditor.config.filter_severity = "HIGH"

        vulns = [
            {"others": {"severity": "CRITICAL"}},
            {"others": {"severity": "HIGH"}},
            {"others": {"severity": "MEDIUM"}},
            {"others": {"severity": "LOW"}},
        ]

        filtered = batch_auditor._apply_filters(vulns)

        assert len(filtered) == 2  # CRITICAL and HIGH

    @patch.object(VulnerabilityAuditor, "audit")
    def test_batch_audit_summary(self, mock_audit, batch_auditor, sample_batch_results, tmp_path):
        """Test batch audit with summary generation."""
        # Mock audit results
        mock_audit.side_effect = [
            AuditResult(
                classification=AuditClassification.TRUE_POSITIVE, confidence=90, reasoning="Real vulnerability"
            ),
            # Second one should be filtered as likely false positive
        ]

        output_path = tmp_path / "summary.json"
        summary = batch_auditor.audit_batch_results(sample_batch_results, output_path)

        # Check summary
        assert summary.total_vulnerabilities == 2
        assert summary.total_audited == 1  # One filtered
        assert summary.classifications["TRUE_POSITIVE"] == 1

        # Check output file
        assert output_path.exists()
        with open(output_path) as f:
            saved_summary = json.load(f)
            assert saved_summary["total_audited"] == 1


class TestReportGenerator:
    """Test the ReportGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a report generator instance."""
        return ReportGenerator(verbose=False)

    @pytest.fixture
    def audit_result(self):
        """Sample audit result."""
        return AuditResult(
            classification=AuditClassification.TRUE_POSITIVE,
            confidence=90,
            reasoning="Clear buffer overflow without bounds checking",
            vulnerable_address="0x1400",
            ioctl_handler="0x1200",
            constraints=["InputBufferLength > 0x100"],
        )

    def test_report_metadata_model(self):
        """Test ReportMetadata model validation."""
        metadata = ReportMetadata(
            severity=ReportSeverity.CRITICAL,
            cvss_score=8.8,
            cwe_id="CWE-121",
            effort_to_fix="LOW",
            effort_to_exploit="MEDIUM",
        )

        assert metadata.severity == ReportSeverity.CRITICAL
        assert metadata.cvss_score == 8.8
        assert metadata.cwe_id == "CWE-121"

    def test_minimal_report_generation(self, generator, audit_result):
        """Test minimal report generation (fallback)."""
        driver_path = Path("test_driver.sys")
        vulnerability = {
            "title": "Buffer Overflow",
            "eval": {"IoControlCode": "0x222003"},
            "others": {"type": "buffer_overflow"},
        }

        report = generator._create_minimal_report(driver_path, vulnerability, audit_result)

        assert report.title == "Buffer Overflow"
        assert report.driver_name == "test_driver.sys"
        assert report.metadata.severity == ReportSeverity.HIGH
        assert "0x222003" in report.executive_summary

    @patch("subprocess.run")
    def test_report_generation_with_claude(self, mock_run, generator, audit_result):
        """Test report generation with Claude Code."""
        driver_path = Path("driver.sys")
        vulnerability = {"title": "Buffer Overflow", "eval": {"IoControlCode": "0x222003"}}

        # Mock Claude output with report sections
        claude_output = """
## 1. Executive Summary
This is a critical buffer overflow vulnerability.

## 2. Technical Details
CVSS Score: 8.8
CWE-121: Stack Buffer Overflow

## 3. Proof of Concept
Exploit code here.

## 4. Root Cause Analysis
Missing bounds checking.

## 5. Remediation
Add input validation.

## 6. References
- CWE-121
- Microsoft SDL

{"metadata": {"severity": "CRITICAL", "cvss_score": 8.8, "cwe_id": "CWE-121"}}
"""

        mock_run.return_value = Mock(stdout=claude_output, returncode=0)

        report = generator.generate_report(driver_path, vulnerability, audit_result)

        assert report.title == "Buffer Overflow"
        assert "critical buffer overflow" in report.executive_summary
        assert report.metadata.cvss_score == 8.8
        assert report.metadata.cwe_id == "CWE-121"

    def test_markdown_report_formatting(self, generator, audit_result):
        """Test Markdown report formatting."""
        report = TechnicalReport(
            title="Test Vulnerability",
            driver_name="test.sys",
            vulnerability_type="buffer_overflow",
            generated_at=datetime.now(),
            executive_summary="Test summary",
            technical_details="Test details",
            proof_of_concept="Test PoC",
            root_cause_analysis="Test analysis",
            remediation="Test fix",
            references="Test refs",
            metadata=ReportMetadata(severity=ReportSeverity.CRITICAL, cvss_score=9.0),
            audit_result=audit_result,
        )

        markdown = generator._format_markdown_report(report)

        assert "# Security Vulnerability Report" in markdown
        assert "🔴 CRITICAL" in markdown
        assert "CVSS Score: 9.0" in markdown
        assert "Test summary" in markdown

    def test_save_report_json(self, generator, audit_result, tmp_path):
        """Test saving report as JSON."""
        report = TechnicalReport(
            title="Test",
            driver_name="test.sys",
            vulnerability_type="test",
            generated_at=datetime.now(),
            executive_summary="Summary",
            technical_details="Details",
            proof_of_concept="PoC",
            root_cause_analysis="Analysis",
            remediation="Fix",
            references="Refs",
            metadata=ReportMetadata(severity=ReportSeverity.HIGH),
            audit_result=audit_result,
        )

        output_path = tmp_path / "report.json"
        generator.save_report(report, output_path, format="json")

        assert output_path.exists()
        with open(output_path) as f:
            saved = json.load(f)
            assert saved["title"] == "Test"
            assert saved["metadata"]["severity"] == "HIGH"


@pytest.mark.integration
class TestAuditIntegration:
    """Integration tests for the audit system."""

    @pytest.mark.skipif(
        not Path("/home/mjbommar/src/ioctlance/samples").exists(), reason="Samples directory not available"
    )
    def test_audit_real_driver(self):
        """Test auditing a real driver sample."""
        # This would require Claude Code CLI to be installed
        # and samples to be available
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
