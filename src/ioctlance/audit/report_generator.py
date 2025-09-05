"""Technical report generator for vulnerability audits."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional
from datetime import datetime
from enum import Enum
import logging

from pydantic import BaseModel, Field

from .auditor import AuditResult, AuditClassification

logger = logging.getLogger(__name__)


class ReportSeverity(str, Enum):
    """Report severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReportMetadata(BaseModel):
    """Metadata for a vulnerability report."""

    severity: ReportSeverity
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cwe_id: str | None = None
    effort_to_fix: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH)$")
    effort_to_exploit: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH)$")

    class Config:
        use_enum_values = True


class TechnicalReport(BaseModel):
    """Complete technical vulnerability report."""

    title: str
    driver_name: str
    vulnerability_type: str
    generated_at: datetime

    executive_summary: str
    technical_details: str
    proof_of_concept: str
    root_cause_analysis: str
    remediation: str
    references: str

    metadata: ReportMetadata
    audit_result: AuditResult

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ReportGenerator:
    """Generates technical reports for vulnerability audits."""

    def __init__(self, claude_command: str = "claude", verbose: bool = False):
        """
        Initialize the report generator.

        Args:
            claude_command: Path to Claude Code CLI command
            verbose: Enable verbose output
        """
        self.claude_command = claude_command
        self.verbose = verbose

    def generate_report(
        self,
        driver_path: Path,
        vulnerability: dict[str, Any],
        audit_result: AuditResult,
        output_format: str = "markdown",
    ) -> TechnicalReport:
        """
        Generate a technical report for an audited vulnerability.

        Args:
            driver_path: Path to the driver file
            vulnerability: Original vulnerability details
            audit_result: Audit classification and evidence
            output_format: Report format (markdown or json)

        Returns:
            TechnicalReport object
        """
        if audit_result.classification != AuditClassification.TRUE_POSITIVE:
            logger.warning(f"Generating report for non-true-positive: {audit_result.classification}")

        # Create report generation prompt
        prompt = self._create_report_prompt(driver_path, vulnerability, audit_result)

        # Generate report using Claude Code
        try:
            report_data = self._generate_with_claude(prompt)
            return self._parse_report(driver_path, vulnerability, audit_result, report_data)
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            # Return a minimal report on error
            return self._create_minimal_report(driver_path, vulnerability, audit_result)

    def _create_report_prompt(self, driver_path: Path, vulnerability: dict[str, Any], audit_result: AuditResult) -> str:
        """Create the report generation prompt for Claude Code."""

        title = vulnerability.get("title", "Unknown Vulnerability")
        ioctl = vulnerability.get("eval", {}).get("IoControlCode", "unknown")

        prompt = f"""Generate a professional technical security audit report for this confirmed vulnerability.

## Vulnerability Information
- Driver: {driver_path.name}
- Vulnerability: {title}
- IOCTL Code: {ioctl}
- Classification: {audit_result.classification}
- Confidence: {audit_result.confidence}%

## Audit Evidence
{json.dumps(audit_result.model_dump(), indent=2)}

## Original Detection
{json.dumps(vulnerability, indent=2)}

## Report Requirements

Create a comprehensive technical report with the following sections:

### 1. Executive Summary
Write a 2-3 paragraph executive summary that:
- Explains the vulnerability in non-technical terms
- Describes the business risk and potential impact
- Provides clear recommendations for stakeholders
- Includes a risk rating (CRITICAL/HIGH/MEDIUM/LOW)

### 2. Technical Details
Provide detailed technical analysis:
- **CWE Classification**: Identify the specific CWE ID (e.g., CWE-121 for stack buffer overflow)
- **CVSS v3.1 Score**: Calculate the base score with justification
  - Attack Vector (AV): Local/Adjacent/Network
  - Attack Complexity (AC): Low/High
  - Privileges Required (PR): None/Low/High
  - User Interaction (UI): None/Required
  - Scope (S): Unchanged/Changed
  - Confidentiality (C): None/Low/High
  - Integrity (I): None/Low/High
  - Availability (A): None/Low/High
- **Attack Surface**: Which IOCTL and input buffers are affected
- **Vulnerable Code**: Specific function at address {audit_result.vulnerable_address or "unknown"}

### 3. Proof of Concept
Detail the exploitation process:
- Step-by-step exploitation methodology
- Required setup and conditions
- Sample exploit code or pseudocode showing:
  ```c
  // Example structure
  HANDLE hDevice = CreateFile(...);
  BYTE inputBuffer[SIZE];
  // Fill buffer to trigger overflow
  DeviceIoControl(hDevice, {ioctl}, inputBuffer, ...);
  ```
- Expected outcome (code execution, DoS, privilege escalation)

### 4. Root Cause Analysis
Explain why this vulnerability exists:
- Missing input validation on buffer size
- Unsafe memory operations (memcpy, strcpy)
- Integer overflow leading to undersized allocation
- Race conditions in IOCTL handling
- Lack of proper access controls

### 5. Remediation
Provide actionable fixes:
**Immediate Fix:**
- Validate input buffer size before processing
- Add bounds checking: `if (InputBufferLength > MAX_SAFE_SIZE) return STATUS_INVALID_PARAMETER;`
- Use safe string functions (StringCbCopy instead of strcpy)

**Long-term Improvements:**
- Implement comprehensive input validation framework
- Add security assertions and runtime checks
- Enable compiler security features (/GS, /DYNAMICBASE, /NXCOMPAT)
- Implement least-privilege design patterns

**Verification:**
- Test with fuzzing tools (WDK Device Fundamentals Tests)
- Verify with static analysis (PREfast, CodeQL)
- Confirm fix with proof-of-concept

### 6. References
- Related CVEs (search for similar driver vulnerabilities)
- Microsoft Security Development Lifecycle for Drivers
- WDK Security Best Practices
- CWE-{audit_result.evidence.get("cwe_id", "121")} documentation

## Output Format

Generate the report as a well-formatted Markdown document.

At the end, include a JSON metadata block:
```json
{{
  "metadata": {{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "cvss_score": 7.8,
    "cwe_id": "CWE-121",
    "effort_to_fix": "LOW|MEDIUM|HIGH",
    "effort_to_exploit": "LOW|MEDIUM|HIGH",
    "executive_summary": "Brief one-line summary",
    "remediation_priority": 1
  }}
}}
```

Make the report:
- Technically accurate with specific details
- Actionable for developers
- Understandable for management
- Compliant with security audit standards"""

        return prompt

    def _generate_with_claude(self, prompt: str, timeout: int = 180) -> dict[str, Any]:
        """Generate report using Claude Code CLI."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(prompt)
            prompt_file = f.name

        try:
            cmd = [self.claude_command, "-p", f"@{prompt_file}", "--output-format", "stream-json"]

            if self.verbose:
                logger.info(f"Generating report with: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            if result.returncode != 0:
                raise RuntimeError(f"Claude Code failed: {result.stderr}")

            # Parse the output to extract report sections
            return self._extract_report_sections(result.stdout)

        finally:
            Path(prompt_file).unlink(missing_ok=True)

    def _extract_report_sections(self, claude_output: str) -> dict[str, Any]:
        """Extract report sections from Claude output."""
        sections = {
            "executive_summary": "",
            "technical_details": "",
            "proof_of_concept": "",
            "root_cause_analysis": "",
            "remediation": "",
            "references": "",
            "metadata": {},
        }

        # Parse the markdown output into sections
        current_section = None
        section_content = []

        for line in claude_output.split("\n"):
            # Check for section headers
            if "# Executive Summary" in line or "## 1. Executive Summary" in line:
                if current_section and section_content:
                    sections[current_section] = "\n".join(section_content)
                current_section = "executive_summary"
                section_content = []
            elif "# Technical Details" in line or "## 2. Technical Details" in line:
                if current_section and section_content:
                    sections[current_section] = "\n".join(section_content)
                current_section = "technical_details"
                section_content = []
            elif "# Proof of Concept" in line or "## 3. Proof of Concept" in line:
                if current_section and section_content:
                    sections[current_section] = "\n".join(section_content)
                current_section = "proof_of_concept"
                section_content = []
            elif "# Root Cause" in line or "## 4. Root Cause" in line:
                if current_section and section_content:
                    sections[current_section] = "\n".join(section_content)
                current_section = "root_cause_analysis"
                section_content = []
            elif "# Remediation" in line or "## 5. Remediation" in line:
                if current_section and section_content:
                    sections[current_section] = "\n".join(section_content)
                current_section = "remediation"
                section_content = []
            elif "# References" in line or "## 6. References" in line:
                if current_section and section_content:
                    sections[current_section] = "\n".join(section_content)
                current_section = "references"
                section_content = []
            elif current_section:
                section_content.append(line)

        # Save last section
        if current_section and section_content:
            sections[current_section] = "\n".join(section_content)

        # Extract metadata JSON if present
        import re

        json_match = re.search(r'\{.*"metadata".*\}', claude_output, re.DOTALL)
        if json_match:
            try:
                metadata_json = json.loads(json_match.group())
                sections["metadata"] = metadata_json.get("metadata", {})
            except json.JSONDecodeError:
                pass

        return sections

    def _parse_report(
        self, driver_path: Path, vulnerability: dict[str, Any], audit_result: AuditResult, report_data: dict[str, Any]
    ) -> TechnicalReport:
        """Parse Claude output into TechnicalReport."""

        # Extract metadata or use defaults
        metadata_dict = report_data.get("metadata", {})
        metadata = ReportMetadata(
            severity=metadata_dict.get("severity", "HIGH"),
            cvss_score=metadata_dict.get("cvss_score", 7.0),
            cwe_id=metadata_dict.get("cwe_id", "CWE-121"),
            effort_to_fix=metadata_dict.get("effort_to_fix", "MEDIUM"),
            effort_to_exploit=metadata_dict.get("effort_to_exploit", "MEDIUM"),
        )

        return TechnicalReport(
            title=vulnerability.get("title", "Unknown Vulnerability"),
            driver_name=driver_path.name,
            vulnerability_type=vulnerability.get("others", {}).get("type", "unknown"),
            generated_at=datetime.now(),
            executive_summary=report_data.get("executive_summary", "No summary available"),
            technical_details=report_data.get("technical_details", "No details available"),
            proof_of_concept=report_data.get("proof_of_concept", "No PoC available"),
            root_cause_analysis=report_data.get("root_cause_analysis", "No analysis available"),
            remediation=report_data.get("remediation", "No remediation available"),
            references=report_data.get("references", "No references available"),
            metadata=metadata,
            audit_result=audit_result,
        )

    def _create_minimal_report(
        self, driver_path: Path, vulnerability: dict[str, Any], audit_result: AuditResult
    ) -> TechnicalReport:
        """Create a minimal report when generation fails."""

        title = vulnerability.get("title", "Unknown Vulnerability")
        ioctl = vulnerability.get("eval", {}).get("IoControlCode", "unknown")

        return TechnicalReport(
            title=title,
            driver_name=driver_path.name,
            vulnerability_type=vulnerability.get("others", {}).get("type", "unknown"),
            generated_at=datetime.now(),
            executive_summary=f"A {title} vulnerability was detected in {driver_path.name} at IOCTL {ioctl}.",
            technical_details=f"Vulnerability detected with {audit_result.confidence}% confidence.\n{audit_result.reasoning}",
            proof_of_concept="Proof of concept generation failed. Manual analysis required.",
            root_cause_analysis="Root cause analysis unavailable. Review the vulnerable code manually.",
            remediation="Implement input validation and bounds checking for IOCTL {ioctl}.",
            references="- Microsoft Security Development Lifecycle\n- CWE Database",
            metadata=ReportMetadata(
                severity=ReportSeverity.HIGH,
                cvss_score=7.0,
                cwe_id="CWE-121",
                effort_to_fix="MEDIUM",
                effort_to_exploit="MEDIUM",
            ),
            audit_result=audit_result,
        )

    def save_report(self, report: TechnicalReport, output_path: Path, format: str = "markdown"):
        """
        Save a technical report to file.

        Args:
            report: The technical report to save
            output_path: Path to save the report
            format: Output format (markdown or json)
        """
        if format == "json":
            with open(output_path, "w") as f:
                json.dump(report.model_dump(), f, indent=2, default=str)
        else:  # markdown
            with open(output_path, "w") as f:
                f.write(self._format_markdown_report(report))

        logger.info(f"Report saved to {output_path}")

    def _format_markdown_report(self, report: TechnicalReport) -> str:
        """Format report as Markdown."""

        severity_badge = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🟢 LOW",
            "INFO": "🔵 INFO",
        }.get(report.metadata.severity, report.metadata.severity)

        markdown = f"""# Security Vulnerability Report: {report.title}

**Driver:** {report.driver_name}
**Severity:** {severity_badge}
**CVSS Score:** {report.metadata.cvss_score or "N/A"}
**CWE:** {report.metadata.cwe_id or "N/A"}
**Generated:** {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")}

---

## Executive Summary

{report.executive_summary}

## Technical Details

{report.technical_details}

## Proof of Concept

{report.proof_of_concept}

## Root Cause Analysis

{report.root_cause_analysis}

## Remediation

{report.remediation}

## References

{report.references}

---

### Metadata

- **Effort to Fix:** {report.metadata.effort_to_fix}
- **Effort to Exploit:** {report.metadata.effort_to_exploit}
- **Audit Confidence:** {report.audit_result.confidence}%
- **Classification:** {report.audit_result.classification}
"""

        return markdown
