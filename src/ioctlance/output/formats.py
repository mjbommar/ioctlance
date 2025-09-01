"""Output format definitions and converters."""

from enum import Enum
from typing import Any
import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field


class OutputFormat(Enum):
    """Supported output formats."""

    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"
    SARIF = "sarif"
    MARKDOWN = "markdown"
    HTML = "html"
    SUMMARY = "summary"
    DETAILED = "detailed"


class OutputLevel(Enum):
    """Output detail levels."""

    QUIET = 0  # Only critical errors
    NORMAL = 1  # Summary + vulnerabilities
    VERBOSE = 2  # + IOCTL discovery details
    DEBUG = 3  # + Symbolic execution trace
    FULL = 4  # Everything including raw state


class VulnerabilitySummary(BaseModel):
    """Summary of vulnerabilities for output."""

    type: str = Field(..., description="Vulnerability type")
    severity: str = Field(..., description="Severity level")
    count: int = Field(..., description="Number of instances")
    ioctl_codes: list[str] = Field(default_factory=list, description="IOCTL codes that trigger")
    first_seen: str | None = Field(None, description="First detection time")

    def to_markdown_row(self) -> str:
        """Convert to markdown table row."""
        ioctls = ", ".join(self.ioctl_codes[:3])
        if len(self.ioctl_codes) > 3:
            ioctls += f" (+{len(self.ioctl_codes) - 3} more)"
        return f"| {self.type} | {self.severity} | {self.count} | {ioctls} |"

    def to_csv_row(self) -> str:
        """Convert to CSV row."""
        ioctls = ";".join(self.ioctl_codes)
        return f'"{self.type}","{self.severity}",{self.count},"{ioctls}"'


class AnalysisSummary(BaseModel):
    """Summary of analysis results."""

    driver_name: str = Field(..., description="Driver file name")
    driver_hash: str = Field(..., description="Driver BLAKE2b hash")
    analysis_time: float = Field(..., description="Analysis time in seconds")
    analysis_date: str = Field(..., description="Analysis timestamp")

    ioctl_codes_found: int = Field(default=0, description="Number of IOCTL codes discovered")
    ioctl_codes: list[str] = Field(default_factory=list, description="List of IOCTL codes")

    vulnerabilities_found: int = Field(default=0, description="Total vulnerabilities found")
    unique_vulnerabilities: int = Field(default=0, description="Unique vulnerability types")

    severity_breakdown: dict[str, int] = Field(default_factory=dict, description="Vulnerability count by severity")

    vulnerability_summary: list[VulnerabilitySummary] = Field(
        default_factory=list, description="Summary of each vulnerability type"
    )

    def to_markdown(self) -> str:
        """Convert to markdown report."""
        lines = [
            f"# Analysis Report: {self.driver_name}",
            "",
            "## Summary",
            f"- **Driver Hash (BLAKE2b)**: `{self.driver_hash}`",
            f"- **Analysis Date**: {self.analysis_date}",
            f"- **Analysis Time**: {self.analysis_time:.2f} seconds",
            f"- **IOCTL Codes Found**: {self.ioctl_codes_found}",
            f"- **Total Vulnerabilities**: {self.vulnerabilities_found}",
            f"- **Unique Vulnerability Types**: {self.unique_vulnerabilities}",
            "",
        ]

        if self.ioctl_codes:
            lines.extend(
                [
                    "## IOCTL Codes",
                    "```",
                    *self.ioctl_codes,
                    "```",
                    "",
                ]
            )

        if self.severity_breakdown:
            lines.extend(
                [
                    "## Severity Distribution",
                    "| Severity | Count |",
                    "|----------|-------|",
                ]
            )
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity in self.severity_breakdown:
                    lines.append(f"| {severity} | {self.severity_breakdown[severity]} |")
            lines.append("")

        if self.vulnerability_summary:
            lines.extend(
                [
                    "## Vulnerabilities",
                    "| Type | Severity | Count | IOCTL Codes |",
                    "|------|----------|-------|-------------|",
                ]
            )
            for vuln in self.vulnerability_summary:
                lines.append(vuln.to_markdown_row())
            lines.append("")

        return "\n".join(lines)

    def to_csv_header(self) -> str:
        """Get CSV header."""
        return "Type,Severity,Count,IOCTL_Codes"

    def to_csv(self) -> str:
        """Convert to CSV format."""
        lines = [self.to_csv_header()]
        for vuln in self.vulnerability_summary:
            lines.append(vuln.to_csv_row())
        return "\n".join(lines)

    def to_html(self) -> str:
        """Convert to HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Analysis Report: {self.driver_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #95a5a6; }}
        code {{ background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>Analysis Report: {self.driver_name}</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <ul>
            <li><strong>Driver Hash (BLAKE2b):</strong> <code>{self.driver_hash}</code></li>
            <li><strong>Analysis Date:</strong> {self.analysis_date}</li>
            <li><strong>Analysis Time:</strong> {self.analysis_time:.2f} seconds</li>
            <li><strong>IOCTL Codes Found:</strong> {self.ioctl_codes_found}</li>
            <li><strong>Total Vulnerabilities:</strong> {self.vulnerabilities_found}</li>
            <li><strong>Unique Vulnerability Types:</strong> {self.unique_vulnerabilities}</li>
        </ul>
    </div>
"""

        if self.severity_breakdown:
            html += """
    <h2>Severity Distribution</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
"""
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity in self.severity_breakdown:
                    severity_class = severity.lower()
                    html += f"""        <tr><td class="{severity_class}">{severity}</td><td>{self.severity_breakdown[severity]}</td></tr>\n"""
            html += "    </table>\n"

        if self.vulnerability_summary:
            html += """
    <h2>Vulnerabilities</h2>
    <table>
        <tr><th>Type</th><th>Severity</th><th>Count</th><th>IOCTL Codes</th></tr>
"""
            for vuln in self.vulnerability_summary:
                severity_class = vuln.severity.lower()
                ioctls = ", ".join(vuln.ioctl_codes[:3])
                if len(vuln.ioctl_codes) > 3:
                    ioctls += f" (+{len(vuln.ioctl_codes) - 3} more)"
                html += f"""        <tr><td>{vuln.type}</td><td class="{severity_class}">{vuln.severity}</td><td>{vuln.count}</td><td><code>{ioctls}</code></td></tr>\n"""
            html += "    </table>\n"

        html += """
</body>
</html>"""
        return html
