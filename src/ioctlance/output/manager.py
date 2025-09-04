"""Unified output manager for consistent, detailed analysis results."""

import json
import logging
from pathlib import Path
from typing import Any
from datetime import datetime
from collections import defaultdict

from pydantic import BaseModel, Field

from .fingerprint import DriverFingerprint
from .formats import OutputFormat, OutputLevel, VulnerabilitySummary, AnalysisSummary
from .vulnerability_context import EnhancedVulnerability
from ..models.analysis_result import AnalysisResult
from ..models.vulnerability import Vulnerability
from ..models.binary_metadata import CompleteMetadata
from ..__version__ import __version__

logger = logging.getLogger(__name__)


class UnifiedAnalysisResult(BaseModel):
    """Unified, rich analysis result with all details."""

    # Driver identification
    fingerprint: DriverFingerprint = Field(..., description="Driver fingerprint and hashes")

    # Analysis metadata
    analysis_id: str = Field(..., description="Unique analysis ID")
    analysis_date: datetime = Field(default_factory=datetime.now)
    analysis_time: float = Field(..., description="Total analysis time in seconds")
    ioctlance_version: str = Field(default=__version__)

    # Analysis configuration
    config: dict[str, Any] = Field(default_factory=dict, description="Analysis configuration used")

    # Summary
    summary: AnalysisSummary = Field(..., description="Analysis summary")

    # IOCTL discovery
    ioctl_handler_address: str | None = Field(None)
    ioctl_codes: list[str] = Field(default_factory=list)
    ioctl_discovery_details: dict[str, Any] = Field(default_factory=dict)

    # Vulnerabilities (deduplicated and enhanced)
    vulnerabilities: list[EnhancedVulnerability] = Field(default_factory=list)
    vulnerability_groups: dict[str, list[EnhancedVulnerability]] = Field(default_factory=dict)

    # Binary metadata
    binary_metadata: CompleteMetadata | None = Field(None)

    # Errors and warnings
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # Raw analysis result (legacy format)
    raw_result: AnalysisResult | None = Field(None)


class OutputManager:
    """Manages output generation and formatting for analysis results."""

    def __init__(
        self,
        output_level: OutputLevel = OutputLevel.NORMAL,
        output_format: OutputFormat = OutputFormat.JSON,
        dedup_vulnerabilities: bool = True,
        capture_raw_state: bool = True,
    ):
        """Initialize output manager.

        Args:
            output_level: Level of detail in output
            output_format: Output format to use
            dedup_vulnerabilities: Whether to deduplicate vulnerabilities
            capture_raw_state: Whether to capture full raw state
        """
        self.output_level = output_level
        self.output_format = output_format
        self.dedup_vulnerabilities = dedup_vulnerabilities
        self.capture_raw_state = capture_raw_state

        # Vulnerability tracking
        self.vulnerabilities: list[EnhancedVulnerability] = []
        self.vulnerability_map: dict[str, EnhancedVulnerability] = {}

        # Metadata
        self.driver_path: Path | None = None
        self.fingerprint: DriverFingerprint | None = None
        self.analysis_start_time: datetime | None = None
        self.config: dict[str, Any] = {}

    def initialize(self, driver_path: Path, config: dict[str, Any] | None = None) -> None:
        """Initialize for a new analysis.

        Args:
            driver_path: Path to driver being analyzed
            config: Analysis configuration
        """
        self.driver_path = driver_path
        self.fingerprint = DriverFingerprint.from_file(driver_path)
        self.analysis_start_time = datetime.now()
        self.config = config or {}

        # Clear previous results
        self.vulnerabilities.clear()
        self.vulnerability_map.clear()

        if self.output_level.value >= OutputLevel.VERBOSE.value:
            logger.info(f"Initialized output manager for: {driver_path.name}")
            logger.info(f"Driver BLAKE2b hash: {self.fingerprint.blake2b}")

    def add_vulnerability(
        self,
        title: str,
        description: str,
        state: Any,  # SimState
        context: Any | None = None,  # AnalysisContext
        parameters: dict[str, Any] | None = None,
        others: dict[str, Any] | None = None,
    ) -> EnhancedVulnerability:
        """Add a vulnerability with rich context.

        Args:
            title: Vulnerability title
            description: Detailed description
            state: Current simulation state
            context: Analysis context
            parameters: Additional parameters
            others: Other information

        Returns:
            Enhanced vulnerability instance
        """
        # Create enhanced vulnerability with full context
        enhanced_vuln = EnhancedVulnerability.from_detection(
            title=title,
            description=description,
            state=state,
            context=context,
            parameters=parameters,
            others=others,
            capture_full_state=self.capture_raw_state and self.output_level.value >= OutputLevel.DEBUG.value,
        )

        # Handle deduplication
        if self.dedup_vulnerabilities:
            if enhanced_vuln.dedup_key in self.vulnerability_map:
                # Update occurrence count
                existing = self.vulnerability_map[enhanced_vuln.dedup_key]
                existing.occurrence_count += 1

                if self.output_level.value >= OutputLevel.DEBUG.value:
                    logger.debug(
                        f"Duplicate vulnerability: {enhanced_vuln.dedup_key} (count: {existing.occurrence_count})"
                    )

                return existing
            else:
                # New unique vulnerability
                self.vulnerability_map[enhanced_vuln.dedup_key] = enhanced_vuln

        # Add to list
        self.vulnerabilities.append(enhanced_vuln)

        if self.output_level.value >= OutputLevel.VERBOSE.value:
            logger.info(f"Added vulnerability: {title} at {hex(state.addr)}")

        return enhanced_vuln

    def create_result(
        self,
        raw_result: AnalysisResult | None = None,
        analysis_time: float | None = None,
        binary_metadata: CompleteMetadata | None = None,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> UnifiedAnalysisResult:
        """Create unified analysis result.

        Args:
            raw_result: Raw analysis result from analyzer
            analysis_time: Total analysis time
            binary_metadata: Binary metadata
            errors: Error messages
            warnings: Warning messages

        Returns:
            Unified analysis result
        """
        # Calculate analysis time if not provided
        if analysis_time is None and self.analysis_start_time:
            analysis_time = (datetime.now() - self.analysis_start_time).total_seconds()

        # Group vulnerabilities by type
        # Use vulnerabilities from raw_result if available, otherwise from self
        vulnerabilities_to_process = []
        if raw_result and hasattr(raw_result, "vuln"):
            logger.info(f"OutputManager: raw_result has 'vuln' attribute with {len(raw_result.vuln)} items")
            # Convert raw_result vulnerabilities to EnhancedVulnerability format
            import uuid

            for i, vuln in enumerate(raw_result.vuln):
                try:
                    # Create a dedup key from title and eval parameters
                    dedup_key = f"{vuln.title}_{vuln.eval.IoControlCode if vuln.eval else '0x0'}"
                    enhanced = EnhancedVulnerability(
                        vulnerability=vuln,
                        first_seen=datetime.now(),
                        dedup_key=dedup_key,
                        instance_id=str(uuid.uuid4()),
                        ioctl_handler_address=raw_result.basic.ioctl_handler if raw_result.basic else None,
                        analysis_phase="phase_2",
                    )
                    vulnerabilities_to_process.append(enhanced)
                    if i < 3:  # Log first few conversions
                        logger.info(f"Converted vuln {i}: {vuln.title}")
                except Exception as e:
                    logger.error(f"Failed to convert vulnerability {i}: {e}")
                    if i < 3:
                        logger.error(f"Vulnerability data: {vuln}")
            logger.info(f"Successfully converted {len(vulnerabilities_to_process)} vulnerabilities")
        else:
            logger.info(f"OutputManager: Using self.vulnerabilities ({len(self.vulnerabilities)} items)")
            vulnerabilities_to_process = self.vulnerabilities

        vulnerability_groups = defaultdict(list)
        for vuln in vulnerabilities_to_process:
            vuln_type = vuln.vulnerability.vulnerability_type
            vulnerability_groups[vuln_type].append(vuln)

        # Create vulnerability summaries
        vuln_summaries = []
        severity_breakdown = defaultdict(int)

        for vuln_type, vulns in vulnerability_groups.items():
            # Get unique IOCTL codes
            ioctl_codes = list(
                set(v.vulnerability.eval.IoControlCode for v in vulns if v.vulnerability.eval.IoControlCode != "0x0")
            )

            # Get severity (should be same for all of same type)
            severity = vulns[0].vulnerability.severity
            severity_breakdown[severity] += len(vulns)

            vuln_summaries.append(
                VulnerabilitySummary(
                    type=vuln_type,
                    severity=severity,
                    count=len(vulns),
                    ioctl_codes=ioctl_codes,
                    first_seen=min(v.first_seen for v in vulns).isoformat(),
                )
            )

        # Sort summaries by severity and count
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        vuln_summaries.sort(key=lambda x: (severity_order.get(x.severity, 4), -x.count))

        # Extract IOCTL codes from raw result
        ioctl_codes = []
        ioctl_handler_address = None

        if raw_result:
            # IOCTL codes can be in basic info or in the ioctl_handler object
            if raw_result.basic.IoControlCodes:
                ioctl_codes = raw_result.basic.IoControlCodes
            elif raw_result.ioctl_handler and raw_result.ioctl_handler.ioctl_codes:
                ioctl_codes = raw_result.ioctl_handler.ioctl_codes

            # Handler address can be in basic info or in the ioctl_handler object
            if raw_result.basic.ioctl_handler:
                ioctl_handler_address = raw_result.basic.ioctl_handler
            elif raw_result.ioctl_handler and raw_result.ioctl_handler.address:
                ioctl_handler_address = raw_result.ioctl_handler.address

        # Create summary
        summary = AnalysisSummary(
            driver_name=self.driver_path.name if self.driver_path else "unknown",
            driver_hash=self.fingerprint.blake2b if self.fingerprint else "",
            analysis_time=analysis_time or 0,
            analysis_date=datetime.now().isoformat(),
            ioctl_codes_found=len(ioctl_codes),
            ioctl_codes=ioctl_codes,
            vulnerabilities_found=len(vulnerabilities_to_process),
            unique_vulnerabilities=len(vulnerability_groups),
            severity_breakdown=dict(severity_breakdown),
            vulnerability_summary=vuln_summaries,
        )

        # Generate unique analysis ID
        import uuid

        analysis_id = str(uuid.uuid4())

        return UnifiedAnalysisResult(
            fingerprint=self.fingerprint
            or DriverFingerprint(blake2b="", sha256="", sha1="", md5="", file_path="", file_name="", file_size=0),
            analysis_id=analysis_id,
            analysis_time=analysis_time or 0,
            config=self.config,
            summary=summary,
            ioctl_handler_address=ioctl_handler_address,
            ioctl_codes=ioctl_codes,
            vulnerabilities=vulnerabilities_to_process,
            vulnerability_groups=dict(vulnerability_groups),
            binary_metadata=binary_metadata,
            errors=errors or [],
            warnings=warnings or [],
            raw_result=raw_result,
        )

    def format_output(self, result: UnifiedAnalysisResult) -> str:
        """Format result according to output format.

        Args:
            result: Unified analysis result

        Returns:
            Formatted output string
        """
        if self.output_format == OutputFormat.JSON:
            return self._format_json(result)
        elif self.output_format == OutputFormat.JSONL:
            return self._format_jsonl(result)
        elif self.output_format == OutputFormat.MARKDOWN:
            return result.summary.to_markdown()
        elif self.output_format == OutputFormat.HTML:
            return result.summary.to_html()
        elif self.output_format == OutputFormat.CSV:
            return result.summary.to_csv()
        elif self.output_format == OutputFormat.SUMMARY:
            return self._format_summary(result)
        elif self.output_format == OutputFormat.DETAILED:
            return self._format_detailed(result)
        elif self.output_format == OutputFormat.SARIF:
            return self._format_sarif(result)
        else:
            return self._format_json(result)

    def _format_json(self, result: UnifiedAnalysisResult) -> str:
        """Format as JSON based on output level."""
        data = {}

        # Always include fingerprint and summary
        data["fingerprint"] = result.fingerprint.to_dict()
        data["summary"] = result.summary.model_dump()

        # Add details based on output level
        if self.output_level.value >= OutputLevel.NORMAL.value:
            data["vulnerabilities"] = [v.to_summary_dict() for v in result.vulnerabilities]

        if self.output_level.value >= OutputLevel.VERBOSE.value:
            data["ioctl_discovery"] = {
                "handler_address": result.ioctl_handler_address,
                "codes": result.ioctl_codes,
                "details": result.ioctl_discovery_details,
            }
            data["config"] = result.config

        if self.output_level.value >= OutputLevel.DEBUG.value:
            data["vulnerabilities"] = [v.to_rich_dict(include_raw_state=False) for v in result.vulnerabilities]
            data["errors"] = result.errors
            data["warnings"] = result.warnings

        if self.output_level.value >= OutputLevel.FULL.value:
            # Include everything, even raw state
            data["vulnerabilities"] = [v.to_rich_dict(include_raw_state=True) for v in result.vulnerabilities]
            if result.binary_metadata:
                data["binary_metadata"] = result.binary_metadata.model_dump()

        return json.dumps(data, indent=2, default=str)

    def _format_jsonl(self, result: UnifiedAnalysisResult) -> str:
        """Format as JSONL (one JSON object per line)."""
        lines = []

        # Summary line
        lines.append(json.dumps({"type": "summary", "data": result.summary.model_dump()}, default=str))

        # Vulnerability lines
        for vuln in result.vulnerabilities:
            lines.append(json.dumps({"type": "vulnerability", "data": vuln.to_summary_dict()}, default=str))

        return "\n".join(lines)

    def _format_summary(self, result: UnifiedAnalysisResult) -> str:
        """Format as text summary."""
        lines = [
            f"Driver: {result.summary.driver_name}",
            f"Hash: {result.summary.driver_hash[:16]}...",
            f"IOCTL Codes: {result.summary.ioctl_codes_found}",
            f"Vulnerabilities: {result.summary.vulnerabilities_found} ({result.summary.unique_vulnerabilities} unique)",
        ]

        if result.summary.severity_breakdown:
            severity_str = ", ".join(f"{k}: {v}" for k, v in result.summary.severity_breakdown.items())
            lines.append(f"Severity: {severity_str}")

        return "\n".join(lines)

    def _format_detailed(self, result: UnifiedAnalysisResult) -> str:
        """Format as detailed text output."""
        lines = [
            "=" * 80,
            f"ANALYSIS REPORT: {result.summary.driver_name}",
            "=" * 80,
            "",
            f"Driver Hash (BLAKE2b): {result.fingerprint.blake2b}",
            f"Analysis Date: {result.analysis_date.isoformat()}",
            f"Analysis Time: {result.analysis_time:.2f}s",
            f"IOCTLance Version: {result.ioctlance_version}",
            "",
        ]

        if result.ioctl_codes:
            lines.extend(
                [
                    f"IOCTL Handler: {result.ioctl_handler_address or 'Unknown'}",
                    f"IOCTL Codes Found ({len(result.ioctl_codes)}):",
                ]
            )
            for code in result.ioctl_codes:
                lines.append(f"  - {code}")
            lines.append("")

        if result.vulnerabilities:
            lines.extend(
                [
                    f"VULNERABILITIES ({result.summary.vulnerabilities_found}):",
                    "",
                ]
            )

            for vuln_type, vulns in result.vulnerability_groups.items():
                lines.append(f"{vuln_type} ({len(vulns)} instances):")
                for v in vulns[:3]:  # Show first 3 instances
                    lines.extend(
                        [
                            f"  - {v.vulnerability.title}",
                            f"    IOCTL: {v.vulnerability.eval.IoControlCode}",
                            f"    State: {v.vulnerability.state[:50]}...",
                        ]
                    )
                if len(vulns) > 3:
                    lines.append(f"  ... and {len(vulns) - 3} more")
                lines.append("")

        return "\n".join(lines)

    def _format_sarif(self, result: UnifiedAnalysisResult) -> str:
        """Format as SARIF (Static Analysis Results Interchange Format)."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurecdn.net/schemas/json/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "IOCTLance",
                            "version": result.ioctlance_version,
                            "informationUri": "https://github.com/mjbommar/ioctlance",
                            "rules": [],
                        }
                    },
                    "results": [],
                    "artifacts": [
                        {
                            "location": {"uri": str(self.driver_path) if self.driver_path else ""},
                            "hashes": {
                                "blake2b": result.fingerprint.blake2b,
                                "sha256": result.fingerprint.sha256,
                            },
                        }
                    ],
                }
            ],
        }

        # Add rules and results for each vulnerability
        rules = {}
        results = []

        for vuln in result.vulnerabilities:
            rule_id = vuln.vulnerability.vulnerability_type

            # Add rule if not already added
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": vuln.vulnerability.title.split(" - ")[0]},
                    "fullDescription": {"text": vuln.vulnerability.description},
                    "defaultConfiguration": {"level": vuln.vulnerability.severity.lower()},
                }

            # Add result
            results.append(
                {
                    "ruleId": rule_id,
                    "message": {"text": vuln.vulnerability.description},
                    "level": vuln.vulnerability.severity.lower(),
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": str(self.driver_path) if self.driver_path else "",
                                    "index": 0,
                                }
                            }
                        }
                    ],
                    "properties": {
                        "ioctl_code": vuln.vulnerability.eval.IoControlCode,
                        "state_address": str(vuln.vulnerability.state),
                    },
                }
            )

        sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
        sarif["runs"][0]["results"] = results

        return json.dumps(sarif, indent=2)

    def save_output(self, result: UnifiedAnalysisResult, output_path: Path) -> None:
        """Save formatted output to file.

        Args:
            result: Analysis result
            output_path: Output file path
        """
        output = self.format_output(result)

        with open(output_path, "w") as f:
            f.write(output)

        if self.output_level.value >= OutputLevel.VERBOSE.value:
            logger.info(f"Results saved to: {output_path}")

    def print_console_summary(self, result: UnifiedAnalysisResult) -> None:
        """Print summary to console.

        Args:
            result: Analysis result
        """
        print("\n[SUMMARY] Analysis Complete")
        print(f"  Driver: {result.summary.driver_name}")
        print(f"  Hash: {result.summary.driver_hash[:16]}...")
        print(f"  Time: {result.analysis_time:.2f}s")

        if result.ioctl_codes:
            print(f"\n[IOCTL] Found {len(result.ioctl_codes)} codes:")
            for code in result.ioctl_codes[:5]:
                print(f"  - {code}")
            if len(result.ioctl_codes) > 5:
                print(f"  ... and {len(result.ioctl_codes) - 5} more")

        if result.vulnerabilities:
            print(f"\n[VULNERABILITIES] Found {result.summary.vulnerabilities_found} issues:")

            # Group by severity
            by_severity = defaultdict(list)
            for vuln in result.vulnerability_summary:
                by_severity[vuln.severity].append(vuln)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity in by_severity:
                    print(f"\n  {severity}:")
                    for vuln_summary in by_severity[severity]:
                        if vuln_summary.count > 1:
                            print(f"    - {vuln_summary.type} ({vuln_summary.count} instances)")
                        else:
                            print(f"    - {vuln_summary.type}")
        else:
            print("\n[RESULT] No vulnerabilities detected")
