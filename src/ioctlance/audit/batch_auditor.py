"""Batch auditor for processing multiple vulnerabilities from IOCTLance results."""

import json
from pathlib import Path
from typing import Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
from enum import Enum

from pydantic import BaseModel, Field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from .auditor import VulnerabilityAuditor, AuditResult, AuditClassification

logger = logging.getLogger(__name__)


class BatchAuditConfig(BaseModel):
    """Configuration for batch auditing."""

    parallel_workers: int = Field(default=1, ge=1, le=10)
    timeout_per_audit: int = Field(default=300, ge=60, le=3600)
    filter_severity: str | None = None
    filter_type: str | None = None
    skip_likely_false_positives: bool = True
    audit_limit: int | None = None
    claude_command: str = Field(default="claude")
    verbose: bool = False

    class Config:
        validate_assignment = True


class BatchAuditSummary(BaseModel):
    """Summary of batch audit results."""

    timestamp: datetime
    total_vulnerabilities: int
    total_audited: int
    classifications: dict[str, int] = Field(
        default_factory=lambda: {"TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "NEEDS_REVIEW": 0, "ERROR": 0}
    )
    results: list[dict[str, Any]] = Field(default_factory=list)

    def add_result(self, driver_path: str, vuln: dict[str, Any], audit_result: AuditResult):
        """Add an audit result to the summary."""
        result_entry = {
            "driver": str(driver_path),
            "vulnerability": vuln.get("title", "Unknown"),
            "ioctl": vuln.get("eval", {}).get("IoControlCode", "unknown"),
            "classification": audit_result.classification,
            "confidence": audit_result.confidence,
            "reasoning": audit_result.reasoning,
        }

        if audit_result.vulnerable_address:
            result_entry["vulnerable_address"] = audit_result.vulnerable_address

        self.results.append(result_entry)
        self.classifications[audit_result.classification] += 1


class BatchAuditor:
    """Processes multiple vulnerabilities from batch_results.jsonl."""

    def __init__(self, config: BatchAuditConfig | None = None):
        """
        Initialize the batch auditor.

        Args:
            config: Batch audit configuration
        """
        self.config = config or BatchAuditConfig()
        self.auditor = VulnerabilityAuditor(claude_command=self.config.claude_command, verbose=self.config.verbose)
        self.console = Console()

    def audit_batch_results(self, batch_results_path: Path, output_path: Path | None = None) -> BatchAuditSummary:
        """
        Audit vulnerabilities from a batch_results.jsonl file.

        Args:
            batch_results_path: Path to batch_results.jsonl
            output_path: Optional path to save summary JSON

        Returns:
            BatchAuditSummary with all results
        """
        # Load and parse results
        vulnerabilities = self._load_vulnerabilities(batch_results_path)

        if not vulnerabilities:
            self.console.print("[yellow]No vulnerabilities found to audit[/yellow]")
            return BatchAuditSummary(timestamp=datetime.now(), total_vulnerabilities=0, total_audited=0)

        self.console.print(f"[cyan]Found {len(vulnerabilities)} vulnerabilities to audit[/cyan]")

        # Apply filters
        filtered = self._apply_filters(vulnerabilities)
        self.console.print(f"[cyan]After filtering: {len(filtered)} vulnerabilities[/cyan]")

        # Create summary
        summary = BatchAuditSummary(
            timestamp=datetime.now(), total_vulnerabilities=len(vulnerabilities), total_audited=len(filtered)
        )

        # Audit vulnerabilities
        if self.config.parallel_workers > 1:
            self._audit_parallel(filtered, summary)
        else:
            self._audit_sequential(filtered, summary)

        # Save summary if requested
        if output_path:
            self._save_summary(summary, output_path)

        # Print summary
        self._print_summary(summary)

        return summary

    def _load_vulnerabilities(self, path: Path) -> list[dict[str, Any]]:
        """Load vulnerabilities from JSONL file."""
        vulnerabilities = []

        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)

                    # Handle different JSONL formats
                    if data.get("type") == "driver_result":
                        driver_data = data.get("data", {})
                    else:
                        driver_data = data

                    driver_path = driver_data.get("path", "unknown")
                    driver_vulns = driver_data.get("vulnerabilities", [])

                    for vuln in driver_vulns:
                        vuln["driver_path"] = driver_path
                        vulnerabilities.append(vuln)

                except json.JSONDecodeError as e:
                    logger.warning(f"Skipping malformed line: {e}")

        return vulnerabilities

    def _apply_filters(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply configured filters to vulnerability list."""
        filtered = vulnerabilities

        # Filter by severity
        if self.config.filter_severity:
            severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if self.config.filter_severity in severity_order:
                min_idx = severity_order.index(self.config.filter_severity)
                filtered = [
                    v for v in filtered if severity_order.index(v.get("others", {}).get("severity", "LOW")) >= min_idx
                ]

        # Filter by type
        if self.config.filter_type:
            filtered = [v for v in filtered if v.get("others", {}).get("type") == self.config.filter_type]

        # Skip likely false positives
        if self.config.skip_likely_false_positives:
            filtered = [v for v in filtered if not self._is_likely_false_positive(v)]

        # Apply limit
        if self.config.audit_limit:
            filtered = filtered[: self.config.audit_limit]

        return filtered

    def _is_likely_false_positive(self, vuln: dict[str, Any]) -> bool:
        """Check if a vulnerability is likely a false positive."""
        # Common false positive patterns

        # NULL pointer dereferences often misclassified as buffer overflows
        if vuln.get("others", {}).get("type") == "unconstrained_state" and "NULL" in vuln.get("description", ""):
            return True

        # SystemBuffer = 0x0 usually indicates NULL pointer, not buffer overflow
        if vuln.get("eval", {}).get("SystemBuffer") == "0x0" and "Buffer Overflow" in vuln.get("title", ""):
            return True

        return False

    def _audit_sequential(self, vulnerabilities: list[dict[str, Any]], summary: BatchAuditSummary):
        """Audit vulnerabilities sequentially."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console,
        ) as progress:
            task = progress.add_task("[cyan]Auditing vulnerabilities...", total=len(vulnerabilities))

            for vuln in vulnerabilities:
                driver_path = Path(vuln.get("driver_path", "unknown"))
                vuln_title = vuln.get("title", "Unknown")

                progress.update(task, description=f"[cyan]Auditing: {driver_path.name} - {vuln_title}")

                # Audit the vulnerability
                try:
                    audit_result = self.auditor.audit(driver_path, vuln, timeout=self.config.timeout_per_audit)

                    summary.add_result(driver_path, vuln, audit_result)

                    # Show result
                    if audit_result.classification == AuditClassification.TRUE_POSITIVE:
                        self.console.print(f"  [red]✗[/red] TRUE POSITIVE: {driver_path.name} - {vuln_title}")
                    elif audit_result.classification == AuditClassification.FALSE_POSITIVE:
                        self.console.print(f"  [green]✓[/green] FALSE POSITIVE: {driver_path.name} - {vuln_title}")
                    elif audit_result.classification == AuditClassification.NEEDS_REVIEW:
                        self.console.print(f"  [yellow]?[/yellow] NEEDS REVIEW: {driver_path.name} - {vuln_title}")
                    else:
                        self.console.print(f"  [red]![/red] ERROR: {driver_path.name} - {vuln_title}")

                except Exception as e:
                    logger.error(f"Failed to audit {driver_path}: {e}")
                    error_result = AuditResult(classification=AuditClassification.ERROR, confidence=0, reasoning=str(e))
                    summary.add_result(driver_path, vuln, error_result)

                progress.advance(task)

    def _audit_parallel(self, vulnerabilities: list[dict[str, Any]], summary: BatchAuditSummary):
        """Audit vulnerabilities in parallel."""
        self.console.print(f"[cyan]Starting parallel audit with {self.config.parallel_workers} workers[/cyan]")

        with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
            # Submit all audit tasks
            futures = {}
            for vuln in vulnerabilities:
                driver_path = Path(vuln.get("driver_path", "unknown"))
                future = executor.submit(self.auditor.audit, driver_path, vuln, self.config.timeout_per_audit)
                futures[future] = (driver_path, vuln)

            # Process results as they complete
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console,
            ) as progress:
                task = progress.add_task("[cyan]Auditing vulnerabilities...", total=len(futures))

                for future in as_completed(futures):
                    driver_path, vuln = futures[future]
                    vuln_title = vuln.get("title", "Unknown")

                    try:
                        audit_result = future.result()
                        summary.add_result(driver_path, vuln, audit_result)

                        # Show result
                        if audit_result.classification == AuditClassification.TRUE_POSITIVE:
                            self.console.print(f"  [red]✗[/red] TRUE POSITIVE: {driver_path.name} - {vuln_title}")
                        elif audit_result.classification == AuditClassification.FALSE_POSITIVE:
                            self.console.print(f"  [green]✓[/green] FALSE POSITIVE: {driver_path.name} - {vuln_title}")
                        elif audit_result.classification == AuditClassification.NEEDS_REVIEW:
                            self.console.print(f"  [yellow]?[/yellow] NEEDS REVIEW: {driver_path.name} - {vuln_title}")
                        else:
                            self.console.print(f"  [red]![/red] ERROR: {driver_path.name} - {vuln_title}")

                    except Exception as e:
                        logger.error(f"Failed to audit {driver_path}: {e}")
                        error_result = AuditResult(
                            classification=AuditClassification.ERROR, confidence=0, reasoning=str(e)
                        )
                        summary.add_result(driver_path, vuln, error_result)

                    progress.advance(task)

    def _save_summary(self, summary: BatchAuditSummary, path: Path):
        """Save audit summary to JSON file."""
        with open(path, "w") as f:
            json.dump(summary.model_dump(), f, indent=2, default=str)

        self.console.print(f"[green]Summary saved to {path}[/green]")

    def _print_summary(self, summary: BatchAuditSummary):
        """Print audit summary to console."""
        self.console.print("\n" + "=" * 60)
        self.console.print("[bold]AUDIT SUMMARY[/bold]")
        self.console.print("=" * 60)
        self.console.print(f"Total vulnerabilities found: {summary.total_vulnerabilities}")
        self.console.print(f"Total audited: {summary.total_audited}")
        self.console.print(f"[red]True Positives:  {summary.classifications['TRUE_POSITIVE']}[/red]")
        self.console.print(f"[green]False Positives: {summary.classifications['FALSE_POSITIVE']}[/green]")
        self.console.print(f"[yellow]Needs Review:    {summary.classifications['NEEDS_REVIEW']}[/yellow]")
        self.console.print(f"[red]Errors:          {summary.classifications['ERROR']}[/red]")

        # Calculate accuracy if we have results
        if summary.total_audited > 0:
            tp = summary.classifications["TRUE_POSITIVE"]
            fp = summary.classifications["FALSE_POSITIVE"]
            if (tp + fp) > 0:
                precision = (tp / (tp + fp)) * 100
                self.console.print(f"\n[cyan]Precision: {precision:.1f}%[/cyan]")
