#!/usr/bin/env python
"""CLI for auditing IOCTLance vulnerability findings."""

import argparse
import json
import sys
from pathlib import Path
import logging

from rich.console import Console

from .audit import VulnerabilityAuditor, BatchAuditor
from .audit.batch_auditor import BatchAuditConfig


def main():
    """Main entry point for audit CLI."""
    parser = argparse.ArgumentParser(
        description="Audit IOCTLance vulnerability findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit from IOCTLance output
  ioctlance driver.sys -o results.json
  ioctlance-audit results.json

  # Audit from batch results
  ioctlance-batch /drivers -o batch.jsonl
  ioctlance-audit batch.jsonl

  # Pipe directly
  ioctlance driver.sys --json | ioctlance-audit -
        """,
    )

    parser.add_argument("input", help="IOCTLance output file (JSON/JSONL) or - for stdin")

    parser.add_argument("-o", "--output", type=Path, help="Save audit results")

    parser.add_argument("--timeout", type=int, default=300, help="Timeout per audit (seconds, default 300)")

    parser.add_argument("--parallel", type=int, default=1, help="Parallel workers for batch")

    parser.add_argument("--claude-command", default="npx @anthropic-ai/claude-code", help="Claude CLI command (default: npx @anthropic-ai/claude-code)")

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(message)s")

    console = Console()

    # Read input
    if args.input == "-":
        data = json.loads(sys.stdin.read())
        input_type = "json"
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            console.print(f"[red]Error: {input_path} not found[/red]")
            return 1

        # Detect format
        with open(input_path) as f:
            first_line = f.readline()
            f.seek(0)

            if input_path.suffix == ".jsonl" or '"type":"driver_result"' in first_line:
                input_type = "jsonl"
                data = input_path
            else:
                data = json.load(f)
                input_type = "json"

    # Handle JSONL batch files
    if input_type == "jsonl":
        config = BatchAuditConfig(
            parallel_workers=args.parallel,
            timeout_per_audit=args.timeout,
            claude_command=args.claude_command,
            verbose=args.verbose,
        )
        auditor = BatchAuditor(config)
        summary = auditor.audit_batch_results(data, args.output)
        return 0

    # Handle single JSON files
    # Check if this is a batch results file
    if "results" in data and isinstance(data["results"], list):
        # This is a batch results file with multiple drivers
        all_vulns = []
        for driver_result in data["results"]:
            driver_data = driver_result.get("result", {})
            driver_path = Path(
                driver_data.get("fingerprint", {}).get("file_path", driver_result.get("driver", "unknown"))
            )
            driver_vulns = driver_data.get("vulnerabilities", [])

            for v in driver_vulns:
                vuln_data = v.get("vulnerability", v) if isinstance(v, dict) else v
                if vuln_data:
                    vuln_data["_driver_path"] = str(driver_path)
                    all_vulns.append(vuln_data)

        if not all_vulns:
            console.print("[yellow]No vulnerabilities found in batch results[/yellow]")
            return 0

        console.print(f"[cyan]Auditing {len(all_vulns)} vulnerabilities from {len(data['results'])} drivers[/cyan]")
        vulns = all_vulns
        driver_path = Path("batch_audit")  # Generic name for batch
    else:
        # Single driver format
        driver_path = Path(
            data.get("fingerprint", {}).get("file_path") or data.get("summary", {}).get("driver_name", "unknown")
        )

        # Get vulnerabilities - handle nested structure
        vulns = []
        for v in data.get("vulnerabilities", []):
            if isinstance(v, dict) and "vulnerability" in v:
                vulns.append(v["vulnerability"])
            else:
                vulns.append(v)

    if not vulns:
        console.print("[yellow]No vulnerabilities found[/yellow]")
        return 0

    console.print(f"[cyan]Auditing {len(vulns)} vulnerabilities from {driver_path.name}[/cyan]")

    # Audit each vulnerability
    auditor = VulnerabilityAuditor(claude_command=args.claude_command, verbose=args.verbose)
    results = []

    # Helper function to save partial results
    def save_results():
        if args.output:
            with open(args.output, "w") as f:
                json.dump(
                    {
                        "driver": str(driver_path),
                        "total": len(vulns),
                        "audited": len(results),
                        "results": results,
                        "status": "partial" if len(results) < len(vulns) else "complete",
                    },
                    f,
                    indent=2,
                )
            if args.verbose:
                console.print(f"  [dim]→ Saved {len(results)} results to {args.output}[/dim]")

    for i, vuln in enumerate(vulns, 1):
        title = vuln.get("title", "Unknown")
        ioctl = vuln.get("eval", {}).get("IoControlCode")
        # Use driver path from vuln if available (for batch mode)
        vuln_driver_path = Path(vuln.get("_driver_path", str(driver_path)))
        console.print(f"\n[{i}/{len(vulns)}] {title} (IOCTL: {ioctl}) - {vuln_driver_path.name}")

        try:
            result = auditor.audit(vuln_driver_path, vuln, args.timeout)
            console.print(f"  → {result.classification} ({result.confidence}%)")

            results.append(
                {
                    "vulnerability": title,
                    "ioctl": ioctl,
                    "classification": result.classification,
                    "confidence": result.confidence,
                    "reasoning": result.reasoning,
                }
            )
        except Exception as e:
            console.print(f"  [red]→ Error: {e}[/red]")
            results.append({"vulnerability": title, "ioctl": ioctl, "classification": "ERROR", "error": str(e)})

        # Save after each vulnerability
        save_results()

    # Final save
    if args.output:
        console.print(f"\n[green]Final results saved to {args.output}[/green]")

    # Summary
    tp = sum(1 for r in results if r.get("classification") == "TRUE_POSITIVE")
    fp = sum(1 for r in results if r.get("classification") == "FALSE_POSITIVE")

    console.print(f"\n[bold]Summary:[/bold] {tp} true positives, {fp} false positives")

    return 0


if __name__ == "__main__":
    sys.exit(main())
