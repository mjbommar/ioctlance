#!/usr/bin/env python
"""CLI for batch analysis of Windows drivers."""

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console

from .batch import BatchAnalyzer, BatchConfig, ProcessingMode, OutputFormat


def main():
    """Main entry point for batch analysis CLI."""
    parser = argparse.ArgumentParser(
        description="Batch analyze Windows drivers with IOCTLance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all drivers in a directory (streams JSONL by default)
  ioctlance-batch /path/to/drivers -o results.jsonl

  # Use memory-safe mode for large archives
  ioctlance-batch /nas4/data/drivers -o results.jsonl --mode safe --batch-size 50

  # Resume from previous analysis
  ioctlance-batch /path/to/drivers --resume previous_results.json

  # Only output vulnerable drivers
  ioctlance-batch /path/to/drivers --filter-vulns -o vulnerable.json
        """,
    )

    parser.add_argument("path", type=Path, help="Path to directory containing drivers or single driver file")

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default="batch_results.jsonl",
        help="Output file for results (default: batch_results.jsonl)",
    )

    parser.add_argument("--format", choices=["json", "jsonl"], default="jsonl", help="Output format (default: jsonl)")

    parser.add_argument("-t", "--timeout", type=int, default=120, help="Timeout per driver in seconds (default: 120)")

    parser.add_argument(
        "--mode",
        choices=["parallel", "safe", "sequential"],
        default="parallel",
        help="Processing mode (default: parallel). 'safe' maps to 'parallel' in the new engine.",
    )

    parser.add_argument(
        "-w", "--workers", type=int, default=None, help="Number of parallel workers (default: CPU count)"
    )

    # Legacy options (ignored in redesigned engine; kept for compatibility)
    parser.add_argument("--batch-size", type=int, default=100, help=argparse.SUPPRESS)
    parser.add_argument("--memory-threshold", type=float, default=80.0, help=argparse.SUPPRESS)
    parser.add_argument("--memory-percent", type=int, default=85, help=argparse.SUPPRESS)

    parser.add_argument("--no-recursive", action="store_true", help="Don't recursively search subdirectories")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # Search strategy controls
    parser.add_argument(
        "--search",
        choices=["dfs", "beam"],
        default="beam",
        help="Path exploration strategy (default: beam)",
    )
    parser.add_argument(
        "--beam-width", type=int, default=64, help="Beam width when --search beam is used (default: 64)"
    )
    parser.add_argument("--triage-steps", type=int, default=3000, help="Beam triage window steps (default: 3000)")
    parser.add_argument(
        "--triage-beam-width", type=int, default=24, help="Beam width during triage window (default: 24)"
    )

    parser.add_argument(
        "--profile",
        choices=["fast", "balanced", "thorough", "paranoid", "memory_safe"],
        default=None,
        help="Analysis profile with preset timeouts and limits (overrides timeout)",
    )

    parser.add_argument("--resume", type=Path, help="Resume from previous results file")

    parser.add_argument(
        "--filter-vulns",
        action="store_true",
        help="Only include drivers with vulnerabilities in output (applies to JSON and JSONL)",
    )

    parser.add_argument("--no-progress", action="store_true", help="Disable progress display")

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    # Verification settings (enabled by default for better accuracy)
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable post-detection verification (not recommended - increases false positives)",
    )

    parser.add_argument(
        "--verification-level",
        choices=["none", "basic", "standard", "deep"],
        default="standard",
        help="Verification depth: none|basic|standard|deep (default: standard)",
    )

    parser.add_argument(
        "--keep-false-positives", action="store_true", help="Don't filter false positives (keeps all detections)"
    )

    parser.add_argument("--no-reclassify", action="store_true", help="Don't reclassify misidentified vulnerabilities")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create console early so it's available
    console = Console()

    # Adjust timeout based on profile if specified
    timeout = args.timeout
    if args.profile:
        from .core.analysis_context import AnalysisConfig

        try:
            profile_config = AnalysisConfig.from_profile(args.profile)
            timeout = profile_config.timeout
            if args.verbose:
                console.print(f"[cyan]Using profile '{args.profile}' with {timeout}s timeout[/cyan]")
        except ValueError:
            # Keep user-specified timeout if profile is invalid
            if args.verbose:
                console.print(f"[yellow]Unknown profile '{args.profile}', using default timeout[/yellow]")

    # Create batch configuration
    # Map legacy 'safe' mode to parallel
    mode = args.mode if args.mode != "safe" else "parallel"

    config = BatchConfig(
        output_path=args.output,
        output_format=OutputFormat(args.format),
        timeout_per_driver=timeout,
        processing_mode=ProcessingMode(mode),
        num_workers=args.workers,
        recursive_search=not args.no_recursive,
        filter_vulnerable=args.filter_vulns,
        resume_from=args.resume,
        verbose=args.verbose,
        show_progress=not args.no_progress,
        analysis_profile=args.profile,  # Pass profile to config
        search_strategy=args.search,
        beam_width=args.beam_width,
        triage_steps=args.triage_steps,
        triage_beam_width=args.triage_beam_width,
        # Verification settings (enabled by default)
        verification_enabled=not args.no_verify,
        verification_level=args.verification_level if not args.no_verify else "none",
        filter_false_positives=not args.keep_false_positives,
        reclassify_vulnerabilities=not args.no_reclassify,
    )

    # Run analyzer (console already created above)

    try:
        analyzer = BatchAnalyzer(config, console)
        result = analyzer.analyze_path(args.path)

        # Exit with appropriate code
        if result.stats.failed > 0:
            return 1  # Some failures
        return 0  # Success

    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
