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
  # Analyze all drivers in a directory
  ioctlance-batch /path/to/drivers -o results.json

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
        default="batch_results.json",
        help="Output file for results (default: batch_results.json)",
    )

    parser.add_argument("--format", choices=["json", "jsonl"], default="json", help="Output format (default: json)")

    parser.add_argument("-t", "--timeout", type=int, default=120, help="Timeout per driver in seconds (default: 120)")

    parser.add_argument(
        "--mode",
        choices=["parallel", "safe", "sequential"],
        default="parallel",
        help="Processing mode (default: parallel)",
    )

    parser.add_argument(
        "-w", "--workers", type=int, default=None, help="Number of parallel workers (default: CPU count)"
    )

    parser.add_argument("--batch-size", type=int, default=100, help="Batch size for safe mode (default: 100)")

    parser.add_argument(
        "--memory-threshold", type=float, default=80.0, help="Memory threshold in GB for safe mode (default: 80)"
    )

    parser.add_argument(
        "--memory-percent", type=int, default=85, help="Memory percent threshold for safe mode (default: 85)"
    )

    parser.add_argument("--no-recursive", action="store_true", help="Don't recursively search subdirectories")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument(
        "--profile",
        choices=["fast", "balanced", "thorough", "paranoid", "memory_safe"],
        default=None,
        help="Analysis profile with preset timeouts and limits (overrides timeout)",
    )

    parser.add_argument("--resume", type=Path, help="Resume from previous results file")

    parser.add_argument(
        "--filter-vulns", action="store_true", help="Only include drivers with vulnerabilities in output"
    )

    parser.add_argument("--no-progress", action="store_true", help="Disable progress display")

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

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
    config = BatchConfig(
        output_path=args.output,
        output_format=OutputFormat(args.format),
        timeout_per_driver=timeout,
        processing_mode=ProcessingMode(args.mode),
        num_workers=args.workers,
        batch_size=args.batch_size,
        memory_threshold_gb=args.memory_threshold,
        memory_percent_threshold=args.memory_percent,
        recursive_search=not args.no_recursive,
        filter_vulnerable=args.filter_vulns,
        resume_from=args.resume,
        verbose=args.verbose,
        show_progress=not args.no_progress,
        analysis_profile=args.profile,  # Pass profile to config
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
