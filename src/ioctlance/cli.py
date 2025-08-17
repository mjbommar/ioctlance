"""Command-line interface for IOCTLance vulnerability scanner."""

import argparse
import json
import logging
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)

logger = logging.getLogger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for IOCTLance.

    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        prog="ioctlance",
        description="IOCTLance - Windows Driver Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Required arguments
    parser.add_argument("driver", type=str, help="Path to Windows driver file or directory to analyze")

    # Optional arguments
    parser.add_argument("-o", "--output", type=str, help="Output file for results (JSON format)")

    parser.add_argument("-t", "--timeout", type=int, default=120, help="Maximum analysis time in seconds")

    parser.add_argument("--ioctl", type=str, help="Specific IOCTL code to test (hex format, e.g., 0x22201c)")

    parser.add_argument(
        "--address",
        "--ioctl-handler",
        type=str,
        dest="ioctl_handler",
        help="Address of IOCTL handler to skip discovery (hex format, e.g., 0x13e8)",
    )

    parser.add_argument(
        "--global-var-size",
        type=int,
        default=0x1000,
        help="Size of .data section to symbolize in bytes",
    )

    parser.add_argument("--complete", action="store_true", help="Complete mode - continue until STATUS_SUCCESS")

    parser.add_argument("--bound", type=int, help="Maximum loop iterations")

    parser.add_argument("--length", type=int, help="Maximum instruction count")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")

    parser.add_argument("--version", action="version", version="%(prog)s 0.2.0")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for IOCTLance CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv)

    Returns:
        Exit code (0 for success)
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    # Set logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    elif args.json:
        # In JSON mode, suppress most logs but keep ERROR and WARNING
        logging.getLogger().setLevel(logging.WARNING)
    else:
        # Default: show INFO level for progress tracking
        logging.getLogger().setLevel(logging.INFO)

    # Validate driver path
    driver_path = Path(args.driver)
    if not driver_path.exists():
        logger.error(f"Path not found: {driver_path}")
        return 1

    # Collect driver files to analyze
    driver_files: list[Path] = []

    if driver_path.is_file():
        # Single file mode
        driver_files.append(driver_path)
    elif driver_path.is_dir():
        # Directory mode - find all .sys files
        driver_files = list(driver_path.glob("*.sys"))
        if not driver_files:
            logger.error(f"No .sys files found in directory: {driver_path}")
            return 1
        logger.info(f"Found {len(driver_files)} driver(s) to analyze in {driver_path}")
    else:
        logger.error(f"Invalid path type: {driver_path}")
        return 1

    # Process each driver
    all_results = []
    failed_drivers = []

    for driver_file in driver_files:
        logger.info(f"Analyzing driver: {driver_file}")
        logger.info(f"Timeout: {args.timeout} seconds")

        if args.ioctl:
            logger.info(f"Testing specific IOCTL: {args.ioctl}")

        try:
            # Create configuration from CLI arguments
            from ioctlance.core.analysis_context import AnalysisConfig, AnalysisContext
            from ioctlance.core.driver_analyzer import DriverAnalyzer

            config_kwargs = {
                "timeout": args.timeout,
                "target_ioctl": args.ioctl,
                "global_var_size": args.global_var_size,
                "complete_mode": args.complete,
                "debug": args.debug,
            }

            if args.bound:
                config_kwargs["bound"] = args.bound
            if args.length:
                config_kwargs["length"] = args.length
            if args.ioctl_handler:
                config_kwargs["ioctl_handler_addr"] = args.ioctl_handler

            # Create config and context with all parameters
            config = AnalysisConfig(**config_kwargs)
            context = AnalysisContext.create_for_driver(driver_file, config)

            # Run analysis
            analyzer = DriverAnalyzer(context)
            result = analyzer.analyze()

            # Display results (unless in JSON mode)
            if not args.json:
                # Basic information
                if result.basic.IoControlCodes:
                    logger.info(f"Found {len(result.basic.IoControlCodes)} IOCTL codes")

                # Vulnerabilities
                if result.vuln:
                    logger.warning(f"Found {len(result.vuln)} vulnerabilities!")
                    for i, vuln in enumerate(result.vuln, 1):
                        logger.warning(f"  {i}. {vuln.title}: {vuln.description}")
                else:
                    logger.info("No vulnerabilities detected")

                # Errors
                if result.error and args.debug:
                    for error in result.error:
                        logger.debug(f"Error: {error}")

            # Store result - use model_dump_json to handle datetime serialization
            all_results.append({"driver": str(driver_file), "result": json.loads(result.model_dump_json())})

        except KeyboardInterrupt:
            logger.error("\nAnalysis interrupted by user")
            return 130

        except Exception as e:
            logger.error(f"Failed to analyze {driver_file}: {e}")
            failed_drivers.append(str(driver_file))
            if args.debug:
                import traceback

                traceback.print_exc()
            continue

    # Output results
    if args.json or args.output:
        # Prepare output data
        if len(driver_files) > 1:
            output_data = {
                "drivers_analyzed": len(driver_files),
                "drivers_failed": len(failed_drivers),
                "results": all_results,
                "failed": failed_drivers,
            }
        else:
            # Single file - save just the result
            output_data = all_results[0]["result"] if all_results else {}

        # Output to file if requested
        if args.output:
            output_path = Path(args.output)
            with open(output_path, "w") as f:
                json.dump(output_data, f, indent=2)
            if not args.json:
                logger.info(f"Results saved to: {output_path}")

        # Output to stdout if JSON mode
        if args.json:
            print(json.dumps(output_data, indent=2))

    # Summary for batch mode
    if len(driver_files) > 1:
        successful = len(driver_files) - len(failed_drivers)
        total = len(driver_files)
        logger.info(f"Analysis complete: {successful}/{total} drivers processed successfully")
        if failed_drivers:
            logger.warning(f"Failed drivers: {', '.join(failed_drivers)}")

    # Return non-zero if any drivers failed
    return 1 if failed_drivers else 0


def run() -> None:
    """Entry point for console script."""
    sys.exit(main())


if __name__ == "__main__":
    run()
