"""Main driver analysis orchestrator for IOCTLance."""

import asyncio
import logging
import resource
import time
from pathlib import Path
from typing import Any

from ..core.analysis_context import AnalysisConfig, AnalysisContext
from ..core.ioctl_handler import find_ioctl_handler
from ..core.vulnerability_hunter import VulnerabilityHunter
from ..models import AnalysisResult, BasicInfo, DriverInfo, IOCTLHandler
from ..utils.helpers import find_device_names, find_driver_type

logger = logging.getLogger(__name__)


class DriverAnalyzer:
    """Orchestrates the complete driver analysis process."""

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the driver analyzer.

        Args:
            context: Analysis context
        """
        self.context = context

    def analyze(self) -> AnalysisResult:
        """Perform complete driver analysis.

        Returns:
            Analysis result with all findings
        """
        # Track overall timing
        total_start = time.time()

        # Find driver type
        self.context.driver_type = find_driver_type(self.context.project)
        if self.context.driver_type != "wdm":
            logger.warning(f"Driver type {self.context.driver_type} not supported (only WDM)")
            return self._create_empty_result()

        # Find device names
        self.context.device_names = find_device_names(self.context.driver_path)

        # Phase 0: Scan and hook dangerous CPU instructions
        logger.info("Phase 0: Scanning for dangerous CPU instructions...")
        from .opcode_scanner import scan_and_hook_opcodes

        # Store context in project globals so hooks can access it
        if not hasattr(self.context.project, "globals"):
            self.context.project.globals = {}
        self.context.project.globals["analysis_context"] = self.context

        opcode_hooks = scan_and_hook_opcodes(self.context)
        if opcode_hooks:
            total_hooks = sum(len(addrs) for addrs in opcode_hooks.values())
            logger.debug(f"Installed {total_hooks} instruction hooks")

        # Phase 1: Find IOCTL handler
        logger.info("Phase 1: Finding IOCTL handler...")
        handler_start_time = time.time()
        handler_start_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        ioctl_handler, handler_state = self._find_ioctl_handler()

        handler_time = round(time.time() - handler_start_time)
        handler_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - handler_start_memory

        if not ioctl_handler:
            logger.error("IOCTL handler not found")
            return self._create_empty_result()

        logger.info(f"IOCTL handler found at: {ioctl_handler.address}")

        # Phase 2: Hunt vulnerabilities
        logger.info("Phase 2: Hunting vulnerabilities...")
        hunt_start_time = time.time()
        hunt_start_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        hunter = VulnerabilityHunter(self.context)

        # Use handler state or blank state
        if not handler_state:
            logger.debug("Using blank state for vulnerability hunting")
            import angr

            handler_state = self.context.project.factory.blank_state(add_options=angr.options.resilience)

        # Hunt for vulnerabilities
        handler_addr = int(ioctl_handler.address, 16)
        vulnerabilities = hunter.hunt(handler_state, handler_addr, self.context.config.target_ioctl)

        hunt_time = round(time.time() - hunt_start_time)
        hunt_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - hunt_start_memory

        # The IOCTLs are discovered during vulnerability hunting, not handler discovery
        # Update the handler with discovered IOCTLs
        if self.context.ioctl_codes and not ioctl_handler.ioctl_codes:
            ioctl_handler.ioctl_codes = self.context.ioctl_codes.copy()

        # Log discovered IOCTLs
        logger.info(f"Discovered {len(ioctl_handler.ioctl_codes)} IOCTL codes: {ioctl_handler.ioctl_codes}")

        # Create result
        basic_info = BasicInfo(
            path=str(self.context.driver_path),
            DeviceName=self.context.device_names,
            time={"ioctl handler": handler_time, "hunting vulns": hunt_time},
            memory={"ioctl handler": handler_memory, "hunting vulns": hunt_memory},
            unique_addr={
                "ioctl handler": len(self.context.unique_addresses),
                "hunting vulns": len(self.context.unique_addresses),  # Update tracking
            },
            ioctl_handler=ioctl_handler.address,
            IoControlCodes=ioctl_handler.ioctl_codes or self.context.ioctl_codes,
        )

        # Convert vulnerabilities to model format
        vuln_models = []
        for vuln_dict in vulnerabilities:
            try:
                # Convert legacy format to model
                from ..models import Vulnerability, VulnerabilityEvaluation

                eval_data = vuln_dict.get("eval", {})
                vuln = Vulnerability(
                    title=vuln_dict.get("title", "Unknown"),
                    description=vuln_dict.get("description", ""),
                    state=vuln_dict.get("state", "<SimState @ 0x0>"),
                    eval=VulnerabilityEvaluation(
                        IoControlCode=eval_data.get("IoControlCode", "0x0"),
                        SystemBuffer=eval_data.get("SystemBuffer", "0x0"),
                        Type3InputBuffer=eval_data.get("Type3InputBuffer", "0x0"),
                        UserBuffer=eval_data.get("UserBuffer", "0x0"),
                        InputBufferLength=eval_data.get("InputBufferLength", "0x0"),
                        OutputBufferLength=eval_data.get("OutputBufferLength", "0x0"),
                    ),
                    parameters=vuln_dict.get("parameters", {}),
                    others=vuln_dict.get("others", {}),
                    raw_data=vuln_dict.get("raw_data"),  # Include raw data if present
                )
                vuln_models.append(vuln)
            except Exception as e:
                self.context.print_error(f"Error converting vulnerability: {e}")

        result = AnalysisResult(
            basic=basic_info,
            vuln=vuln_models,
            error=self.context.error_messages,
            driver_info=DriverInfo.from_file(self.context.driver_path),
            ioctl_handler=ioctl_handler,
            analysis_time=time.time() - total_start,
        )

        self.context.print_info(f"Analysis complete: {result.vulnerability_count} vulnerabilities found")

        return result

    def _find_ioctl_handler(self) -> tuple[IOCTLHandler | None, Any | None]:
        """Find the IOCTL handler.

        Returns:
            Tuple of (handler, state) or (None, None) if not found
        """
        # Check if address is provided directly
        if hasattr(self.context.config, "ioctl_handler_addr") and self.context.config.ioctl_handler_addr:
            addr = self.context.config.ioctl_handler_addr
            handler = IOCTLHandler(address=addr if addr.startswith("0x") else f"0x{addr}", ioctl_codes=[])
            return handler, None

        # Find handler through symbolic execution
        handler, state = find_ioctl_handler(
            self.context.driver_path,
            timeout=self.context.config.timeout,
            global_var_size=self.context.config.global_var_size,
            complete_mode=self.context.config.complete_mode,
        )

        if handler:
            return handler, state

        return None, None

    def _create_empty_result(self) -> AnalysisResult:
        """Create an empty analysis result.

        Returns:
            Empty analysis result
        """
        basic_info = BasicInfo(
            path=str(self.context.driver_path),
            DeviceName=self.context.device_names,
            time={},
            memory={},
            unique_addr={},
            ioctl_handler="0x0",
            IoControlCodes=[],
        )

        return AnalysisResult(basic=basic_info, vuln=[], error=self.context.error_messages)


def analyze_driver(driver_path: Path | str, timeout: int = 120, ioctl_code: str | None = None) -> AnalysisResult:
    """Analyze a Windows driver for vulnerabilities.

    Args:
        driver_path: Path to the driver file
        timeout: Maximum analysis time in seconds
        ioctl_code: Specific IOCTL code to test

    Returns:
        Analysis result with findings
    """
    # Create configuration
    config = AnalysisConfig(timeout=timeout, target_ioctl=ioctl_code)

    # Create context
    context = AnalysisContext.create_for_driver(driver_path, config)

    # Run analysis
    analyzer = DriverAnalyzer(context)
    return analyzer.analyze()


async def analyze_driver_async(
    driver_path: Path | str, max_time: int = 120, ioctl_code: str | None = None
) -> AnalysisResult:
    """Async wrapper for driver analysis.

    Args:
        driver_path: Path to the driver file
        max_time: Maximum analysis time in seconds
        ioctl_code: Specific IOCTL code to test

    Returns:
        Analysis result with findings
    """
    # Run in executor to avoid blocking
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, analyze_driver, driver_path, max_time, ioctl_code)


def analyze_driver_with_metrics(driver_path: Path | str, timeout: int = 120) -> tuple[AnalysisResult, Any]:
    """Analyze driver and return performance metrics.

    Args:
        driver_path: Path to the driver file
        timeout: Maximum analysis time

    Returns:
        Tuple of (result, metrics)
    """
    result = analyze_driver(driver_path, timeout)

    # Extract metrics from result
    from ..models import PerformanceMetrics

    metrics = PerformanceMetrics(
        time=result.basic.time, memory=result.basic.memory, unique_addr=result.basic.unique_addr
    )

    return result, metrics
