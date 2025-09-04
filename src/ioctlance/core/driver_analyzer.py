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
from ..utils.binary_metadata import extract_complete_metadata, analyze_binary_for_vulnerabilities

# Apply runtime patches to angr
from ..hooks.ccall_patch import apply_patches

apply_patches()

logger = logging.getLogger(__name__)


class DriverAnalyzer:
    """Orchestrates the complete driver analysis process.

    Backward-compatible constructor and analyze signature:
    - DriverAnalyzer(AnalysisContext)
    - DriverAnalyzer(driver_path: str | Path)
    - analyze(timeout=...): optional legacy kwarg supported, returns dict in legacy mode
    """

    def __init__(self, context_or_path: AnalysisContext | str | Path) -> None:
        """Initialize the driver analyzer.

        Args:
            context_or_path: Analysis context or driver path (legacy)
        """
        from .analysis_context import AnalysisConfig, AnalysisContext

        self._compat_mode = False
        if isinstance(context_or_path, (str, Path)):
            # Legacy path-only usage
            self._compat_mode = True
            # Use fast profile by default for CLI/test usage to keep analysis responsive
            default_config = AnalysisConfig.fast()
            self.context = AnalysisContext.create_for_driver(Path(context_or_path), default_config)
        else:
            self.context = context_or_path

    def analyze(self, timeout: int | None = None, **kwargs) -> AnalysisResult | dict:
        """Perform complete driver analysis.

        Returns:
            Analysis result with all findings
        """
        # Legacy: allow override of timeout and return dict result
        if timeout is not None:
            # Adjust config safely
            try:
                self.context.config.timeout = timeout
                if self.context.config.ioctl_timeout > timeout:
                    self.context.config.ioctl_timeout = timeout
            except Exception:
                pass
        # Track overall timing
        total_start = time.time()

        # Extract binary metadata first (before symbolic execution)
        logger.info("Extracting binary metadata...")
        binary_metadata = None
        try:
            binary_metadata = extract_complete_metadata(self.context.driver_path)
            if binary_metadata:
                logger.info(
                    f"Binary metadata extracted: {binary_metadata.machine}, "
                    f"{binary_metadata.num_imports} imports, "
                    f"{binary_metadata.num_sections} sections"
                )

                # Analyze for vulnerability patterns based on imports
                binary_analysis = analyze_binary_for_vulnerabilities(binary_metadata)
                if binary_analysis.vulnerability_indicators:
                    for indicator in binary_analysis.vulnerability_indicators:
                        logger.warning(f"Binary analysis warning: {indicator}")

                logger.info(
                    f"Binary security score: {binary_analysis.security_score}/100 (Risk: {binary_analysis.risk_level})"
                )
        except Exception as e:
            logger.warning(f"Failed to extract binary metadata: {e}")

        # Find driver type
        self.context.driver_type = find_driver_type(self.context.project)
        if self.context.driver_type not in ("wdm", "kmdf", "wdf"):
            logger.warning(f"Driver type {self.context.driver_type} not supported (only WDM/KMDF)")
            return self._create_empty_result()
        if self.context.driver_type in ("kmdf", "wdf"):
            logger.info("KMDF driver detected. Experimental support enabled (heuristic WDF hooks).")

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

        # Enforce overall timeout across phases by shrinking per-phase budgets
        try:
            elapsed_total = time.time() - total_start
            time_left = max(1, int(self.context.config.timeout - elapsed_total))
            original_timeout = self.context.config.timeout
            self.context.config.timeout = time_left
        except Exception:
            original_timeout = None

        ioctl_handler, handler_state = self._find_ioctl_handler()

        handler_time = round(time.time() - handler_start_time)
        handler_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - handler_start_memory

        if not ioctl_handler:
            logger.error("IOCTL handler not found")
            return self._create_empty_result()

        logger.info(f"IOCTL handler found at: {ioctl_handler.address}")

        # Phase 1.5: Probe for IOCTLs (simplified approach)
        logger.info("Phase 1.5: Probing for IOCTL codes...")
        discovery_start_time = time.time()
        discovery_start_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        from .ioctl_prober import IOCTLProber

        prober = IOCTLProber(self.context)
        handler_addr = int(ioctl_handler.address, 16)

        # Probe for IOCTLs in the common range
        discovered_ioctls = prober.probe_ioctl_range(handler_addr)

        discovery_time = round(time.time() - discovery_start_time)
        discovery_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - discovery_start_memory
        logger.info(f"IOCTL probing complete: {len(discovered_ioctls)} codes found in {discovery_time}s")

        # Update the handler with discovered IOCTLs
        if discovered_ioctls:
            ioctl_handler.ioctl_codes = discovered_ioctls.copy()
            self.context.ioctl_codes = discovered_ioctls.copy()  # Also update context
            logger.info(f"Updated handler with probed IOCTLs: {', '.join(sorted(discovered_ioctls))}")

        # Phase 2: Hunt vulnerabilities
        logger.info("Phase 2: Hunting vulnerabilities...")
        hunt_start_time = time.time()
        hunt_start_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        hunter = VulnerabilityHunter(self.context)
        logger.debug(
            f"Context id in analyzer: {id(self.context)}, vulnerabilities before hunt: {len(self.context.vulnerabilities)}"
        )

        # Use handler state or blank state
        if not handler_state:
            logger.debug("Using blank state for vulnerability hunting")
            import angr

            handler_state = self.context.project.factory.blank_state(add_options=angr.options.resilience)

        # Adjust remaining time for the hunting phase
        try:
            if original_timeout is not None:
                # Restore original reference timeout
                self.context.config.timeout = original_timeout
            elapsed_total = time.time() - total_start
            time_left = max(1, int(self.context.config.timeout - elapsed_total))
            self.context.print_info(f"[BUDGET] Time left for hunting: {time_left}s")
            # Use remaining time as the hunt budget
            self.context.config.timeout = time_left
        except Exception:
            pass

        # Hunt for vulnerabilities
        handler_addr = int(ioctl_handler.address, 16)
        vulnerabilities = hunter.hunt(handler_state, handler_addr, self.context.config.target_ioctl)
        logger.info(f"After hunt: returned {len(vulnerabilities)} vulnerabilities")
        logger.info(f"Context vulnerabilities: {len(self.context.vulnerabilities)}")
        logger.info(f"Context vuln_buffer: {len(self.context.vuln_buffer)}")

        # Log first few vulnerabilities for debugging
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities[:3]):
                if isinstance(vuln, dict):
                    logger.info(f"Vulnerability {i}: {vuln.get('title', 'No title')}")
                else:
                    logger.info(f"Vulnerability {i}: {vuln}")

        hunt_time = round(time.time() - hunt_start_time)
        hunt_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - hunt_start_memory

        # The IOCTLs are discovered during vulnerability hunting, not handler discovery
        # Always update the handler with discovered IOCTLs from context
        if self.context.ioctl_codes:
            ioctl_handler.ioctl_codes = self.context.ioctl_codes.copy()
            logger.info(
                f"Updated handler with {len(ioctl_handler.ioctl_codes)} IOCTL codes: {ioctl_handler.ioctl_codes}"
            )
        else:
            logger.info("No IOCTL codes discovered during analysis")

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
            IoControlCodes=ioctl_handler.ioctl_codes,  # Now always updated from context
        )

        # Convert vulnerabilities to model format
        vuln_models = []
        logger.info(f"Converting {len(vulnerabilities)} vulnerabilities to model format")
        for i, vuln_dict in enumerate(vulnerabilities):
            try:
                # Convert legacy format to model
                from ..models import Vulnerability, VulnerabilityEvaluation

                eval_data = vuln_dict.get("eval", {})

                # Use state_str if available, fall back to state or default
                state_str = vuln_dict.get("state_str")
                if not state_str:
                    state = vuln_dict.get("state")
                    # Handle weakproxy objects
                    if state is not None:
                        try:
                            import weakref

                            if isinstance(state, weakref.ProxyType):
                                # Try to get string before it dies
                                try:
                                    state_str = str(state)
                                except (ReferenceError, Exception):
                                    state_str = "<SimState @ 0x0>"
                            elif hasattr(state, "addr"):
                                state_str = str(state)
                            elif isinstance(state, str):
                                state_str = state
                            else:
                                state_str = "<SimState @ 0x0>"
                        except Exception:
                            state_str = "<SimState @ 0x0>"
                    else:
                        state_str = "<SimState @ 0x0>"

                # Get severity from vuln_dict or compute from title
                severity = vuln_dict.get("severity")
                if not severity:
                    others_dict = vuln_dict.get("others", {})
                    severity = others_dict.get("severity")
                if not severity:
                    severity = Vulnerability.compute_severity_from_title(vuln_dict.get("title", "Unknown"))

                vuln = Vulnerability(
                    title=vuln_dict.get("title", "Unknown"),
                    description=vuln_dict.get("description", ""),
                    state=state_str,
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
                    severity=severity,
                )
                vuln_models.append(vuln)
                if i < 5:  # Log first few conversions for debugging
                    logger.debug(f"Successfully converted vulnerability {i}: {vuln.title}")
            except Exception as e:
                self.context.print_error(f"Error converting vulnerability {i}: {e}")
                if i < 5:  # Log details for first few failures
                    logger.error(f"Failed to convert vulnerability {i}: {vuln_dict}")
                    logger.error(f"Exception details: {e}")

        logger.info(f"Converted {len(vuln_models)} of {len(vulnerabilities)} vulnerabilities successfully")

        # Log first few converted models for debugging
        if vuln_models:
            for i, vuln_model in enumerate(vuln_models[:3]):
                logger.info(f"Converted model {i}: {vuln_model.title}")

        result = AnalysisResult(
            basic=basic_info,
            vuln=vuln_models,
            error=self.context.error_messages,
            driver_info=DriverInfo.from_file(self.context.driver_path),
            ioctl_handler=ioctl_handler,
            analysis_time=time.time() - total_start,
            binary_metadata=binary_metadata,  # Add the complete metadata
        )

        logger.info(f"Created AnalysisResult with {len(result.vuln)} vulnerabilities")
        logger.info(f"result.vulnerability_count = {result.vulnerability_count}")
        self.context.print_info(f"Analysis complete: {result.vulnerability_count} vulnerabilities found")

        # Return legacy dict format if in compat mode
        if self._compat_mode:
            # Legacy dictionary format expected by some tests
            return {
                "driver": str(self.context.driver_path),
                "ioctl_handler": result.basic.ioctl_handler if result.basic else None,
                "ioctl_codes": result.basic.IoControlCodes if result.basic else [],
                "vulnerabilities": [v.model_dump(exclude_none=True) for v in result.vuln],
                "errors": result.error,
            }

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
