"""Physical memory mapping vulnerability detector."""

import logging
from typing import Any, cast

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class PhysicalMemoryDetector(VulnerabilityDetector):
    """Detects physical memory mapping vulnerabilities via MmMapIoSpace and related APIs."""

    name = "physical_memory_mapping"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects arbitrary physical memory mapping via MmMapIoSpace/ZwMapViewOfSection"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the physical memory detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        self.detected_mappings = set()

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect physical memory mapping vulnerabilities.

        This detector hooks MmMapIoSpace, ZwMapViewOfSection, and MmCopyMemory
        to check if user-controlled data flows into physical address parameters.

        Args:
            state: Current simulation state

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # Called from hooks, not directly
        return None

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check if a vulnerability exists in the current state.

        Args:
            state: Current simulation state
            event_type: Type of event (e.g., 'mem_read', 'mem_write', 'call')
            **kwargs: Additional event-specific parameters

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # This detector works through specific API hooks
        return None

    def check_mmmapiosspace(
        self, state: SimState, physical_address: Any, number_of_bytes: Any, cache_type: Any
    ) -> dict[str, Any] | None:
        """Check MmMapIoSpace call for vulnerabilities.

        Args:
            state: Current simulation state
            physical_address: Physical address to map
            number_of_bytes: Size of mapping
            cache_type: Cache type for mapping

        Returns:
            Vulnerability info if detected
        """
        # Check if physical address is tainted (user-controlled)
        is_tainted_addr = self._is_tainted(physical_address)
        is_tainted_size = self._is_tainted(number_of_bytes)

        if is_tainted_addr or is_tainted_size:
            # Create unique key for deduplication
            vuln_key = (state.addr, "mmmapiosspace", is_tainted_addr, is_tainted_size)
            if vuln_key in self.detected_mappings:
                return None
            self.detected_mappings.add(vuln_key)

            # Get IOCTL code if available
            ioctl_code = self._get_ioctl_code(state)

            return self.create_vulnerability_info(
                title="Arbitrary Physical Memory Mapping - MmMapIoSpace",
                description=f"User controls {'address' if is_tainted_addr else ''}"
                f"{' and ' if is_tainted_addr and is_tainted_size else ''}"
                f"{'size' if is_tainted_size else ''} in MmMapIoSpace",
                state=state,
                parameters={
                    "physical_address": str(physical_address)[:100],
                    "number_of_bytes": str(number_of_bytes)[:100],
                    "tainted_address": str(is_tainted_addr),
                    "tainted_size": str(is_tainted_size),
                    "ioctl_code": ioctl_code,
                },
                others={
                    "severity": "CRITICAL",
                    "exploitation": "Complete physical memory access - token stealing, code execution",
                    "cve_examples": "CVE-2020-12138, CVE-2024-41498, CVE-2020-15368",
                },
            )

        return None

    def check_zwmapviewofsection(
        self,
        state: SimState,
        section_handle: Any,
        process_handle: Any,
        base_address: Any,
        commit_size: Any,
        section_offset: Any,
        view_size: Any,
    ) -> dict[str, Any] | None:
        """Check ZwMapViewOfSection for vulnerabilities.

        Args:
            state: Current simulation state
            section_handle: Handle to section
            process_handle: Process handle
            base_address: Base address for mapping
            commit_size: Commit size
            section_offset: Offset into section
            view_size: Size of view

        Returns:
            Vulnerability info if detected
        """
        # Check for tainted parameters
        tainted_params = []
        if self._is_tainted(section_handle):
            tainted_params.append("section_handle")
        if self._is_tainted(base_address):
            tainted_params.append("base_address")
        if self._is_tainted(section_offset):
            tainted_params.append("section_offset")
        if self._is_tainted(view_size):
            tainted_params.append("view_size")

        if tainted_params:
            # Create unique key for deduplication
            vuln_key = (state.addr, "zwmapviewofsection", tuple(tainted_params))
            if vuln_key in self.detected_mappings:
                return None
            self.detected_mappings.add(vuln_key)

            ioctl_code = self._get_ioctl_code(state)

            return self.create_vulnerability_info(
                title="Arbitrary Memory Mapping - ZwMapViewOfSection",
                description=f"User controls {', '.join(tainted_params)} in ZwMapViewOfSection",
                state=state,
                parameters={
                    "tainted_params": ", ".join(tainted_params),
                    "section_offset": str(section_offset)[:100],
                    "view_size": str(view_size)[:100],
                    "ioctl_code": ioctl_code,
                },
                others={
                    "severity": "CRITICAL",
                    "exploitation": "Memory mapping control, potential privilege escalation",
                },
            )

        return None

    def check_mmcopymeory(
        self, state: SimState, target_address: Any, source_address: Any, number_of_bytes: Any
    ) -> dict[str, Any] | None:
        """Check MmCopyMemory for vulnerabilities.

        Args:
            state: Current simulation state
            target_address: Target address
            source_address: Source address
            number_of_bytes: Bytes to copy

        Returns:
            Vulnerability info if detected
        """
        # Check if addresses are in physical memory range (high bits set)
        # and if they're user-controlled
        is_tainted_target = self._is_tainted(target_address)
        is_tainted_source = self._is_tainted(source_address)
        is_tainted_size = self._is_tainted(number_of_bytes)

        if is_tainted_target or is_tainted_source:
            # Create unique key for deduplication
            vuln_key = (state.addr, "mmcopymemory", is_tainted_target, is_tainted_source)
            if vuln_key in self.detected_mappings:
                return None
            self.detected_mappings.add(vuln_key)

            ioctl_code = self._get_ioctl_code(state)

            return self.create_vulnerability_info(
                title="Physical Memory Access - MmCopyMemory",
                description=f"User controls {'target' if is_tainted_target else ''}"
                f"{' and ' if is_tainted_target and is_tainted_source else ''}"
                f"{'source' if is_tainted_source else ''} in MmCopyMemory",
                state=state,
                parameters={
                    "tainted_target": str(is_tainted_target),
                    "tainted_source": str(is_tainted_source),
                    "tainted_size": str(is_tainted_size),
                    "ioctl_code": ioctl_code,
                },
                others={
                    "severity": "CRITICAL",
                    "exploitation": "Physical memory read/write primitives",
                },
            )

        return None

    def _is_tainted(self, value: Any) -> bool:
        """Check if a value is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if value is tainted
        """
        if hasattr(value, "symbolic"):
            return value.symbolic
        elif hasattr(value, "variables"):
            return len(value.variables) > 0
        return False

    def _get_ioctl_code(self, state: SimState) -> str:
        """Get IOCTL code from state if available.

        Args:
            state: Current simulation state

        Returns:
            IOCTL code as hex string or '0x0'
        """
        globals_dict = get_state_globals(state)
        if "IoControlCode" in globals_dict:
            return safe_hex(globals_dict["IoControlCode"])
        elif self.context.io_control_code:
            try:
                return safe_hex(state.solver.eval(self.context.io_control_code))
            except:
                pass
        return "0x0"


# Register the detector
detector_registry.register(PhysicalMemoryDetector)
