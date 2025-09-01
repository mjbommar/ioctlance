"""Unified privilege escalation detector for IOCTLance.

This detector merges:
- Physical memory mapping detection (from physical_memory.py)
- Process termination/manipulation (from process_termination.py)

Provides comprehensive privilege escalation vulnerability detection.
"""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class UnifiedPrivilegeEscalationDetector(VulnerabilityDetector):
    """Unified detector for all privilege escalation vulnerabilities.

    Combines detection for:
    - Arbitrary physical memory mapping (MmMapIoSpace, ZwMapViewOfSection)
    - Process termination (ZwTerminateProcess, handle manipulation)
    - Kernel object manipulation for privilege escalation
    - Memory protection bypass
    """

    name = "unified_privilege_escalation"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Comprehensive privilege escalation vulnerability detection"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the unified privilege escalation detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)

        # Physical memory tracking
        self.detected_mappings: set[tuple[int, str, Any]] = set()

        # Process manipulation tracking
        self.tainted_handles: set[Any] = set()
        self.tainted_pids: set[Any] = set()
        self.tainted_objects: set[Any] = set()

        # General deduplication
        self.detected_vulns: set[tuple[int, str, str]] = set()

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for privilege escalation vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Event-specific arguments

        Returns:
            Vulnerability info if detected, None otherwise
        """
        # This detector primarily works through API hooks
        # But we can check for some patterns in memory operations
        if event_type == "mem_write":
            address = kwargs.get("address")
            if address is not None and self._is_kernel_structure(address):
                return self._check_kernel_write(state, address, **kwargs)

        return None

    # ==================== Physical Memory Mapping ====================

    def check_mmmapiosspace(
        self, state: SimState, physical_address: Any, number_of_bytes: Any, cache_type: Any
    ) -> dict[str, Any] | None:
        """Check MmMapIoSpace for arbitrary physical memory mapping.

        Args:
            state: Current simulation state
            physical_address: Physical address to map
            number_of_bytes: Size of mapping
            cache_type: Cache type for mapping

        Returns:
            Vulnerability info if detected
        """
        is_tainted_addr = self._is_tainted(physical_address)
        is_tainted_size = self._is_tainted(number_of_bytes)

        if is_tainted_addr or is_tainted_size:
            vuln_key = (
                state.addr if hasattr(state, "addr") else 0,
                "mmmapiosspace",
                f"{is_tainted_addr}_{is_tainted_size}",
            )
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

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
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "CRITICAL",
                    "exploitation": "Map arbitrary physical memory, read/write kernel",
                    "confidence": "HIGH",
                    "impact": "Full system compromise",
                    "cve_pattern": "CVE-2019-16098, CVE-2020-12446",
                    "mitigation": "Validate physical addresses, use MDL instead",
                    "windows_specific": "Can bypass KASLR, read credentials, patch kernel",
                },
            )

        return None

    def check_zwmapviewofsection(
        self, state: SimState, section_handle: Any, process_handle: Any, base_address: Any
    ) -> dict[str, Any] | None:
        """Check ZwMapViewOfSection for memory mapping vulnerabilities.

        Args:
            state: Current simulation state
            section_handle: Handle to section object
            process_handle: Handle to process
            base_address: Base address for mapping

        Returns:
            Vulnerability info if detected
        """
        # Check if any parameters are tainted
        if self._is_tainted(section_handle) or self._is_tainted(process_handle) or self._is_tainted(base_address):
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "zwmapviewofsection", "tainted")
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Arbitrary Memory Mapping - ZwMapViewOfSection",
                description="User-controlled parameters in ZwMapViewOfSection",
                state=state,
                parameters={
                    "section_handle": str(section_handle)[:100],
                    "process_handle": str(process_handle)[:100],
                    "base_address": str(base_address)[:100],
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "CRITICAL",
                    "exploitation": "Map arbitrary memory sections",
                    "confidence": "HIGH",
                    "impact": "Memory disclosure, privilege escalation",
                    "mitigation": "Validate handles and addresses",
                },
            )

        return None

    def check_mmcopymemory(
        self, state: SimState, target_address: Any, source_address: Any, number_of_bytes: Any
    ) -> dict[str, Any] | None:
        """Check MmCopyMemory for arbitrary memory operations.

        Args:
            state: Current simulation state
            target_address: Destination address
            source_address: Source address
            number_of_bytes: Number of bytes to copy

        Returns:
            Vulnerability info if detected
        """
        # Check if addresses are in physical memory space
        is_tainted_src = self._is_tainted(source_address)
        is_tainted_dst = self._is_tainted(target_address)
        is_tainted_size = self._is_tainted(number_of_bytes)

        if is_tainted_src or is_tainted_dst or is_tainted_size:
            vuln_key = (
                state.addr if hasattr(state, "addr") else 0,
                "mmcopymemory",
                f"{is_tainted_src}_{is_tainted_dst}",
            )
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Arbitrary Memory Copy - MmCopyMemory",
                description="User-controlled parameters in MmCopyMemory",
                state=state,
                parameters={
                    "source": str(source_address)[:100],
                    "target": str(target_address)[:100],
                    "size": str(number_of_bytes)[:100],
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "CRITICAL",
                    "exploitation": "Read/write arbitrary memory",
                    "confidence": "HIGH",
                    "impact": "Memory corruption, info disclosure",
                    "mitigation": "Validate memory ranges",
                },
            )

        return None

    # ==================== Process Manipulation ====================

    def check_zwterminateprocess(self, state: SimState, process_handle: Any, exit_status: Any) -> dict[str, Any] | None:
        """Check ZwTerminateProcess for arbitrary process termination.

        Args:
            state: Current simulation state
            process_handle: Handle to process to terminate
            exit_status: Exit status code

        Returns:
            Vulnerability info if detected
        """
        # Check if process handle is tainted or tracked as tainted
        if self._is_tainted(process_handle) or process_handle in self.tainted_handles:
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "zwterminateprocess", str(process_handle)[:20])
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Arbitrary Process Termination",
                description="User-controlled process handle in ZwTerminateProcess",
                state=state,
                parameters={
                    "process_handle": str(process_handle)[:100],
                    "exit_status": str(exit_status)[:100],
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "CRITICAL",
                    "exploitation": "Terminate any process including security software",
                    "confidence": "HIGH",
                    "impact": "DoS, security bypass, system instability",
                    "mitigation": "Validate process handles, check permissions",
                    "windows_specific": "Can terminate protected processes",
                },
            )

        return None

    def check_zwopenprocess(
        self, state: SimState, process_handle: Any, desired_access: Any, client_id: Any
    ) -> dict[str, Any] | None:
        """Check ZwOpenProcess for privilege escalation.

        Args:
            state: Current simulation state
            process_handle: Output process handle
            desired_access: Requested access rights
            client_id: Process/thread IDs

        Returns:
            Vulnerability info if detected
        """
        # Check if client_id (contains PID) is tainted
        if self._is_tainted(client_id):
            # Track the handle as tainted for future operations
            if process_handle is not None:
                self.tainted_handles.add(process_handle)

            # Check if requesting dangerous access rights
            if desired_access and self._is_dangerous_access(desired_access):
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "zwopenprocess", "dangerous")
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Arbitrary Process Access - ZwOpenProcess",
                    description="User-controlled PID with dangerous access rights",
                    state=state,
                    parameters={
                        "desired_access": str(desired_access)[:100],
                        "client_id": str(client_id)[:100],
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "HIGH",
                        "exploitation": "Open handle to any process",
                        "confidence": "HIGH",
                        "impact": "Process manipulation, memory access",
                        "mitigation": "Validate PIDs and access rights",
                    },
                )

        return None

    def check_pslookupprocessbyprocessid(self, state: SimState, process_id: Any, process: Any) -> dict[str, Any] | None:
        """Check PsLookupProcessByProcessId for tainted PIDs.

        Args:
            state: Current simulation state
            process_id: Process ID to lookup
            process: Output EPROCESS pointer

        Returns:
            Vulnerability info if detected
        """
        if self._is_tainted(process_id):
            # Track this PID as tainted
            self.tainted_pids.add(process_id)

            # Track the resulting object as tainted
            if process is not None:
                self.tainted_objects.add(process)

            vuln_key = (state.addr if hasattr(state, "addr") else 0, "pslookupprocess", str(process_id)[:20])
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Arbitrary Process Lookup",
                description="User-controlled PID in PsLookupProcessByProcessId",
                state=state,
                parameters={
                    "process_id": str(process_id)[:100],
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "MEDIUM",
                    "exploitation": "Access EPROCESS of any process",
                    "confidence": "HIGH",
                    "impact": "Information disclosure, further exploitation",
                    "mitigation": "Validate PIDs before lookup",
                    "windows_specific": "Can access system process structures",
                },
            )

        return None

    def check_obopenobjectbypointer(
        self, state: SimState, object_ptr: Any, handle_attributes: Any, access_mode: Any
    ) -> dict[str, Any] | None:
        """Check ObOpenObjectByPointer for object manipulation.

        Args:
            state: Current simulation state
            object_ptr: Pointer to kernel object
            handle_attributes: Handle attributes
            access_mode: Access mode (kernel/user)

        Returns:
            Vulnerability info if detected
        """
        # Check if object pointer is tainted or from tainted source
        if self._is_tainted(object_ptr) or object_ptr in self.tainted_objects:
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "obopenobject", str(object_ptr)[:20])
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Arbitrary Object Handle Creation",
                description="User-controlled object in ObOpenObjectByPointer",
                state=state,
                parameters={
                    "object_ptr": str(object_ptr)[:100],
                    "access_mode": str(access_mode)[:100],
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "HIGH",
                    "exploitation": "Create handle to arbitrary kernel object",
                    "confidence": "HIGH",
                    "impact": "Object manipulation, privilege escalation",
                    "mitigation": "Validate object pointers",
                    "windows_specific": "Can access protected objects",
                },
            )

        return None

    # ==================== Helper Methods ====================

    def _check_kernel_write(self, state: SimState, address: Any, **kwargs: Any) -> dict[str, Any] | None:
        """Check for writes to kernel structures.

        Args:
            state: Current simulation state
            address: Address being written to
            **kwargs: Additional parameters

        Returns:
            Vulnerability info if detected
        """
        # Check if writing to token, EPROCESS, or other critical structures
        addr_str = str(address)
        critical_structures = ["TOKEN", "EPROCESS", "KTHREAD", "DRIVER_OBJECT"]

        for struct in critical_structures:
            if struct in addr_str:
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "kernel_struct_write", struct)
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title=f"Kernel Structure Modification - {struct}",
                    description=f"Write to critical kernel structure {struct}",
                    state=state,
                    parameters={
                        "address": str(address)[:100],
                        "structure": struct,
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "CRITICAL",
                        "exploitation": "Direct privilege escalation",
                        "confidence": "HIGH",
                        "impact": "Full system compromise",
                        "mitigation": "Prevent writes to kernel structures",
                    },
                )

        return None

    def _is_kernel_structure(self, address: Any) -> bool:
        """Check if address refers to a kernel structure.

        Args:
            address: Address to check

        Returns:
            True if address is a kernel structure
        """
        if address is None:
            return False

        addr_str = str(address)
        kernel_structures = ["TOKEN", "EPROCESS", "ETHREAD", "KTHREAD", "DRIVER_OBJECT", "DEVICE_OBJECT", "MDL"]
        return any(struct in addr_str for struct in kernel_structures)

    def _is_dangerous_access(self, access_rights: Any) -> bool:
        """Check if access rights are dangerous.

        Args:
            access_rights: Access rights value

        Returns:
            True if access rights are dangerous
        """
        # Common dangerous access rights
        process_all_access = 0x1FFFFF
        process_vm_write = 0x0020
        process_create_thread = 0x0002
        process_terminate = 0x0001

        try:
            if hasattr(access_rights, "concrete"):
                rights = access_rights
            else:
                rights = int(access_rights)

            # Check for dangerous combinations
            dangerous = [process_all_access, process_vm_write, process_create_thread, process_terminate]

            for dangerous_right in dangerous:
                if rights & dangerous_right:
                    return True

        except:
            # If we can't evaluate, assume dangerous
            return True

        return False

    def _is_tainted(self, value: Any) -> bool:
        """Check if a value is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if value is tainted
        """
        if value is None:
            return False

        # Check if symbolic
        if hasattr(value, "symbolic") and value.symbolic:
            return True

        # Check if contains user input references
        value_str = str(value)
        tainted_sources = ["SystemBuffer", "Type3InputBuffer", "UserBuffer", "InputBuffer", "OutputBuffer", "IRP"]
        return any(src in value_str for src in tainted_sources)

    def _get_ioctl_code(self, state: SimState) -> str:
        """Get current IOCTL code from state.

        Args:
            state: Current simulation state

        Returns:
            IOCTL code as hex string
        """
        globals_dict = get_state_globals(state)
        if "IoControlCode" in globals_dict:
            return safe_hex(globals_dict["IoControlCode"])
        elif self.context and self.context.io_control_code:
            try:
                return safe_hex(state.solver.eval(self.context.io_control_code))
            except:
                pass
        return "0x0"

    def get_statistics(self) -> dict[str, Any]:
        """Get detector statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "detected_mappings": len(self.detected_mappings),
            "tainted_handles": len(self.tainted_handles),
            "tainted_pids": len(self.tainted_pids),
            "tainted_objects": len(self.tainted_objects),
            "detected_vulnerabilities": len(self.detected_vulns),
        }


# Register the detector
detector_registry.register(UnifiedPrivilegeEscalationDetector)
