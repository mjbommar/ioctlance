"""Process termination and manipulation vulnerability detector."""

import logging
from typing import Any, cast

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class ProcessTerminationDetector(VulnerabilityDetector):
    """Detects arbitrary process termination and handle manipulation vulnerabilities."""

    name = "process_termination"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects arbitrary process termination via ZwTerminateProcess and handle abuse"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the process termination detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        self.tainted_handles = set()  # Track tainted process handles
        self.tainted_pids = set()  # Track tainted PIDs
        self.tainted_objects = set()  # Track tainted object pointers (from ObOpenObjectByPointer)
        self.detected_vulns = set()

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect process termination vulnerabilities.

        Args:
            state: Current simulation state

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # Called from hooks
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

    def check_zwterminateprocess(self, state: SimState, process_handle: Any, exit_status: Any) -> dict[str, Any] | None:
        """Check ZwTerminateProcess for arbitrary termination.

        Args:
            state: Current simulation state
            process_handle: Handle to process to terminate
            exit_status: Exit status code

        Returns:
            Vulnerability info if detected
        """
        # Debug output
        logger.info(
            f"[ProcessTerminationDetector] Checking ZwTerminateProcess: handle={process_handle}, tainted={self._is_tainted(process_handle)}"
        )

        # Check if process handle is tainted
        if self._is_tainted(process_handle) or process_handle in self.tainted_handles:
            vuln_key = (state.addr, "zwterminateprocess")
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Arbitrary Process Termination - ZwTerminateProcess",
                    description="User-controlled process handle passed to ZwTerminateProcess",
                    state=state,
                    parameters={
                        "process_handle": str(process_handle)[:100],
                        "exit_status": str(exit_status)[:100],
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "CRITICAL",
                        "exploitation": "DoS, terminate security software, bypass protections",
                        "impact": "System instability, security bypass",
                    },
                )

        return None

    def check_pslookupprocessbyprocessid(self, state: SimState, process_id: Any, process: Any) -> dict[str, Any] | None:
        """Check PsLookupProcessByProcessId for handle abuse.

        Args:
            state: Current simulation state
            process_id: Process ID to lookup
            process: Output process pointer

        Returns:
            Vulnerability info if detected
        """
        # Check if PID is tainted
        if self._is_tainted(process_id):
            # Mark the resulting process handle as tainted
            self.tainted_pids.add(process_id)
            if process:
                self.tainted_handles.add(process)

            vuln_key = (state.addr, "pslookup_tainted")
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Process Handle Abuse - PsLookupProcessByProcessId",
                    description="User-controlled PID used in PsLookupProcessByProcessId",
                    state=state,
                    parameters={
                        "process_id": str(process_id)[:100],
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "HIGH",
                        "exploitation": "Token stealing, privilege escalation via SYSTEM process",
                        "technique": "Lookup SYSTEM process, steal token",
                    },
                )

        return None

    def check_zwopenprocess(
        self,
        state: SimState,
        process_handle: Any,
        desired_access: Any,
        object_attributes: Any,
        client_id: Any,
    ) -> dict[str, Any] | None:
        """Check ZwOpenProcess for privilege escalation.

        Args:
            state: Current simulation state
            process_handle: Output process handle
            desired_access: Desired access rights
            object_attributes: Object attributes
            client_id: Client ID with PID

        Returns:
            Vulnerability info if detected
        """
        # Check if client_id (contains PID) is tainted
        if self._is_tainted(client_id):
            # Mark resulting handle as tainted
            if process_handle:
                self.tainted_handles.add(process_handle)

            # Check if requesting dangerous access rights
            try:
                if hasattr(desired_access, "concrete"):
                    access_val = state.solver.eval_one(desired_access)
                else:
                    access_val = desired_access

                # PROCESS_ALL_ACCESS = 0x1F0FFF
                # PROCESS_TERMINATE = 0x0001
                # PROCESS_VM_WRITE = 0x0020
                dangerous_access = access_val & 0x1F0FFF

                if dangerous_access:
                    vuln_key = (state.addr, "zwopenprocess_dangerous")
                    if vuln_key not in self.detected_vulns:
                        self.detected_vulns.add(vuln_key)

                        return self.create_vulnerability_info(
                            title="Dangerous Process Access - ZwOpenProcess",
                            description="User-controlled PID with dangerous access rights",
                            state=state,
                            parameters={
                                "client_id": str(client_id)[:100],
                                "desired_access": hex(access_val),
                                "ioctl_code": self._get_ioctl_code(state),
                            },
                            others={
                                "severity": "CRITICAL",
                                "exploitation": "Open SYSTEM process, inject code, steal token",
                                "access_rights": self._decode_process_access(access_val),
                            },
                        )
            except:
                pass

        return None

    def check_obdereferenceobject(self, state: SimState, object_ptr: Any) -> dict[str, Any] | None:
        """Check ObDereferenceObject for use-after-free.

        Args:
            state: Current simulation state
            object_ptr: Object pointer to dereference

        Returns:
            Vulnerability info if detected
        """
        # Check if dereferencing a tainted handle
        if self._is_tainted(object_ptr) or object_ptr in self.tainted_handles:
            vuln_key = (state.addr, "obderef_tainted")
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Tainted Object Dereference",
                    description="User-controlled object passed to ObDereferenceObject",
                    state=state,
                    parameters={
                        "object_ptr": str(object_ptr)[:100],
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "MEDIUM",
                        "exploitation": "Reference counting issues, potential UAF",
                    },
                )

        return None

    def _decode_process_access(self, access: int) -> str:
        """Decode process access rights.

        Args:
            access: Access rights value

        Returns:
            Human-readable access rights
        """
        rights = []
        if access & 0x0001:
            rights.append("TERMINATE")
        if access & 0x0020:
            rights.append("VM_WRITE")
        if access & 0x0010:
            rights.append("VM_READ")
        if access & 0x0008:
            rights.append("VM_OPERATION")
        if access & 0x0200:
            rights.append("CREATE_THREAD")
        if access & 0x0400:
            rights.append("QUERY_INFORMATION")
        if access == 0x1F0FFF:
            return "PROCESS_ALL_ACCESS"
        return ", ".join(rights) if rights else hex(access)

    def _is_tainted(self, value: Any) -> bool:
        """Check if a value is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if value is tainted
        """
        if value is None:
            return False
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
        elif self.context and self.context.io_control_code:
            try:
                return safe_hex(state.solver.eval(self.context.io_control_code))
            except:
                pass
        return "0x0"


# Register the detector
detector_registry.register(ProcessTerminationDetector)
