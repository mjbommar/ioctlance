"""Dangerous file operation vulnerability detector."""

import logging
from typing import Any, cast

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class FileOperationDetector(VulnerabilityDetector):
    """Detects dangerous file operations with user-controlled parameters."""

    name = "file_operations"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects dangerous file operations via ZwCreateFile/ZwOpenFile/ZwWriteFile"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the file operation detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        self.detected_operations = set()
        self.tainted_handles = set()

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect file operation vulnerabilities.

        Args:
            state: Current simulation state

        Returns:
            Vulnerability information if detected, None otherwise
        """
        return None

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check if a vulnerability exists in the current state.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Additional event-specific parameters

        Returns:
            Vulnerability information if detected, None otherwise
        """
        return None

    def check_zwcreatefile(
        self,
        state: SimState,
        file_handle: Any,
        desired_access: Any,
        object_attributes: Any,
        io_status_block: Any,
        allocation_size: Any,
        file_attributes: Any,
        share_access: Any,
        create_disposition: Any,
        create_options: Any,
        ea_buffer: Any,
        ea_length: Any,
    ) -> dict[str, Any] | None:
        """Check ZwCreateFile for dangerous operations.

        Args:
            state: Current simulation state
            file_handle: Output file handle
            desired_access: Desired access rights
            object_attributes: Object attributes (contains path)
            io_status_block: I/O status block
            allocation_size: Initial allocation size
            file_attributes: File attributes
            share_access: Share access
            create_disposition: Create disposition
            create_options: Create options
            ea_buffer: Extended attributes buffer
            ea_length: Extended attributes length

        Returns:
            Vulnerability info if detected
        """
        is_tainted_path = self._is_tainted(object_attributes)
        is_tainted_access = self._is_tainted(desired_access)
        is_tainted_disposition = self._is_tainted(create_disposition)

        if is_tainted_path:
            if file_handle:
                self.tainted_handles.add(file_handle)

            dangerous_conditions = []

            try:
                if hasattr(desired_access, "concrete"):
                    access_val = state.solver.eval_one(desired_access)
                else:
                    access_val = desired_access if isinstance(desired_access, int) else 0

                if access_val & 0x000D0106:
                    dangerous_conditions.append("write_access")

                if hasattr(create_disposition, "concrete"):
                    disp_val = state.solver.eval_one(create_disposition)
                else:
                    disp_val = create_disposition if isinstance(create_disposition, int) else 0

                if disp_val in [4, 5]:
                    dangerous_conditions.append("overwrite")

            except:
                pass

            if dangerous_conditions or is_tainted_path:
                vuln_key = (state.addr, "zwcreatefile", tuple(dangerous_conditions))
                if vuln_key not in self.detected_operations:
                    self.detected_operations.add(vuln_key)

                    severity = "CRITICAL" if dangerous_conditions else "HIGH"

                    return self.create_vulnerability_info(
                        title="Dangerous File Operation - ZwCreateFile",
                        description=f"User-controlled {'path' if is_tainted_path else ''}"
                        f"{' with ' + ', '.join(dangerous_conditions) if dangerous_conditions else ''}",
                        state=state,
                        parameters={
                            "tainted_path": str(is_tainted_path),
                            "tainted_access": str(is_tainted_access),
                            "tainted_disposition": str(is_tainted_disposition),
                            "dangerous_conditions": ", ".join(dangerous_conditions),
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": severity,
                            "exploitation": "Arbitrary file creation/overwrite, potential privilege escalation",
                            "impact": "System file modification, config tampering, persistence",
                        },
                    )

        return None

    def check_zwopenfile(
        self,
        state: SimState,
        file_handle: Any,
        desired_access: Any,
        object_attributes: Any,
        io_status_block: Any,
        share_access: Any,
        open_options: Any,
    ) -> dict[str, Any] | None:
        """Check ZwOpenFile for dangerous operations.

        Args:
            state: Current simulation state
            file_handle: Output file handle
            desired_access: Desired access rights
            object_attributes: Object attributes (contains path)
            io_status_block: I/O status block
            share_access: Share access
            open_options: Open options

        Returns:
            Vulnerability info if detected
        """
        is_tainted_path = self._is_tainted(object_attributes)
        is_tainted_access = self._is_tainted(desired_access)

        if is_tainted_path:
            if file_handle:
                self.tainted_handles.add(file_handle)

            dangerous_conditions = []

            try:
                if hasattr(desired_access, "concrete"):
                    access_val = state.solver.eval_one(desired_access)
                else:
                    access_val = desired_access if isinstance(desired_access, int) else 0

                if access_val & 0x0081:
                    dangerous_conditions.append("read_access")

                if access_val & 0x000D0106:
                    dangerous_conditions.append("write_access")

                if access_val & 0x10000000:
                    dangerous_conditions.append("full_control")

            except:
                pass

            if is_tainted_path:
                vuln_key = (state.addr, "zwopenfile", tuple(dangerous_conditions))
                if vuln_key not in self.detected_operations:
                    self.detected_operations.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="Dangerous File Operation - ZwOpenFile",
                        description=f"User-controlled path with {', '.join(dangerous_conditions) if dangerous_conditions else 'access'}",
                        state=state,
                        parameters={
                            "tainted_path": str(is_tainted_path),
                            "tainted_access": str(is_tainted_access),
                            "dangerous_conditions": ", ".join(dangerous_conditions),
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "Information disclosure, file tampering",
                            "targets": "SAM database, registry hives, config files",
                        },
                    )

        return None

    def check_zwwritefile(
        self,
        state: SimState,
        file_handle: Any,
        event: Any,
        apc_routine: Any,
        apc_context: Any,
        io_status_block: Any,
        buffer: Any,
        length: Any,
        byte_offset: Any,
        key: Any,
    ) -> dict[str, Any] | None:
        """Check ZwWriteFile for dangerous operations.

        Args:
            state: Current simulation state
            file_handle: File handle
            event: Event handle
            apc_routine: APC routine
            apc_context: APC context
            io_status_block: I/O status block
            buffer: Data buffer
            length: Write length
            byte_offset: File offset
            key: Lock key

        Returns:
            Vulnerability info if detected
        """
        is_tainted_handle = file_handle in self.tainted_handles or self._is_tainted(file_handle)
        is_tainted_buffer = self._is_tainted(buffer)
        is_tainted_length = self._is_tainted(length)
        is_tainted_offset = self._is_tainted(byte_offset)

        if is_tainted_handle or is_tainted_buffer:
            dangerous_conditions = []

            if is_tainted_handle:
                dangerous_conditions.append("tainted_handle")
            if is_tainted_buffer:
                dangerous_conditions.append("tainted_data")
            if is_tainted_length:
                dangerous_conditions.append("controlled_size")
            if is_tainted_offset:
                dangerous_conditions.append("controlled_offset")

            vuln_key = (state.addr, "zwwritefile", tuple(dangerous_conditions))
            if vuln_key not in self.detected_operations:
                self.detected_operations.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Arbitrary File Write - ZwWriteFile",
                    description=f"Writing with {', '.join(dangerous_conditions)}",
                    state=state,
                    parameters={
                        "tainted_handle": str(is_tainted_handle),
                        "tainted_buffer": str(is_tainted_buffer),
                        "tainted_length": str(is_tainted_length),
                        "tainted_offset": str(is_tainted_offset),
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "CRITICAL",
                        "exploitation": "Arbitrary file write, code execution via DLL hijacking",
                        "technique": "Overwrite system DLLs, modify startup scripts",
                    },
                )

        return None

    def check_zwdeletefile(self, state: SimState, object_attributes: Any) -> dict[str, Any] | None:
        """Check ZwDeleteFile for dangerous operations.

        Args:
            state: Current simulation state
            object_attributes: Object attributes (contains path)

        Returns:
            Vulnerability info if detected
        """
        if self._is_tainted(object_attributes):
            vuln_key = (state.addr, "zwdeletefile")
            if vuln_key not in self.detected_operations:
                self.detected_operations.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Arbitrary File Deletion - ZwDeleteFile",
                    description="User-controlled path in ZwDeleteFile",
                    state=state,
                    parameters={"tainted_path": "True", "ioctl_code": self._get_ioctl_code(state)},
                    others={
                        "severity": "HIGH",
                        "exploitation": "DoS via critical file deletion",
                        "impact": "System instability, data loss",
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
detector_registry.register(FileOperationDetector)
