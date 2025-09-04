"""IOCTL validation detector for Windows drivers.

Detects vulnerabilities related to IOCTL handling:
- Invalid IOCTL codes
- Buffer size validation issues
- Method confusion (METHOD_BUFFERED vs METHOD_NEITHER)
- Transfer type validation
- Missing input/output validation
"""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


# IOCTL transfer methods
METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3

# IOCTL access types
FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 1
FILE_WRITE_ACCESS = 2

# Common device types
FILE_DEVICE_UNKNOWN = 0x00000022


def decode_ioctl(ioctl_code: int) -> dict[str, int]:
    """Decode an IOCTL code into its components.

    IOCTL format (32 bits):
    - Bits 31-16: Device type
    - Bits 15-14: Access rights
    - Bits 13-2: Function code
    - Bits 1-0: Method

    Args:
        ioctl_code: The IOCTL code to decode

    Returns:
        Dictionary with decoded components
    """
    return {
        "device_type": (ioctl_code >> 16) & 0xFFFF,
        "access": (ioctl_code >> 14) & 0x3,
        "function": (ioctl_code >> 2) & 0xFFF,
        "method": ioctl_code & 0x3,
    }


class IOCTLValidationDetector(VulnerabilityDetector):
    """Detects IOCTL-specific validation vulnerabilities.

    This detector identifies:
    - Invalid IOCTL codes
    - Buffer size mismatches
    - Method confusion vulnerabilities
    - Missing validation checks
    """

    name = "ioctl_validation"

    # Expected IOCTL ranges for common drivers
    COMMON_DEVICE_TYPES = {
        0x22,  # FILE_DEVICE_UNKNOWN (custom drivers)
        0x8000,  # Custom device type range start
        0x9000,  # Common custom range
    }

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects IOCTL validation vulnerabilities"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the IOCTL validation detector."""
        super().__init__(context)

        # Track validated IOCTLs
        self.validated_ioctls: set[int] = set()
        self.seen_ioctls: dict[int, dict[str, Any]] = {}  # IOCTL -> info
        self.detected_vulns: set[tuple[int, str, str]] = set()

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for IOCTL validation vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Event-specific arguments

        Returns:
            Vulnerability info if detected, None otherwise
        """
        # Check when IOCTL handler is called
        if event_type == "ioctl_start":
            return self._check_ioctl_start(state, **kwargs)

        # Check buffer operations within IOCTL
        elif event_type in ("mem_read", "mem_write"):
            return self._check_buffer_operation(state, event_type, **kwargs)

        # Check at end of IOCTL processing
        elif event_type == "ioctl_end":
            return self._check_ioctl_end(state, **kwargs)

        return None

    def _check_ioctl_start(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check IOCTL code and initial validation.

        Args:
            state: Current simulation state
            **kwargs: IOCTL parameters

        Returns:
            Vulnerability info if detected
        """
        # Get IOCTL code
        ioctl_code_str = self._get_ioctl_code(state)
        if ioctl_code_str == "0x0":
            return None

        try:
            ioctl_code = int(ioctl_code_str, 16) if isinstance(ioctl_code_str, str) else ioctl_code_str
        except (ValueError, TypeError):
            return None

        # Decode IOCTL
        decoded = decode_ioctl(ioctl_code)

        # Track this IOCTL
        if ioctl_code not in self.seen_ioctls:
            self.seen_ioctls[ioctl_code] = {
                "decoded": decoded,
                "input_buffer_checked": False,
                "output_buffer_checked": False,
                "size_validated": False,
                "first_seen": state.addr if hasattr(state, "addr") else 0,
            }

        # Check for invalid device type
        if decoded["device_type"] == 0 or decoded["device_type"] > 0xFFFF:
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "invalid_device", hex(ioctl_code))
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Invalid IOCTL Device Type",
                description=f"IOCTL {hex(ioctl_code)} has invalid device type {hex(decoded['device_type'])}",
                state=state,
                parameters={
                    "ioctl_code": hex(ioctl_code),
                    "device_type": hex(decoded["device_type"]),
                    "method": decoded["method"],
                },
                others={
                    "severity": "LOW",
                    "exploitation": "May indicate fuzzing or malformed input",
                    "confidence": "HIGH",
                    "mitigation": "Validate IOCTL code ranges",
                },
            )

        # Check for METHOD_NEITHER without proper validation
        if decoded["method"] == METHOD_NEITHER:
            # METHOD_NEITHER is dangerous - direct user pointers
            if not self._has_probe_validation(state):
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "method_neither", hex(ioctl_code))
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Unsafe METHOD_NEITHER IOCTL",
                    description=f"IOCTL {hex(ioctl_code)} uses METHOD_NEITHER without proper validation",
                    state=state,
                    parameters={
                        "ioctl_code": hex(ioctl_code),
                        "method": "METHOD_NEITHER",
                        "function": hex(decoded["function"]),
                    },
                    others={
                        "severity": "HIGH",
                        "exploitation": "Direct user pointer access without validation",
                        "confidence": "HIGH",
                        "mitigation": "Use ProbeForRead/Write or switch to METHOD_BUFFERED",
                        "windows_specific": "Can bypass kernel memory protections",
                    },
                )

        # Check for suspicious function codes
        if decoded["function"] == 0 or decoded["function"] == 0xFFF:
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "suspicious_function", hex(ioctl_code))
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Suspicious IOCTL Function Code",
                description=f"IOCTL {hex(ioctl_code)} has suspicious function code {hex(decoded['function'])}",
                state=state,
                parameters={
                    "ioctl_code": hex(ioctl_code),
                    "function": hex(decoded["function"]),
                },
                others={
                    "severity": "LOW",
                    "exploitation": "May indicate testing/debug code",
                    "confidence": "MEDIUM",
                    "mitigation": "Review IOCTL function codes",
                },
            )

        return None

    def _check_buffer_operation(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check buffer operations for size validation issues.

        Args:
            state: Current simulation state
            event_type: Type of memory event
            **kwargs: Memory operation parameters

        Returns:
            Vulnerability info if detected
        """
        address = kwargs.get("address")
        size = kwargs.get("size")

        if address is None or size is None:
            return None

        # Get current IOCTL
        ioctl_code_str = self._get_ioctl_code(state)
        if ioctl_code_str == "0x0":
            return None
        try:
            ioctl_code = int(ioctl_code_str, 16) if isinstance(ioctl_code_str, str) else ioctl_code_str
        except (ValueError, TypeError):
            return None
        if ioctl_code not in self.seen_ioctls:
            return None

        ioctl_info = self.seen_ioctls[ioctl_code]
        decoded = ioctl_info["decoded"]

        # Check if accessing user buffers without size validation
        if self._is_user_buffer(address):
            # Check if size is symbolic (user-controlled)
            if self._is_symbolic(size):
                # Check if size was validated
                if not ioctl_info["size_validated"]:
                    vuln_key = (state.addr if hasattr(state, "addr") else 0, "unvalidated_size", hex(ioctl_code))
                    if vuln_key in self.detected_vulns:
                        return None
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="Unvalidated Buffer Size",
                        description=f"User-controlled size in {event_type} without validation",
                        state=state,
                        parameters={
                            "ioctl_code": hex(ioctl_code),
                            "operation": event_type,
                            "size": str(size)[:100],
                            "method": decoded["method"],
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "Buffer overflow via controlled size",
                            "confidence": "HIGH",
                            "mitigation": "Validate buffer sizes before use",
                        },
                    )

            # Track that buffers are being accessed
            if event_type == "mem_read":
                ioctl_info["input_buffer_checked"] = True
            else:
                ioctl_info["output_buffer_checked"] = True

        # Check for size mismatches in METHOD_BUFFERED
        if decoded["method"] == METHOD_BUFFERED:
            # Check if size exceeds expected buffer sizes
            if hasattr(self.context, "input_buffer_length") and self.context.input_buffer_length:
                try:
                    max_input = state.solver.max(self.context.input_buffer_length)
                    if isinstance(size, int) and size > max_input:
                        vuln_key = (state.addr if hasattr(state, "addr") else 0, "size_mismatch", hex(ioctl_code))
                        if vuln_key in self.detected_vulns:
                            return None
                        self.detected_vulns.add(vuln_key)

                        return self.create_vulnerability_info(
                            title="Buffer Size Mismatch",
                            description=f"Access size {size} exceeds buffer length {max_input}",
                            state=state,
                            parameters={
                                "ioctl_code": hex(ioctl_code),
                                "access_size": size,
                                "buffer_length": max_input,
                            },
                            others={
                                "severity": "HIGH",
                                "exploitation": "Buffer overflow",
                                "confidence": "HIGH",
                                "mitigation": "Check buffer bounds",
                            },
                        )
                except:
                    pass

        return None

    def _check_ioctl_end(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check for missing validation at end of IOCTL.

        Args:
            state: Current simulation state
            **kwargs: IOCTL end parameters

        Returns:
            Vulnerability info if detected
        """
        ioctl_code_str = self._get_ioctl_code(state)
        if ioctl_code_str == "0x0":
            return None
        try:
            ioctl_code = int(ioctl_code_str, 16) if isinstance(ioctl_code_str, str) else ioctl_code_str
        except (ValueError, TypeError):
            return None
        if ioctl_code not in self.seen_ioctls:
            return None

        ioctl_info = self.seen_ioctls[ioctl_code]
        decoded = ioctl_info["decoded"]

        # Check if input was never validated for METHOD_NEITHER
        if decoded["method"] == METHOD_NEITHER:
            if not ioctl_info["input_buffer_checked"] and decoded["access"] in (FILE_READ_ACCESS, FILE_ANY_ACCESS):
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "no_input_validation", hex(ioctl_code))
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Missing Input Validation",
                    description=f"IOCTL {hex(ioctl_code)} doesn't validate input buffer",
                    state=state,
                    parameters={
                        "ioctl_code": hex(ioctl_code),
                        "method": "METHOD_NEITHER",
                        "access": decoded["access"],
                    },
                    others={
                        "severity": "MEDIUM",
                        "exploitation": "Unvalidated user input processing",
                        "confidence": "MEDIUM",
                        "mitigation": "Add input validation",
                    },
                )

        # Mark IOCTL as validated for next time
        self.validated_ioctls.add(ioctl_code)

        return None

    def _has_probe_validation(self, state: SimState) -> bool:
        """Check if proper probe validation exists.

        Args:
            state: Current simulation state

        Returns:
            True if ProbeForRead/Write was called
        """
        # Check if ProbeForRead or ProbeForWrite was called in this path
        if hasattr(state, "history") and hasattr(state.history, "events"):
            for event in state.history.events:
                if hasattr(event, "type") and event.type == "call":
                    if hasattr(event, "function_name"):
                        if "ProbeFor" in event.function_name:
                            return True
        return False

    def _is_user_buffer(self, address: Any) -> bool:
        """Check if address is a user buffer.

        Args:
            address: Address to check

        Returns:
            True if address is user buffer
        """
        if address is None:
            return False

        addr_str = str(address)
        user_buffers = ["SystemBuffer", "Type3InputBuffer", "UserBuffer", "InputBuffer", "OutputBuffer"]
        return any(buf in addr_str for buf in user_buffers)

    def _is_symbolic(self, value: Any) -> bool:
        """Check if value is symbolic.

        Args:
            value: Value to check

        Returns:
            True if value is symbolic
        """
        if hasattr(value, "symbolic"):
            return value.symbolic
        return False

    def get_statistics(self) -> dict[str, Any]:
        """Get detector statistics.

        Returns:
            Statistics dictionary
        """
        method_counts = {}
        for ioctl_info in self.seen_ioctls.values():
            method = ioctl_info["decoded"]["method"]
            method_name = {
                0: "METHOD_BUFFERED",
                1: "METHOD_IN_DIRECT",
                2: "METHOD_OUT_DIRECT",
                3: "METHOD_NEITHER",
            }.get(method, f"UNKNOWN_{method}")
            method_counts[method_name] = method_counts.get(method_name, 0) + 1

        return {
            "total_ioctls": len(self.seen_ioctls),
            "validated_ioctls": len(self.validated_ioctls),
            "method_distribution": method_counts,
            "detected_vulnerabilities": len(self.detected_vulns),
        }


# Register the detector
detector_registry.register(IOCTLValidationDetector)
