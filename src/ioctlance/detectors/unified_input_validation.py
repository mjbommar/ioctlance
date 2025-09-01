"""Unified input validation detector for IOCTLance.

This detector merges:
- Arbitrary read/write detection (from arbitrary_rw.py)
- ProbeForRead/Write bypass detection (from probe_bypass.py)

Provides comprehensive input validation vulnerability detection.
Note: TOCTOU/double-fetch detection is handled by race_condition.py
"""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class UnifiedInputValidationDetector(VulnerabilityDetector):
    """Unified detector for all input validation vulnerabilities.

    Combines detection for:
    - Arbitrary read/write through controllable pointers
    - ProbeForRead/Write bypass (zero-length, size mismatch)
    - Kernel pointer disclosure
    Note: TOCTOU/double-fetch is handled by race_condition detector
    """

    name = "unified_input_validation"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Comprehensive input validation vulnerability detection"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the unified input validation detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)

        # From probe_bypass
        self.probed_addresses: dict[int, list[dict]] = {}  # Track probed addresses

        # Deduplication tracking
        self.detected_vulns: set[tuple[int, str, str]] = set()

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for input validation vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Event-specific arguments

        Returns:
            Vulnerability info if detected, None otherwise
        """
        # Handle memory operations (from arbitrary_rw)
        if event_type in ("mem_read", "mem_write"):
            vuln = self._check_arbitrary_rw(state, event_type, **kwargs)
            if vuln:
                return vuln

            # Also check for size mismatch (from probe_bypass)
            address = kwargs.get("address")
            size = kwargs.get("size")
            if address is not None and size:
                vuln = self._check_memory_access(state, address, size, event_type == "mem_write")
                if vuln:
                    return vuln

        # Handle function calls
        elif event_type == "call":
            func_name = kwargs.get("function_name", "")

            # ProbeForRead/Write checks
            if func_name == "ProbeForRead":
                return self._check_probe_for_read(state, **kwargs)
            elif func_name == "ProbeForWrite":
                return self._check_probe_for_write(state, **kwargs)

        return None

    def _check_arbitrary_rw(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for arbitrary read/write vulnerabilities (from arbitrary_rw).

        Args:
            state: Current simulation state
            event_type: 'mem_read' or 'mem_write'
            **kwargs: Event data including address

        Returns:
            Vulnerability info if detected
        """
        address = kwargs.get("address")
        if address is None:
            return None

        # Target buffers to check
        targets = ["SystemBuffer", "Type3InputBuffer", "UserBuffer"]

        for target in targets:
            if target not in str(address):
                continue

            # Extract base address
            asts = [i for i in address.children_asts()]
            target_base = asts[0] if len(asts) > 1 else address

            # Check if already validated
            if self.is_address_validated(state, target_base):
                continue

            # Only check if single variable
            if len(address.variables) != 1:
                continue

            # Create a test state
            tmp_state = state.copy()

            # Check for controllable address based on buffer type
            if target == "SystemBuffer" and "*" in str(address):
                # SystemBuffer is a pointer - check if controllable
                if event_type == "mem_read":
                    tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0x41414141)
                else:
                    tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0x41414141)

                if tmp_state.satisfiable():
                    vuln_key = (
                        state.addr if hasattr(state, 'addr') else 0,
                        "arbitrary_rw",
                        f"{event_type}_{target}"
                    )
                    if vuln_key in self.detected_vulns:
                        return None
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title=f"Arbitrary {'Read' if event_type == 'mem_read' else 'Write'} - Controllable Pointer",
                        description=f"User-controlled pointer allows arbitrary memory {event_type[4:]}",
                        state=state,
                        parameters={
                            "address": str(address)[:100],
                            "buffer_type": target,
                            "operation": event_type,
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "CRITICAL" if event_type == "mem_write" else "HIGH",
                            "exploitation": "Read/write arbitrary kernel memory",
                            "confidence": "HIGH",
                            "mitigation": "Validate pointers before dereference"
                        }
                    )

            elif target in ("Type3InputBuffer", "UserBuffer"):
                # Check if Type3InputBuffer or UserBuffer is controllable
                if target == "Type3InputBuffer" and self.context.type3_input_buffer:
                    tmp_state.solver.add(self.context.type3_input_buffer == 0x41414141)
                elif target == "UserBuffer" and self.context.user_buffer:
                    tmp_state.solver.add(self.context.user_buffer == 0x41414141)
                else:
                    continue

                if tmp_state.satisfiable():
                    vuln_key = (
                        state.addr if hasattr(state, 'addr') else 0,
                        "arbitrary_rw_direct",
                        f"{event_type}_{target}"
                    )
                    if vuln_key in self.detected_vulns:
                        return None
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title=f"Arbitrary {'Read' if event_type == 'mem_read' else 'Write'} - {target}",
                        description=f"Direct user buffer allows arbitrary memory {event_type[4:]}",
                        state=state,
                        parameters={
                            "address": str(address)[:100],
                            "buffer_type": target,
                            "operation": event_type,
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "CRITICAL",
                            "exploitation": f"Direct kernel memory {event_type[4:]} via {target}",
                            "confidence": "HIGH",
                            "mitigation": "Use ProbeForRead/Write or METHOD_BUFFERED"
                        }
                    )

        return None

    def check_probe_for_read(self, state: SimState, address: Any, length: Any, alignment: Any) -> dict[str, Any] | None:
        """Public interface for ProbeForRead checks (for hooks).

        Args:
            state: Current simulation state
            address: Address to probe
            length: Length to probe
            alignment: Alignment requirement

        Returns:
            Vulnerability info if detected
        """
        return self._check_probe_for_read(state, args=[address, length, alignment])

    def _check_probe_for_read(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check ProbeForRead for bypass patterns (from probe_bypass).

        Args:
            state: Current simulation state
            **kwargs: Function arguments

        Returns:
            Vulnerability info if detected
        """
        args = kwargs.get("args", [])
        if len(args) < 3:
            return None

        address = args[0]
        length = args[1]

        # Store the probed range
        state_id = id(state)
        if state_id not in self.probed_addresses:
            self.probed_addresses[state_id] = []

        # Check for zero-length bypass
        try:
            if hasattr(length, "concrete"):
                length_val = state.solver.eval_one(length)
            else:
                length_val = int(length) if length is not None else 0

            if length_val == 0:
                vuln_key = (
                    state.addr if hasattr(state, 'addr') else 0,
                    "probe_zero_length",
                    "read"
                )
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="ProbeForRead Bypass - Zero Length",
                    description="ProbeForRead with length=0 bypasses all validation",
                    state=state,
                    parameters={
                        "address": str(address)[:100],
                        "length": "0",
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "HIGH",
                        "exploitation": "Validation bypass allows kernel memory access",
                        "confidence": "HIGH",
                        "reference": "MS08-066",
                        "mitigation": "Check for zero length before probe"
                    }
                )

            # Track this probe for later comparison
            self.probed_addresses[state_id].append({
                "address": address,
                "length": length,
                "type": "read"
            })

        except Exception as e:
            logger.debug(f"Error checking ProbeForRead: {e}")

        return None

    def check_probe_for_write(self, state: SimState, address: Any, length: Any, alignment: Any) -> dict[str, Any] | None:
        """Public interface for ProbeForWrite checks (for hooks).

        Args:
            state: Current simulation state
            address: Address to probe
            length: Length to probe
            alignment: Alignment requirement

        Returns:
            Vulnerability info if detected
        """
        return self._check_probe_for_write(state, args=[address, length, alignment])

    def _check_probe_for_write(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check ProbeForWrite for bypass patterns (from probe_bypass).

        Args:
            state: Current simulation state
            **kwargs: Function arguments

        Returns:
            Vulnerability info if detected
        """
        args = kwargs.get("args", [])
        if len(args) < 3:
            return None

        address = args[0]
        length = args[1]

        # Store the probed range
        state_id = id(state)
        if state_id not in self.probed_addresses:
            self.probed_addresses[state_id] = []

        # Check for zero-length bypass
        try:
            if hasattr(length, "concrete"):
                length_val = state.solver.eval_one(length)
            else:
                length_val = int(length) if length is not None else 0

            if length_val == 0:
                vuln_key = (
                    state.addr if hasattr(state, 'addr') else 0,
                    "probe_zero_length",
                    "write"
                )
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="ProbeForWrite Bypass - Zero Length",
                    description="ProbeForWrite with length=0 bypasses all validation",
                    state=state,
                    parameters={
                        "address": str(address)[:100],
                        "length": "0",
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "CRITICAL",
                        "exploitation": "Write-what-where primitive to kernel memory",
                        "confidence": "HIGH",
                        "reference": "MS08-066, CVE-2023-21768",
                        "mitigation": "Check for zero length before probe"
                    }
                )

            # Check if address is user-controlled but in kernel space
            if self._is_tainted(address):
                try:
                    addr_val = state.solver.eval_one(address) if hasattr(address, "concrete") else address
                    # Check if address is in kernel space (high bit set on x64)
                    if addr_val >= 0xFFFF000000000000:
                        vuln_key = (
                            state.addr if hasattr(state, 'addr') else 0,
                            "probe_kernel_address",
                            hex(addr_val)[:16]
                        )
                        if vuln_key in self.detected_vulns:
                            return None
                        self.detected_vulns.add(vuln_key)

                        return self.create_vulnerability_info(
                            title="ProbeForWrite - Kernel Address",
                            description="Tainted kernel address passed to ProbeForWrite",
                            state=state,
                            parameters={
                                "address": hex(addr_val),
                                "ioctl_code": self._get_ioctl_code(state),
                            },
                            others={
                                "severity": "CRITICAL",
                                "exploitation": "Direct kernel memory write",
                                "confidence": "HIGH",
                                "mitigation": "Validate address is in user space"
                            }
                        )
                except:
                    pass

            # Track this probe for later comparison
            self.probed_addresses[state_id].append({
                "address": address,
                "length": length,
                "type": "write"
            })

        except Exception as e:
            logger.debug(f"Error checking ProbeForWrite: {e}")

        return None

    def _check_memory_access(
        self, state: SimState, address: Any, size: Any, is_write: bool
    ) -> dict[str, Any] | None:
        """Check if memory access violates previous probe (from probe_bypass).

        Detects size mismatch issues.

        Args:
            state: Current simulation state
            address: Address being accessed
            size: Size of access
            is_write: True if write, False if read

        Returns:
            Vulnerability info if detected
        """
        state_id = id(state)

        # Check if this access was probed with different size
        if state_id in self.probed_addresses:
            for probe in self.probed_addresses[state_id]:
                if self._addresses_match(probe["address"], address):
                    # Check for size mismatch
                    if not self._sizes_match(probe["length"], size):
                        vuln_key = (
                            state.addr if hasattr(state, 'addr') else 0,
                            "probe_size_mismatch",
                            str(is_write)
                        )
                        if vuln_key in self.detected_vulns:
                            return None
                        self.detected_vulns.add(vuln_key)

                        return self.create_vulnerability_info(
                            title=f"Probe Size Mismatch - {'Write' if is_write else 'Read'}",
                            description="Memory access uses different size than probe validation",
                            state=state,
                            parameters={
                                "probed_size": str(probe["length"])[:100],
                                "actual_size": str(size)[:100],
                                "address": str(address)[:100],
                                "ioctl_code": self._get_ioctl_code(state),
                            },
                            others={
                                "severity": "HIGH",
                                "exploitation": "Buffer overflow via size mismatch",
                                "confidence": "HIGH",
                                "mitigation": "Ensure probe and access sizes match"
                            }
                        )

        return None

    def _addresses_match(self, addr1: Any, addr2: Any) -> bool:
        """Check if two addresses match.

        Args:
            addr1: First address
            addr2: Second address

        Returns:
            True if addresses match
        """
        try:
            # Convert to string for comparison if symbolic
            str1 = str(addr1)
            str2 = str(addr2)

            # Check if base addresses match (ignore offsets)
            for buf in ["SystemBuffer", "Type3InputBuffer", "UserBuffer"]:
                if buf in str1 and buf in str2:
                    return True

            # Try concrete comparison
            val1 = addr1
            val2 = addr2

            if hasattr(addr1, "concrete"):
                val1 = addr1.solver.eval_one(addr1) if hasattr(addr1, "solver") else addr1
            if hasattr(addr2, "concrete"):
                val2 = addr2.solver.eval_one(addr2) if hasattr(addr2, "solver") else addr2

            return val1 == val2
        except:
            return False

    def _sizes_match(self, size1: Any, size2: Any) -> bool:
        """Check if two sizes match.

        Args:
            size1: First size
            size2: Second size

        Returns:
            True if sizes match
        """
        try:
            val1 = size1
            val2 = size2

            if hasattr(size1, "concrete"):
                val1 = size1.solver.eval_one(size1) if hasattr(size1, "solver") else size1
            if hasattr(size2, "concrete"):
                val2 = size2.solver.eval_one(size2) if hasattr(size2, "solver") else size2

            return val1 == val2
        except:
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

        if hasattr(value, "symbolic"):
            return value.symbolic
        elif hasattr(value, "variables"):
            return len(value.variables) > 0

        # Check string representation for user buffers
        value_str = str(value)
        tainted_sources = [
            'SystemBuffer', 'Type3InputBuffer', 'UserBuffer',
            'InputBuffer', 'OutputBuffer'
        ]
        return any(src in value_str for src in tainted_sources)

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

    def get_statistics(self) -> dict[str, Any]:
        """Get detector statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "tracked_states": len(self.probed_addresses),
            "detected_vulnerabilities": len(self.detected_vulns),
        }


# Register the detector
detector_registry.register(UnifiedInputValidationDetector)
