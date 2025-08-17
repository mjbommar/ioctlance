"""ProbeForRead/Write bypass vulnerability detector."""

import logging
from typing import Any, cast

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class ProbeBypassDetector(VulnerabilityDetector):
    """Detects ProbeForRead/Write bypass vulnerabilities including zero-length and TOCTOU."""

    name = "probe_bypass"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects ProbeForRead/Write bypass patterns (zero-length, TOCTOU, size mismatch)"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the probe bypass detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        self.probed_addresses = {}  # Track probed addresses and their sizes
        self.memory_accesses = {}  # Track actual memory accesses
        self.detected_bypasses = set()

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect probe bypass vulnerabilities.

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

    def check_probe_for_read(self, state: SimState, address: Any, length: Any, alignment: Any) -> dict[str, Any] | None:
        """Check ProbeForRead for bypass patterns.

        Args:
            state: Current simulation state
            address: Address to probe
            length: Length to probe
            alignment: Alignment requirement

        Returns:
            Vulnerability info if detected
        """
        # Store the probed range
        state_id = id(state)
        if state_id not in self.probed_addresses:
            self.probed_addresses[state_id] = []

        # Check for zero-length bypass
        try:
            if hasattr(length, "concrete"):
                length_val = state.solver.eval_one(length)
            else:
                length_val = length

            if length_val == 0:
                # Zero-length probe - this bypasses all checks!
                vuln_key = (state.addr, "probe_zero_length")
                if vuln_key not in self.detected_bypasses:
                    self.detected_bypasses.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="ProbeForRead Bypass - Zero Length",
                        description="ProbeForRead called with length=0, bypassing all validation",
                        state=state,
                        parameters={
                            "address": str(address)[:100],
                            "length": "0",
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "Validation bypass allows kernel memory access",
                            "reference": "MS08-066",
                        },
                    )

            # Track this probe for later comparison
            self.probed_addresses[state_id].append({"address": address, "length": length, "type": "read"})

        except Exception as e:
            logger.debug(f"Error checking ProbeForRead: {e}")

        return None

    def check_probe_for_write(
        self, state: SimState, address: Any, length: Any, alignment: Any
    ) -> dict[str, Any] | None:
        """Check ProbeForWrite for bypass patterns.

        Args:
            state: Current simulation state
            address: Address to probe
            length: Length to probe
            alignment: Alignment requirement

        Returns:
            Vulnerability info if detected
        """
        # Store the probed range
        state_id = id(state)
        if state_id not in self.probed_addresses:
            self.probed_addresses[state_id] = []

        # Check for zero-length bypass
        try:
            if hasattr(length, "concrete"):
                length_val = state.solver.eval_one(length)
            else:
                length_val = length

            if length_val == 0:
                # Zero-length probe - this bypasses all checks!
                vuln_key = (state.addr, "probe_zero_length_write")
                if vuln_key not in self.detected_bypasses:
                    self.detected_bypasses.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="ProbeForWrite Bypass - Zero Length",
                        description="ProbeForWrite called with length=0, bypassing all validation",
                        state=state,
                        parameters={
                            "address": str(address)[:100],
                            "length": "0",
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "CRITICAL",
                            "exploitation": "Write-what-where primitive to kernel memory",
                            "reference": "MS08-066, CVE-2023-21768",
                        },
                    )

            # Check if address is user-controlled but in kernel space
            if self._is_tainted(address):
                try:
                    addr_val = state.solver.eval_one(address) if hasattr(address, "concrete") else address
                    # Check if address is in kernel space (high bit set on x64)
                    if addr_val >= 0xFFFF000000000000:
                        vuln_key = (state.addr, "probe_kernel_address")
                        if vuln_key not in self.detected_bypasses:
                            self.detected_bypasses.add(vuln_key)

                            return self.create_vulnerability_info(
                                title="ProbeForWrite - Kernel Address",
                                description="Tainted address in kernel space passed to ProbeForWrite",
                                state=state,
                                parameters={
                                    "address": hex(addr_val),
                                    "ioctl_code": self._get_ioctl_code(state),
                                },
                                others={
                                    "severity": "CRITICAL",
                                    "exploitation": "Direct kernel memory write",
                                },
                            )
                except:
                    pass

            # Track this probe for later comparison
            self.probed_addresses[state_id].append({"address": address, "length": length, "type": "write"})

        except Exception as e:
            logger.debug(f"Error checking ProbeForWrite: {e}")

        return None

    def check_memory_access(self, state: SimState, address: Any, size: Any, is_write: bool) -> dict[str, Any] | None:
        """Check if memory access violates previous probe.

        This detects size mismatch and TOCTOU issues.

        Args:
            state: Current simulation state
            address: Address being accessed
            size: Size of access
            is_write: True if write, False if read

        Returns:
            Vulnerability info if detected
        """
        state_id = id(state)
        if state_id not in self.probed_addresses:
            return None

        # Check if this access was probed with different size
        for probe in self.probed_addresses[state_id]:
            if self._addresses_match(probe["address"], address):
                # Check for size mismatch
                if not self._sizes_match(probe["length"], size):
                    vuln_key = (state.addr, "probe_size_mismatch", is_write)
                    if vuln_key not in self.detected_bypasses:
                        self.detected_bypasses.add(vuln_key)

                        return self.create_vulnerability_info(
                            title=f"Probe{'ForWrite' if is_write else 'ForRead'} Size Mismatch",
                            description=f"Memory {'write' if is_write else 'read'} uses different size than probe",
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
                            },
                        )

        # Track this access for TOCTOU detection
        if state_id not in self.memory_accesses:
            self.memory_accesses[state_id] = []

        # Check for double-fetch (TOCTOU)
        for prev_access in self.memory_accesses[state_id]:
            if self._addresses_match(prev_access["address"], address) and prev_access["is_write"] == is_write:
                # Same address accessed multiple times - potential TOCTOU
                vuln_key = (state.addr, "double_fetch", str(address)[:20])
                if vuln_key not in self.detected_bypasses:
                    self.detected_bypasses.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="Double-Fetch (TOCTOU) Vulnerability",
                        description="Same user memory accessed multiple times - race condition",
                        state=state,
                        parameters={
                            "address": str(address)[:100],
                            "access_type": "write" if is_write else "read",
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "Race condition exploitation via concurrent modification",
                        },
                    )

        self.memory_accesses[state_id].append({"address": address, "size": size, "is_write": is_write})

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
            # Handle symbolic and concrete addresses
            val1 = addr1
            val2 = addr2

            if hasattr(addr1, "concrete"):
                val1 = addr1.solver.eval_one(addr1) if hasattr(addr1, "solver") else addr1
            if hasattr(addr2, "concrete"):
                val2 = addr2.solver.eval_one(addr2) if hasattr(addr2, "solver") else addr2

            return val1 == val2
        except:
            # If we can't evaluate, assume they don't match
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
            # If we can't evaluate, assume they don't match
            return False

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
        elif self.context and self.context.io_control_code:
            try:
                return safe_hex(state.solver.eval(self.context.io_control_code))
            except:
                pass
        return "0x0"


# Register the detector
detector_registry.register(ProbeBypassDetector)
