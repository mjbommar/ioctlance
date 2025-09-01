"""Information disclosure vulnerability detector for IOCTLance.

Detects various forms of information leakage:
- Kernel address disclosure (KASLR bypass)
- Uninitialized memory reads
- Out-of-bounds reads
- Stack/heap information leaks
- Pool metadata disclosure
"""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import safe_hex, get_state_globals
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class InformationDisclosureDetector(VulnerabilityDetector):
    """Detects information disclosure vulnerabilities.

    This detector identifies:
    - Kernel pointer leaks to userspace
    - Uninitialized memory disclosure
    - Out-of-bounds reads exposing sensitive data
    - Stack/heap metadata leaks
    """

    name = "information_disclosure"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects information disclosure and KASLR bypass vulnerabilities"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the information disclosure detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)

        # Track memory operations
        self.kernel_addresses_leaked: set[int] = set()
        self.uninitialized_reads: set[tuple[int, str]] = set()
        self.oob_reads: set[tuple[int, str]] = set()

        # Deduplication
        self.detected_vulns: set[tuple[int, str, str]] = set()

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for information disclosure vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Event-specific arguments

        Returns:
            Vulnerability info if detected, None otherwise
        """
        if event_type == "mem_read":
            # Check for various read-based disclosures
            vuln = self._check_memory_read(state, **kwargs)
            if vuln:
                return vuln

        elif event_type == "mem_write":
            # Check if kernel addresses are being written to user buffers
            vuln = self._check_kernel_address_leak(state, **kwargs)
            if vuln:
                return vuln

        elif event_type == "call":
            func_name = kwargs.get("function_name", "")
            # Check specific functions that might leak info
            if func_name in ["RtlCopyMemory", "memcpy", "memmove"]:
                return self._check_copy_disclosure(state, **kwargs)

        return None

    def _check_memory_read(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check memory read operations for disclosure.

        Args:
            state: Current simulation state
            **kwargs: Read operation parameters

        Returns:
            Vulnerability info if detected
        """
        address = kwargs.get("address")
        size = kwargs.get("size")

        if address is None:
            return None

        # Check for kernel pool/stack reads
        addr_str = str(address)

        # 1. Check for uninitialized memory reads
        if self._is_uninitialized_memory(address, state):
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "uninitialized_read", addr_str[:30])
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Uninitialized Memory Disclosure",
                    description="Reading uninitialized kernel memory",
                    state=state,
                    parameters={
                        "address": addr_str[:100],
                        "size": str(size)[:100] if size else "unknown",
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "MEDIUM",
                        "exploitation": "Leak kernel data, addresses, secrets",
                        "confidence": "MEDIUM",
                        "impact": "Information disclosure, KASLR bypass",
                        "mitigation": "Initialize memory before use",
                        "windows_specific": "Can leak pool tags, kernel addresses",
                    },
                )

        # 2. Check for kernel stack reads
        if self._is_kernel_stack(address):
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "stack_disclosure", addr_str[:30])
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Kernel Stack Information Disclosure",
                    description="Reading from kernel stack memory",
                    state=state,
                    parameters={
                        "address": addr_str[:100],
                        "size": str(size)[:100] if size else "unknown",
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "HIGH",
                        "exploitation": "Leak return addresses, local variables",
                        "confidence": "HIGH",
                        "impact": "KASLR bypass, control flow disclosure",
                        "mitigation": "Avoid exposing stack data to userspace",
                    },
                )

        # 3. Check for out-of-bounds reads
        if self._is_oob_read(address, size, state):
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "oob_read", addr_str[:30])
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Out-of-Bounds Read",
                    description="Reading beyond allocated buffer boundaries",
                    state=state,
                    parameters={
                        "address": addr_str[:100],
                        "size": str(size)[:100] if size else "unknown",
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "HIGH",
                        "exploitation": "Read adjacent memory, leak sensitive data",
                        "confidence": "MEDIUM",
                        "impact": "Information disclosure",
                        "mitigation": "Validate read boundaries",
                    },
                )

        return None

    def _check_kernel_address_leak(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check if kernel addresses are being leaked to userspace.

        Args:
            state: Current simulation state
            **kwargs: Write operation parameters

        Returns:
            Vulnerability info if detected
        """
        address = kwargs.get("address")
        data = kwargs.get("data")

        if address is None or not data:
            return None

        # Check if writing to user buffer
        if not self._is_user_buffer(address):
            return None

        # Check if data contains kernel addresses
        if self._contains_kernel_address(data):
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "kernel_address_leak", str(address)[:30])
            if vuln_key not in self.detected_vulns:
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Kernel Address Disclosure (KASLR Bypass)",
                    description="Kernel addresses leaked to userspace buffer",
                    state=state,
                    parameters={
                        "user_buffer": str(address)[:100],
                        "leaked_data": str(data)[:100],
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "HIGH",
                        "exploitation": "Bypass KASLR, calculate kernel base",
                        "confidence": "HIGH",
                        "impact": "Defeats address randomization",
                        "mitigation": "Sanitize data before copying to userspace",
                        "windows_specific": "Exposes kernel module addresses",
                    },
                )

        return None

    def _check_copy_disclosure(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check memory copy operations for information disclosure.

        Args:
            state: Current simulation state
            **kwargs: Function arguments

        Returns:
            Vulnerability info if detected
        """
        args = kwargs.get("args", [])
        if len(args) < 3:
            return None

        dest = args[0]
        src = args[1]
        size = args[2]

        # Check if copying from kernel to user
        if self._is_user_buffer(dest) and self._is_kernel_memory(src):
            # Check for various disclosure patterns

            # 1. Copying uninitialized memory
            if self._is_uninitialized_memory(src, state):
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "copy_uninitialized", str(src)[:30])
                if vuln_key not in self.detected_vulns:
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="Uninitialized Memory Copy to Userspace",
                        description="Copying uninitialized kernel memory to user buffer",
                        state=state,
                        parameters={
                            "source": str(src)[:100],
                            "destination": str(dest)[:100],
                            "size": str(size)[:100],
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "Leak previous kernel data",
                            "confidence": "HIGH",
                            "impact": "Information disclosure",
                            "mitigation": "Zero memory before copying",
                        },
                    )

            # 2. Excessive size copying (potential OOB)
            if self._is_excessive_size(size):
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "excessive_copy", str(size)[:30])
                if vuln_key not in self.detected_vulns:
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="Excessive Data Copy to Userspace",
                        description="Large copy operation may leak adjacent memory",
                        state=state,
                        parameters={
                            "source": str(src)[:100],
                            "destination": str(dest)[:100],
                            "size": str(size)[:100],
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "MEDIUM",
                            "exploitation": "Read beyond intended boundaries",
                            "confidence": "MEDIUM",
                            "impact": "Information disclosure",
                            "mitigation": "Validate copy size",
                        },
                    )

        return None

    def _is_uninitialized_memory(self, address: Any, state: SimState) -> bool:
        """Check if memory appears to be uninitialized.

        Args:
            address: Memory address
            state: Current state

        Returns:
            True if memory is likely uninitialized
        """
        addr_str = str(address)

        # Common patterns for uninitialized memory
        uninitialized_patterns = [
            "Alloc",  # Recently allocated
            "Pool",  # Pool allocations
            "Stack",  # Stack variables
        ]

        # Check if this is freshly allocated memory
        for pattern in uninitialized_patterns:
            if pattern in addr_str and "Init" not in addr_str:
                return True

        # Check if memory was just allocated (heuristic)
        if hasattr(state, "history"):
            recent_calls = []
            try:
                for action in state.history.actions[-10:]:
                    if hasattr(action, "type") and action.type == "call":
                        if hasattr(action, "function_name"):
                            recent_calls.append(action.function_name)
            except:
                pass

            alloc_functions = ["ExAllocatePool", "ExAllocatePoolWithTag", "alloca"]
            for func in alloc_functions:
                if func in recent_calls:
                    return True

        return False

    def _is_kernel_stack(self, address: Any) -> bool:
        """Check if address is on kernel stack.

        Args:
            address: Memory address

        Returns:
            True if address is on kernel stack
        """
        addr_str = str(address)
        stack_indicators = ["rsp", "esp", "rbp", "ebp", "Stack", "STACK"]
        return any(indicator in addr_str for indicator in stack_indicators)

    def _is_kernel_memory(self, address: Any) -> bool:
        """Check if address is kernel memory.

        Args:
            address: Memory address

        Returns:
            True if address is kernel memory
        """
        # Check if not user buffer
        return not self._is_user_buffer(address)

    def _is_user_buffer(self, address: Any) -> bool:
        """Check if address is a user buffer.

        Args:
            address: Memory address

        Returns:
            True if address is user buffer
        """
        if address is None:
            return False

        addr_str = str(address)
        user_buffers = ["SystemBuffer", "Type3InputBuffer", "UserBuffer", "OutputBuffer", "InputBuffer"]
        return any(buf in addr_str for buf in user_buffers)

    def _is_oob_read(self, address: Any, size: Any, state: SimState) -> bool:
        """Check if read is out-of-bounds.

        Args:
            address: Read address
            size: Read size
            state: Current state

        Returns:
            True if read appears to be OOB
        """
        # Check if size is suspiciously large
        if size is not None:
            try:
                size_val = state.solver.eval_one(size) if hasattr(size, "concrete") else int(size)
                # Suspicious if reading more than a page
                if size_val > 0x1000:
                    return True
            except:
                pass

        # Check if address calculation suggests OOB
        addr_str = str(address)
        if "+" in addr_str:
            # Look for large offsets
            parts = addr_str.split("+")
            for part in parts[1:]:
                try:
                    offset = int(part.strip(), 16) if "0x" in part else int(part.strip())
                    if offset > 0x1000:
                        return True
                except:
                    pass

        return False

    def _contains_kernel_address(self, data: Any) -> bool:
        """Check if data contains kernel addresses.

        Args:
            data: Data to check

        Returns:
            True if data contains kernel addresses
        """
        if data is None:
            return False

        # Windows kernel addresses typically start with 0xFFFF
        data_str = str(data)
        kernel_patterns = [
            "0xffff",  # Kernel address prefix
            "0xFFFF",
            "nt!",  # NT kernel symbols
            "hal!",  # HAL symbols
            "Driver",  # Driver objects
            "Device",  # Device objects
        ]

        return any(pattern in data_str for pattern in kernel_patterns)

    def _is_excessive_size(self, size: Any) -> bool:
        """Check if copy size is excessive.

        Args:
            size: Size value

        Returns:
            True if size is excessive
        """
        if size is None:
            return False

        try:
            if hasattr(size, "concrete"):
                size_val = size
            else:
                size_val = int(size)

            # More than 4KB is suspicious for most operations
            return size_val > 0x1000
        except:
            # If we can't evaluate, check symbolically
            size_str = str(size)
            return "InputBufferLength" in size_str or "OutputBufferLength" in size_str

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
            "kernel_addresses_leaked": len(self.kernel_addresses_leaked),
            "uninitialized_reads": len(self.uninitialized_reads),
            "oob_reads": len(self.oob_reads),
            "detected_vulnerabilities": len(self.detected_vulns),
        }


# Register the detector
detector_registry.register(InformationDisclosureDetector)
