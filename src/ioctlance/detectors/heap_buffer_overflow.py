"""Heap buffer overflow detector for IOCTLance."""

import logging
from typing import Any
from angr import SimState

from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class HeapBufferOverflowDetector(VulnerabilityDetector):
    """Detects heap buffer overflow vulnerabilities in kernel drivers."""

    def __init__(self, context):
        """Initialize heap buffer overflow detector."""
        super().__init__(context)
        self.detected_vulns = set()  # Track detected vulnerabilities to avoid duplicates

    @property
    def name(self) -> str:
        """Get detector name."""
        return "heap_buffer_overflow"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects heap buffer overflows through size miscalculations and improper bounds checking"

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for heap buffer overflow vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event ('mem_write', 'mem_read', 'function_call')
            **kwargs: Event-specific data

        Returns:
            Vulnerability info if found, None otherwise
        """
        if event_type == "mem_write":
            return self._check_heap_write(state, **kwargs)
        elif event_type == "function_call":
            return self._check_heap_function(state, **kwargs)

        return None

    def _check_heap_write(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check for heap overflow on memory write."""
        address = kwargs.get("address")
        size = kwargs.get("size")

        if address is None:
            return None

        addr_str = str(address)

        # Check for heap-related addresses
        heap_indicators = [
            "ExAllocatePool", "RtlAllocateHeap",
            "ExAllocatePoolWithTag", "HeapAlloc"
        ]

        is_heap = any(ind in addr_str for ind in heap_indicators)
        if not is_heap:
            return None

        # Check for controllable size
        if self._is_controllable_size(state, size):
            return self._create_heap_overflow_vuln(state, address, size)

        # Check for integer overflow in size calculation
        if self._has_integer_overflow_in_size(state, size):
            return self._create_heap_overflow_vuln(state, address, size, integer_overflow=True)

        return None

    def _check_heap_function(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Check for heap overflow in function calls."""
        func_name = kwargs.get("func_name", "").lower()

        # Memory copy functions that can cause heap overflow
        dangerous_funcs = {
            "memcpy": ("dest", "src", "count"),
            "memmove": ("dest", "src", "count"),
            "rtlcopymemory": ("destination", "source", "length"),
            "rtlmovememory": ("destination", "source", "length"),
            "strcpy": ("dest", "src", None),
            "strcat": ("dest", "src", None),
            "sprintf": ("buffer", "format", None),
            "swprintf": ("buffer", "format", None),
        }

        for func, (dest_param, src_param, size_param) in dangerous_funcs.items():
            if func in func_name:
                dest = kwargs.get(dest_param)
                src = kwargs.get(src_param)
                size = kwargs.get(size_param) if size_param else None

                # Check if destination is heap memory
                if dest and self._is_heap_address(state, dest):
                    # Check for unbounded copy (strcpy, strcat)
                    if size_param is None:
                        return self._create_unbounded_copy_vuln(state, func_name, dest, src)

                    # Check for controllable size
                    if size is not None and self._is_controllable_size(state, size):
                        return self._create_sized_copy_vuln(state, func_name, dest, src, size)

                    # Check for size miscalculation
                    if size is not None and self._has_size_miscalculation(state, dest, size):
                        return self._create_size_mismatch_vuln(state, func_name, dest, size)

        return None

    def _is_heap_address(self, state: SimState, address: Any) -> bool:
        """Check if address is heap memory."""
        if address is None:
            return False

        addr_str = str(address)
        heap_indicators = [
            "ExAllocatePool", "RtlAllocateHeap",
            "ExAllocatePoolWithTag", "HeapAlloc",
            "pool", "heap"
        ]

        return any(ind.lower() in addr_str.lower() for ind in heap_indicators)

    def _is_controllable_size(self, state: SimState, size: Any) -> bool:
        """Check if size is user-controllable."""
        if size is None:
            return False

        size_str = str(size)

        # Check for user input sources
        user_sources = [
            "SystemBuffer", "Type3InputBuffer", "UserBuffer",
            "input_buffer", "InputBufferLength", "IoControlCode"
        ]

        for source in user_sources:
            if source in size_str:
                # Size derived from user input
                return True

        # Check if symbolic and derived from user input
        if hasattr(size, 'symbolic') and size.symbolic:
            if hasattr(size, 'variables'):
                for var in size.variables:
                    var_str = str(var)
                    for source in user_sources:
                        if source in var_str:
                            return True

        return False

    def _has_integer_overflow_in_size(self, state: SimState, size: Any) -> bool:
        """Check for integer overflow in size calculation."""
        if size is None:
            return False

        size_str = str(size)

        # Look for multiplication or addition that could overflow
        overflow_patterns = [
            "__mul__", "__add__", "*", "+",
            "Concat"  # Concatenation can lead to large values
        ]

        has_arithmetic = any(pattern in size_str for pattern in overflow_patterns)

        if has_arithmetic and hasattr(state, 'solver'):
            try:
                # Check if size can be very large (potential overflow)
                tmp_state = state.copy()
                # Check for wrap-around to small values
                tmp_state.solver.add(size < 0x100)  # Small value after overflow
                if tmp_state.satisfiable():
                    # Also check if original calculation would be large
                    tmp_state2 = state.copy()
                    tmp_state2.solver.add(size > 0xFFFF0000)  # Near max value
                    if tmp_state2.satisfiable():
                        return True
            except:
                pass

        return False

    def _has_size_miscalculation(self, state: SimState, dest: Any, size: Any) -> bool:
        """Check for size miscalculation between allocation and usage."""
        # This would require tracking allocation sizes
        # For now, check for obvious mismatches

        if size is None:
            return False

        size_str = str(size)
        dest_str = str(dest)

        # Check for different size calculations
        if "InputBufferLength" in size_str and "OutputBufferLength" in dest_str:
            return True

        # Check for off-by-one patterns
        if "+1" in size_str or "-1" in size_str:
            return True

        return False

    def _create_heap_overflow_vuln(self, state: SimState, address: Any, size: Any, integer_overflow: bool = False) -> dict[str, Any]:
        """Create heap overflow vulnerability."""
        vuln_type = "heap_overflow_int" if integer_overflow else "heap_overflow"
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, vuln_type, str(address)[:30])

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        title = "Heap Buffer Overflow - Integer Overflow" if integer_overflow else "Heap Buffer Overflow"

        return self.create_vulnerability_info(
            title=title,
            description="Heap buffer overflow due to " + ("integer overflow in size calculation" if integer_overflow else "controllable size"),
            state=state,
            parameters={
                "address": str(address)[:100],
                "size": str(size)[:100],
                "is_integer_overflow": integer_overflow,
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "CRITICAL",
                "exploitation": "Code execution, privilege escalation",
                "confidence": "HIGH" if integer_overflow else "MEDIUM",
                "windows_specific": "Can corrupt heap metadata, trigger KERNEL_MODE_HEAP_CORRUPTION (0x13A)",
                "cwe": "CWE-122: Heap-based Buffer Overflow",
                "mitigation": "Validate sizes, use safe integer arithmetic, bounds checking"
            }
        )

    def _create_unbounded_copy_vuln(self, state: SimState, func_name: str, dest: Any, src: Any) -> dict[str, Any]:
        """Create unbounded copy vulnerability."""
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, "unbounded_copy", func_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title=f"Unbounded Heap Copy - {func_name}",
            description=f"Using unsafe {func_name} on heap buffer without size limit",
            state=state,
            parameters={
                "function": func_name,
                "destination": str(dest)[:100],
                "source": str(src)[:100],
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "CRITICAL",
                "exploitation": "Heap overflow, code execution",
                "confidence": "HIGH",
                "windows_specific": "Use RtlStringCbCopy or RtlStringCchCopy instead",
                "cwe": "CWE-120: Buffer Copy without Checking Size of Input",
            }
        )

    def _create_sized_copy_vuln(self, state: SimState, func_name: str, dest: Any, src: Any, size: Any) -> dict[str, Any]:
        """Create controllable size copy vulnerability."""
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, "sized_copy", func_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title=f"Controllable Size Heap Copy - {func_name}",
            description=f"Using {func_name} with user-controllable size on heap buffer",
            state=state,
            parameters={
                "function": func_name,
                "destination": str(dest)[:100],
                "source": str(src)[:100],
                "size": str(size)[:100],
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "HIGH",
                "exploitation": "Heap overflow, memory corruption",
                "confidence": "MEDIUM",
                "windows_specific": "Validate size against allocated buffer size",
                "cwe": "CWE-805: Buffer Access with Incorrect Length Value",
            }
        )

    def _create_size_mismatch_vuln(self, state: SimState, func_name: str, dest: Any, size: Any) -> dict[str, Any]:
        """Create size mismatch vulnerability."""
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, "size_mismatch", func_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title=f"Heap Size Mismatch - {func_name}",
            description="Size calculation mismatch between allocation and usage",
            state=state,
            parameters={
                "function": func_name,
                "destination": str(dest)[:100],
                "size": str(size)[:100],
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "HIGH",
                "exploitation": "Heap overflow, off-by-one errors",
                "confidence": "MEDIUM",
                "windows_specific": "Track allocation sizes, validate against usage",
                "cwe": "CWE-131: Incorrect Calculation of Buffer Size",
            }
        )

    def _get_ioctl_code(self, state: SimState) -> str:
        """Get current IOCTL code."""
        if hasattr(self.context, 'io_control_code'):
            try:
                ioctl = state.solver.eval_one(self.context.io_control_code)
                return hex(ioctl)
            except:
                pass
        return "0x0"


# Register the detector
detector_registry.register(HeapBufferOverflowDetector)
