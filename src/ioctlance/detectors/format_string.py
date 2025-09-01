"""Format string vulnerability detector for IOCTLance."""

import logging
from typing import Any
from angr import SimState

from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class FormatStringDetector(VulnerabilityDetector):
    """Detects format string vulnerabilities in kernel drivers."""

    # Common printf-family functions vulnerable to format string attacks
    PRINTF_FUNCTIONS = {
        # Standard C functions
        "sprintf",
        "vsprintf",
        "swprintf",
        "vswprintf",
        "snprintf",
        "vsnprintf",
        "_snprintf",
        "_vsnprintf",
        "fprintf",
        "vfprintf",
        "printf",
        "vprintf",
        # Windows kernel specific
        "DbgPrint",
        "DbgPrintEx",
        "KdPrint",
        "KdPrintEx",
        "RtlStringCbPrintf",
        "RtlStringCbPrintfEx",
        "RtlStringCchPrintf",
        "RtlStringCchPrintfEx",
        "RtlUnicodeStringPrintf",
        "RtlUnicodeStringPrintfEx",
    }

    def __init__(self, context):
        """Initialize format string detector."""
        super().__init__(context)
        self.detected_vulns = set()
        self.tainted_strings = set()  # Track strings that come from user input

    @property
    def name(self) -> str:
        """Get detector name."""
        return "format_string"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects format string vulnerabilities where user-controlled format strings are passed to printf-family functions"

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for format string vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event ('function_call')
            **kwargs: Event-specific data

        Returns:
            Vulnerability info if found, None otherwise
        """
        if event_type == "function_call":
            return self._check_format_function(state, **kwargs)
        elif event_type == "mem_write":
            # Track when user data is written to buffers
            address = kwargs.get("address")
            value = kwargs.get("value")
            if address is not None and value is not None:
                self._track_tainted_write(state, address, value)

        return None

    def _check_format_function(self, state: SimState, function_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check if a printf-family function has tainted format string.

        Args:
            state: Current simulation state
            function_name: Name of function being called
            **kwargs: Additional parameters

        Returns:
            Vulnerability info if found, None otherwise
        """
        if function_name not in self.PRINTF_FUNCTIONS:
            return None

        # Get format string argument position based on function
        format_arg_pos = self._get_format_arg_position(function_name)

        # Check if format string is tainted (comes from user input)
        try:
            # Get calling convention arguments
            if hasattr(state, "regs"):
                # Windows x64 calling convention: RCX, RDX, R8, R9, stack
                arg_regs = ["rcx", "rdx", "r8", "r9"] if hasattr(state.regs, "rcx") else ["rdi", "rsi", "rdx", "rcx"]

                if format_arg_pos < len(arg_regs):
                    format_arg = getattr(state.regs, arg_regs[format_arg_pos])
                else:
                    # Stack argument
                    stack_offset = 0x20 + (format_arg_pos - 4) * 8  # Shadow space + args
                    format_arg = state.memory.load(state.regs.rsp + stack_offset, 8)

                # Check if format string pointer is tainted
                if self._is_tainted(format_arg):
                    return self._create_format_string_vuln(state, function_name, format_arg)

                # Check if format string itself contains dangerous specifiers
                if self._contains_dangerous_specifiers(state, format_arg):
                    return self._create_format_string_vuln(state, function_name, format_arg, dangerous_specifiers=True)

        except Exception as e:
            logger.debug(f"Error checking format string: {e}")

        return None

    def _track_tainted_write(self, state: SimState, address: Any, value: Any) -> None:
        """Track when tainted data is written to memory.

        Args:
            state: Current simulation state
            address: Memory address being written
            value: Value being written
        """
        # If value comes from IOCTL input, mark address as tainted
        if self._is_from_ioctl_input(value):
            try:
                if hasattr(address, "concrete"):
                    concrete_addr = state.solver.eval(address)
                    self.tainted_strings.add(concrete_addr)
            except:
                pass

    def _get_format_arg_position(self, function_name: str) -> int:
        """Get the argument position of format string for a function.

        Args:
            function_name: Name of the printf-family function

        Returns:
            Zero-based index of format string argument
        """
        # For most functions, format string is the second argument (index 1)
        # First argument is usually the destination buffer
        if function_name in ["sprintf", "snprintf", "swprintf", "_snprintf", "RtlStringCbPrintf", "RtlStringCchPrintf"]:
            return 1
        # For printf/DbgPrint, format string is first argument
        elif function_name in ["printf", "DbgPrint", "KdPrint", "vprintf"]:
            return 0
        # For fprintf, format string is second argument (after file handle)
        elif function_name in ["fprintf", "vfprintf"]:
            return 1
        # For Ex versions, format string comes after component/level
        elif function_name in ["DbgPrintEx", "KdPrintEx"]:
            return 2
        else:
            return 1  # Default to second argument

    def _is_tainted(self, value: Any) -> bool:
        """Check if a value is tainted (comes from user input).

        Args:
            value: Value to check

        Returns:
            True if tainted, False otherwise
        """
        if value is None:
            return False

        # Check if value has symbolic variables
        if hasattr(value, "symbolic") and value.symbolic:
            # Check if any symbolic variable is from IOCTL input
            for var in value.variables:
                if "input" in var.lower() or "ioctl" in var.lower() or "user" in var.lower():
                    return True

        # Check if concrete value points to tainted memory
        try:
            if hasattr(value, "concrete"):
                concrete_val = self.context.state.solver.eval(value)
                if concrete_val in self.tainted_strings:
                    return True
        except:
            pass

        return False

    def _is_from_ioctl_input(self, value: Any) -> bool:
        """Check if value originates from IOCTL input.

        Args:
            value: Value to check

        Returns:
            True if from IOCTL input, False otherwise
        """
        if value is None:
            return False

        # Check symbolic variable names
        if hasattr(value, "symbolic") and value.symbolic:
            for var in value.variables:
                var_name = var.lower() if hasattr(var, "lower") else str(var).lower()
                if "systembuffer" in var_name or "inputbuffer" in var_name:
                    return True

        return False

    def _contains_dangerous_specifiers(self, state: SimState, format_str_ptr: Any) -> bool:
        """Check if format string contains dangerous format specifiers.

        Args:
            state: Current simulation state
            format_str_ptr: Pointer to format string

        Returns:
            True if dangerous specifiers found, False otherwise
        """
        dangerous_specifiers = ["%n", "%hn", "%hhn", "%ln", "%lln"]  # Write to memory

        try:
            # Try to read format string from memory
            if hasattr(format_str_ptr, "concrete"):
                ptr = state.solver.eval(format_str_ptr)
                # Read up to 256 bytes for format string
                fmt_bytes = state.memory.load(ptr, 256)

                if hasattr(fmt_bytes, "concrete"):
                    fmt_str = state.solver.eval(fmt_bytes, cast_to=bytes)
                    fmt_str = fmt_str.decode("utf-8", errors="ignore")

                    for spec in dangerous_specifiers:
                        if spec in fmt_str:
                            return True
        except:
            pass

        return False

    def _create_format_string_vuln(
        self, state: SimState, function_name: str, format_arg: Any, dangerous_specifiers: bool = False
    ) -> dict[str, Any]:
        """Create format string vulnerability info.

        Args:
            state: Current simulation state
            function_name: Name of vulnerable function
            format_arg: Format string argument
            dangerous_specifiers: Whether dangerous specifiers were found

        Returns:
            Vulnerability information dictionary
        """
        vuln_type = "format_string_specifier" if dangerous_specifiers else "format_string_tainted"
        vuln_key = (state.addr if hasattr(state, "addr") else 0, vuln_type, function_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        title = "Format String - Dangerous Specifier" if dangerous_specifiers else "Format String - Tainted Input"

        return self.create_vulnerability_info(
            title=title,
            description=f"Format string vulnerability in {function_name}: "
            + ("dangerous format specifier detected" if dangerous_specifiers else "user-controlled format string"),
            state=state,
            severity="CRITICAL" if dangerous_specifiers else "HIGH",
            parameters={
                "function": function_name,
                "format_arg": str(format_arg)[:100],
                "type": "dangerous_specifier" if dangerous_specifiers else "tainted_input",
            },
        )


# Register detector
detector_registry.register(FormatStringDetector)
