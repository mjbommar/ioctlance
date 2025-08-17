"""Format string vulnerability detector."""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from .base import VulnerabilityDetector

logger = logging.getLogger(__name__)


class FormatStringDetector(VulnerabilityDetector):
    """Detects format string vulnerabilities in sprintf/swprintf/printf family functions."""

    name = "format_string"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects format string vulnerabilities with tainted format parameters"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the format string detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        self.detected_format_strings = set()

        # Functions that use format strings
        self.format_functions = {
            "sprintf",
            "swprintf",
            "snprintf",
            "snwprintf",
            "vsprintf",
            "vswprintf",
            "vsnprintf",
            "vsnwprintf",
            "RtlStringCbPrintfA",
            "RtlStringCbPrintfW",
            "RtlStringCchPrintfA",
            "RtlStringCchPrintfW",
            "DbgPrint",
            "KdPrint",
        }

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect format string vulnerabilities.

        This detector hooks format string functions and checks if:
        1. The format parameter is tainted (user-controlled)
        2. The format string contains dangerous specifiers

        Args:
            state: Current simulation state

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # This is called from breakpoints, not directly
        # The actual detection happens in check_format_string_call
        return None

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for format string vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event (mem_read, mem_write, call, expr)
            **kwargs: Additional event-specific arguments

        Returns:
            Vulnerability information if detected
        """
        # We only care about function calls
        if event_type != "call":
            return None

        func_name = kwargs.get("func_name")
        if func_name not in self.format_functions:
            return None

        # Check the format string parameter
        return self.check_format_string_call(state, func_name, **kwargs)

    def check_format_string_call(self, state: SimState, func_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check a format string function call for vulnerabilities.

        Args:
            state: Current simulation state
            func_name: Name of the function being called
            **kwargs: Function arguments

        Returns:
            Vulnerability information if detected
        """
        # Get the format string parameter (usually the second parameter)
        # For sprintf(buffer, format, ...) - format is at index 1
        # For swprintf(buffer, size, format, ...) - format is at index 2

        format_param_index = 1
        if "swprintf" in func_name or "snwprintf" in func_name:
            format_param_index = 2  # swprintf has size parameter

        # Get function arguments based on calling convention
        # Windows x64 uses RCX, RDX, R8, R9 for first 4 params
        format_param = None

        if state.arch.name == "AMD64":
            if format_param_index == 1:
                format_param = state.regs.rdx
            elif format_param_index == 2:
                format_param = state.regs.r8
        else:
            # x86 uses stack
            format_param = state.mem[state.regs.esp + 4 + (format_param_index * 4)].dword.resolved

        if format_param is None:
            return None

        # Check if format parameter is symbolic (tainted)
        is_tainted = False

        if hasattr(format_param, "symbolic"):
            is_tainted = format_param.symbolic
        elif hasattr(format_param, "variables") and len(format_param.variables) > 0:
            is_tainted = True

        # Also check if the format string points to tainted memory
        if not is_tainted:
            try:
                # Try to read the format string from memory
                format_str_addr = state.solver.eval_one(format_param)
                # Check if the memory at that address is symbolic
                format_byte = state.memory.load(format_str_addr, 1)
                if hasattr(format_byte, "symbolic") and format_byte.symbolic:
                    is_tainted = True
            except Exception:
                pass

        if not is_tainted:
            return None

        # Create unique key for deduplication
        vuln_key = (state.addr, func_name)
        if vuln_key in self.detected_format_strings:
            return None
        self.detected_format_strings.add(vuln_key)

        # Create vulnerability report
        vuln = {
            "title": "format string vulnerability",
            "description": f"Tainted format string in {func_name} can lead to information disclosure or code execution",
            "state": repr(state),
            "eval": {
                "IoControlCode": (
                    hex(self.context.io_control_code)
                    if isinstance(self.context.io_control_code, int)
                    else str(self.context.io_control_code)
                    if self.context.io_control_code is not None
                    else "N/A"
                ),
            },
            "parameters": {
                "function": func_name,
                "format_param": str(format_param),
                "format_param_index": format_param_index,
            },
            "others": {
                "instruction_address": hex(state.addr),
                "severity": "CRITICAL",  # Format string bugs can lead to arbitrary code execution
            },
        }

        self.context.print_info(f"[VULN] Format string vulnerability in {func_name} at {state.addr:#x}")
        return vuln


# Register the detector
from .base import detector_registry

detector_registry.register(FormatStringDetector)
