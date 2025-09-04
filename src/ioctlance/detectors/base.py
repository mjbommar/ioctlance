"""Base vulnerability detector interface for IOCTLance."""

import logging
from abc import ABC, abstractmethod
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.state_capture import capture_raw_state
from ..utils.error_handler import SymbolicExecutionErrorHandler

logger = logging.getLogger(__name__)


class VulnerabilityDetector(ABC):
    """Base class for vulnerability detectors.

    Each detector specializes in finding specific types of vulnerabilities
    in Windows drivers during symbolic execution.
    """

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the detector.

        Args:
            context: Analysis context containing driver and configuration
        """
        self.context = context
        self.enabled = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of this detector.

        Returns:
            Detector name (e.g., 'buffer_overflow', 'null_pointer')
        """
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Get a description of what this detector finds.

        Returns:
            Human-readable description
        """
        pass

    @abstractmethod
    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check if a vulnerability exists in the current state.

        Args:
            state: Current simulation state
            event_type: Type of event ('mem_read', 'mem_write', 'call', etc.)
            **kwargs: Additional event-specific data

        Returns:
            Vulnerability info dict if found, None otherwise
        """
        pass

    def is_address_validated(self, state: SimState, address: Any) -> bool:
        """Check if an address has been validated by ProbeForRead/Write or MmIsAddressValid.

        Args:
            state: Current simulation state
            address: Address to check

        Returns:
            True if address has been validated
        """
        tainted_probe_read = state.globals.get("tainted_ProbeForRead", ())
        tainted_probe_write = state.globals.get("tainted_ProbeForWrite", ())
        tainted_mmisvalid = state.globals.get("tainted_MmIsAddressValid", ())

        addr_str = str(address)
        return addr_str in tainted_probe_read or addr_str in tainted_probe_write or addr_str in tainted_mmisvalid

    def create_vulnerability_info(
        self,
        title: str,
        description: str,
        state: SimState,
        parameters: dict[str, Any] | None = None,
        others: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a standardized vulnerability info dictionary.

        Args:
            title: Vulnerability title
            description: Detailed description
            state: Current simulation state
            parameters: Additional parameters
            others: Other information

        Returns:
            Vulnerability info dictionary
        """
        # Get evaluation values
        eval_params = {}

        if self.context.io_control_code is not None:
            try:
                ioctl = state.solver.eval_one(self.context.io_control_code)
                eval_params["IoControlCode"] = hex(ioctl)
            except Exception as e:
                if not SymbolicExecutionErrorHandler.handle_claripy_error(e, "IoControlCode evaluation"):
                    logger.debug(f"Failed to evaluate IoControlCode: {e}")
                # Use the _get_ioctl_code method which handles symbolic values properly
                eval_params["IoControlCode"] = self._get_ioctl_code(state)

        # Add buffer values
        for name, buf in [
            ("SystemBuffer", self.context.system_buffer),
            ("Type3InputBuffer", self.context.type3_input_buffer),
            ("UserBuffer", self.context.user_buffer),
            ("InputBufferLength", self.context.input_buffer_length),
            ("OutputBufferLength", self.context.output_buffer_length),
        ]:
            if buf is not None:
                try:
                    val = state.solver.eval_one(buf)
                    eval_params[name] = hex(val) if isinstance(val, int) else str(val)
                except Exception as e:
                    if not SymbolicExecutionErrorHandler.handle_claripy_error(e, f"{name} evaluation"):
                        logger.debug(f"Failed to evaluate {name}: {e}")
                    # For symbolic values, try to get possible values or use placeholder
                    try:
                        possible_values = state.solver.eval_upto(buf, 10)
                        if possible_values:
                            val = possible_values[0]
                            eval_params[name] = hex(val) if isinstance(val, int) else str(val)
                        else:
                            eval_params[name] = "0x0"  # Default placeholder
                    except Exception:
                        eval_params[name] = "0x0"  # Default placeholder

        # Capture raw state data for enhanced analysis
        raw_data = None
        try:
            raw_data = capture_raw_state(state, self.context)
        except Exception as e:
            # Don't fail vulnerability recording if raw capture fails
            logger.debug(f"Failed to capture raw state data: {e}")

        # Compute severity from title if not provided in others
        severity = (others or {}).get("severity")
        if not severity:
            from ..models.vulnerability import Vulnerability

            severity = Vulnerability.compute_severity_from_title(title)

        # Convert state to string immediately while it's still alive
        state_str = "<SimState @ 0x0>"
        try:
            state_str = str(state)
        except Exception:
            # State might be a weakproxy that's dead or other issue
            try:
                if hasattr(state, "addr"):
                    state_str = f"<SimState @ {hex(state.addr)}>"
            except Exception as e:
                if not SymbolicExecutionErrorHandler.is_non_fatal_error(e):
                    logger.debug(f"Error getting state address: {e}")
                pass

        vulnerability_info = {
            "title": title,
            "description": description,
            "state": state,  # Pass the actual state object
            "state_str": state_str,  # String version captured while state is alive
            "eval": eval_params,
            "parameters": parameters or {},
            "others": others or {},
            "detector": self.name,
            "raw_data": raw_data,  # Include raw state data
            "severity": severity,  # Include severity field
        }

        return vulnerability_info

    def _get_ioctl_code(self, state: SimState) -> str:
        """Get IOCTL code from state if available.

        Args:
            state: Current simulation state

        Returns:
            IOCTL code as hex string or '0x0'
        """
        from ..utils.helpers import safe_hex, get_state_globals

        # First try the context's io_control_code
        if self.context.io_control_code is not None:
            try:
                # Try to evaluate to a concrete value
                concrete_value = state.solver.eval_one(self.context.io_control_code)
                return hex(concrete_value) if isinstance(concrete_value, int) else safe_hex(concrete_value)
            except Exception:
                # If it's symbolic and can't be evaluated, try to get possible values
                try:
                    possible_values = state.solver.eval_upto(self.context.io_control_code, 10)
                    if possible_values:
                        # Use the first possible value
                        return (
                            hex(possible_values[0])
                            if isinstance(possible_values[0], int)
                            else safe_hex(possible_values[0])
                        )
                except Exception:
                    pass  # Fall through to other methods

        # Then check globals
        globals_dict = get_state_globals(state)
        if "IoControlCode" in globals_dict:
            ioctl_code_value = globals_dict["IoControlCode"]
            # If it's a symbolic value, evaluate it first
            if hasattr(ioctl_code_value, "symbolic"):
                try:
                    concrete_value = state.solver.eval(ioctl_code_value)
                    return hex(concrete_value) if isinstance(concrete_value, int) else safe_hex(concrete_value)
                except Exception:
                    # If evaluation fails, try to get possible values
                    try:
                        possible_values = state.solver.eval_upto(ioctl_code_value, 10)
                        if possible_values:
                            return (
                                hex(possible_values[0])
                                if isinstance(possible_values[0], int)
                                else safe_hex(possible_values[0])
                            )
                    except Exception:
                        pass  # Fall through to default
                    return "0x0"
            else:
                return safe_hex(ioctl_code_value)
        elif self.context and self.context.io_control_code is not None:
            try:
                return safe_hex(state.solver.eval(self.context.io_control_code))
            except Exception as e:
                if not SymbolicExecutionErrorHandler.handle_claripy_error(e, "IOCTL code evaluation"):
                    logger.debug(f"Failed to evaluate IOCTL code: {e}")
                pass
        return "0x0"

    def _is_tainted(self, value: Any) -> bool:
        """Check if value is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if value is tainted
        """
        # Check if the value comes from user input
        if value is None:
            return False

        # Check if value contains references to user buffers
        value_str = str(value)
        user_sources = ["SystemBuffer", "Type3InputBuffer", "UserBuffer", "input_buffer", "user_buffer", "InputBuffer"]

        for source in user_sources:
            if source in value_str:
                return True

        # Check if it's a symbolic value derived from IOCTL input
        if SymbolicExecutionErrorHandler.safe_symbolic_check(value):
            # Check if any of its variables are from user input
            if hasattr(value, "variables"):
                for var in value.variables:
                    var_str = str(var)
                    for source in user_sources:
                        if source in var_str:
                            return True
            # Fallback: treat symbolic values as tainted to avoid truthiness misses
            return True

        return False


class DetectorRegistry:
    """Registry for vulnerability detectors."""

    def __init__(self) -> None:
        """Initialize the registry."""
        self._detectors: dict[str, type[VulnerabilityDetector]] = {}

    def register(self, detector_class: type[VulnerabilityDetector]) -> None:
        """Register a detector class.

        Args:
            detector_class: Detector class to register
        """
        # Create a minimal fake context just to get the name
        from ..core.analysis_context import AnalysisConfig

        fake_context = type(
            "FakeContext",
            (),
            {
                "config": AnalysisConfig(),
                "vulnerabilities": [],
                "system_buffer": None,
                "type3_input_buffer": None,
                "user_buffer": None,
                "input_buffer_length": None,
                "output_buffer_length": None,
                "io_control_code": None,
            },
        )()
        instance = detector_class(fake_context)  # Temporary instance to get name
        self._detectors[instance.name] = detector_class

    def get_detector(self, name: str) -> type[VulnerabilityDetector] | None:
        """Get a detector class by name.

        Args:
            name: Detector name

        Returns:
            Detector class or None if not found
        """
        return self._detectors.get(name)

    def get_all_detectors(self) -> list[type[VulnerabilityDetector]]:
        """Get all registered detector classes.

        Returns:
            List of detector classes
        """
        return list(self._detectors.values())

    def create_instances(self, context: AnalysisContext) -> list[VulnerabilityDetector]:
        """Create instances of all registered detectors.

        Args:
            context: Analysis context

        Returns:
            List of detector instances
        """
        return [detector_class(context) for detector_class in self._detectors.values()]


# Global registry instance
detector_registry = DetectorRegistry()
