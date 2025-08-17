"""Base vulnerability detector interface for IOCTLance."""

from abc import ABC, abstractmethod
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..utils.state_capture import capture_raw_state


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
            except:
                eval_params["IoControlCode"] = str(self.context.io_control_code)

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
                except:
                    eval_params[name] = str(buf)

        # Capture raw state data for enhanced analysis
        raw_data = None
        try:
            raw_data = capture_raw_state(state, self.context)
        except Exception as e:
            # Don't fail vulnerability recording if raw capture fails
            pass
        
        return {
            "title": title,
            "description": description,
            "state": str(state),
            "eval": eval_params,
            "parameters": parameters or {},
            "others": others or {},
            "detector": self.name,
            "raw_data": raw_data,  # Include raw state data
        }


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
