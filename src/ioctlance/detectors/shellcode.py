"""Shellcode execution detector for IOCTLance."""

from typing import Any

from angr import SimState

from ..utils.helpers import is_tainted_buffer
from .base import VulnerabilityDetector, detector_registry


class ShellcodeExecutionDetector(VulnerabilityDetector):
    """Detects arbitrary shellcode execution vulnerabilities."""

    @property
    def name(self) -> str:
        """Get detector name."""
        return "shellcode_execution"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects arbitrary shellcode execution through tainted function pointers"

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for shellcode execution vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event ('call')
            **kwargs: Event-specific data (function_address, etc.)

        Returns:
            Vulnerability info if found, None otherwise
        """
        if event_type != "call":
            return None

        function_address = kwargs.get("function_address")
        if function_address is None:
            return None

        # Check if the function address is tainted (controllable)
        if is_tainted_buffer(function_address):
            # Get return address for logging
            ret_addr = 0
            try:
                ret_addr = state.solver.eval(
                    state.memory.load(
                        state.regs.rsp if hasattr(state.regs, "rsp") else state.regs.sp,
                        state.arch.bytes,
                        endness=state.arch.memory_endness,
                    )
                )
            except:
                pass

            return self.create_vulnerability_info(
                title="arbitrary shellcode execution",
                description="call to tainted function address",
                state=state,
                others={
                    "function_address": str(function_address),
                    "return_address": hex(ret_addr) if ret_addr else "unknown",
                },
            )

        return None


# Register the detector
detector_registry.register(ShellcodeExecutionDetector)
