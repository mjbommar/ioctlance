"""Null pointer dereference detector for IOCTLance."""

from typing import Any

from angr import SimState

from .base import VulnerabilityDetector, detector_registry


class NullPointerDetector(VulnerabilityDetector):
    """Detects null pointer dereference vulnerabilities."""

    @property
    def name(self) -> str:
        """Get detector name."""
        return "null_pointer"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects null pointer dereferences in input/output buffers"

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for null pointer dereference vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event ('mem_read' or 'mem_write')
            **kwargs: Event-specific data (address, etc.)

        Returns:
            Vulnerability info if found, None otherwise
        """
        if event_type not in ("mem_read", "mem_write"):
            return None

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

            # Check for null pointer based on buffer type
            if target == "SystemBuffer":
                if "*" not in str(address):
                    # SystemBuffer is not a pointer - check for null
                    tmp_state.solver.add(self.context.system_buffer == 0)
                    tmp_state.solver.add(self.context.input_buffer_length == 0)
                    tmp_state.solver.add(self.context.output_buffer_length == 0)

                    if tmp_state.satisfiable():
                        return self.create_vulnerability_info(
                            title="null pointer dereference - input buffer"
                            if event_type == "mem_read"
                            else "null pointer dereference - output buffer",
                            description=f"{event_type.replace('_', ' ')} {'input' if event_type == 'mem_read' else 'output'} buffer",
                            state=state,
                            others={
                                event_type.replace("mem_", "") + " from"
                                if event_type == "mem_read"
                                else event_type.replace("mem_", "") + " to": str(address)
                            },
                        )

            # Check for null pointer in allocated memory
            elif "+" not in str(address):
                tmp_state.solver.add(address == 0)
                if tmp_state.satisfiable():
                    return self.create_vulnerability_info(
                        title="null pointer dereference - allocated memory",
                        description=f"{event_type.replace('_', ' ')} allocated memory",
                        state=state,
                        others={
                            event_type.replace("mem_", "") + " from"
                            if event_type == "mem_read"
                            else event_type.replace("mem_", "") + " to": str(address)
                        },
                    )

        return None


# Register the detector
detector_registry.register(NullPointerDetector)
