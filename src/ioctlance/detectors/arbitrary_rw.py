"""Arbitrary read/write detector for IOCTLance."""

from typing import Any

from angr import SimState

from .base import VulnerabilityDetector, detector_registry


class ArbitraryRWDetector(VulnerabilityDetector):
    """Detects arbitrary read/write vulnerabilities."""

    @property
    def name(self) -> str:
        """Get detector name."""
        return "arbitrary_rw"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects arbitrary read/write through controllable pointers"

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for arbitrary read/write vulnerabilities.

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

            # Check for controllable address based on buffer type
            if target == "SystemBuffer" and "*" in str(address):
                # SystemBuffer is a pointer - check if controllable
                tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0x87)

                if tmp_state.satisfiable():
                    return self.create_vulnerability_info(
                        title="read/write controllable address" if event_type == "mem_read" else "arbitrary write",
                        description="read" if event_type == "mem_read" else "write through controllable pointer",
                        state=state,
                        others={"read from" if event_type == "mem_read" else "write to": str(address)},
                    )

            elif target in ("Type3InputBuffer", "UserBuffer"):
                # Check if Type3InputBuffer or UserBuffer is controllable
                if target == "Type3InputBuffer":
                    tmp_state.solver.add(self.context.type3_input_buffer == 0x87)
                else:
                    tmp_state.solver.add(self.context.user_buffer == 0x87)

                if tmp_state.satisfiable():
                    return self.create_vulnerability_info(
                        title=f"read/write controllable address - {target}"
                        if event_type == "mem_read"
                        else f"arbitrary write - {target}",
                        description="read" if event_type == "mem_read" else "write through controllable pointer",
                        state=state,
                        others={"read from" if event_type == "mem_read" else "write to": str(address)},
                    )

        return None


# Register the detector
detector_registry.register(ArbitraryRWDetector)
