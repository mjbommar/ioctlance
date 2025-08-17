"""Use-After-Free (UAF) detector for IOCTLance."""

from typing import Any

from angr import SimState

from .base import VulnerabilityDetector, detector_registry


class UseAfterFreeDetector(VulnerabilityDetector):
    """Detects use-after-free vulnerabilities with heap tracking."""

    def __init__(self, context: Any) -> None:
        """Initialize the UAF detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        # Track freed memory regions
        # Format: {address: (size, free_location, allocation_tag)}
        self.freed_regions: dict[int, tuple[int, int, str]] = {}

        # Track allocated memory regions
        # Format: {address: (size, allocation_location, tag)}
        self.allocated_regions: dict[int, tuple[int, int, str]] = {}

    @property
    def name(self) -> str:
        """Get detector name."""
        return "use_after_free"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects use-after-free vulnerabilities with heap tracking"

    def track_allocation(self, state: SimState, address: int, size: int, tag: str = "") -> None:
        """Track a memory allocation.

        Args:
            state: Current simulation state
            address: Allocated address
            size: Size of allocation
            tag: Pool tag or identifier
        """
        state_addr = state.addr if hasattr(state, "addr") else 0
        self.allocated_regions[address] = (size, state_addr, tag)

        # Remove from freed list if it was there (reallocation)
        if address in self.freed_regions:
            del self.freed_regions[address]

    def track_free(self, state: SimState, address: int) -> None:
        """Track a memory free operation.

        Args:
            state: Current simulation state
            address: Address being freed
        """
        state_addr = state.addr if hasattr(state, "addr") else 0

        # Check if this was previously allocated
        if address in self.allocated_regions:
            size, alloc_loc, tag = self.allocated_regions[address]
            self.freed_regions[address] = (size, state_addr, tag)
            del self.allocated_regions[address]
        else:
            # Track it anyway with unknown size
            self.freed_regions[address] = (0, state_addr, "")

    def _check_address_in_freed_region(
        self, address: int, access_size: int = 1
    ) -> tuple[int, tuple[int, int, str]] | None:
        """Check if an address falls within a freed region.

        Args:
            address: Address to check
            access_size: Size of the access

        Returns:
            Tuple of (freed_base_address, freed_info) if found, None otherwise
        """
        for freed_addr, freed_info in self.freed_regions.items():
            freed_size, _, _ = freed_info

            # If we don't know the size, assume a reasonable default
            if freed_size == 0:
                freed_size = 0x1000

            # Check if access overlaps with freed region
            if freed_addr <= address < freed_addr + freed_size:
                return (freed_addr, freed_info)

            # Check if access spans into freed region
            if address < freed_addr < address + access_size:
                return (freed_addr, freed_info)

        return None

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for use-after-free vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event ('memory_read', 'memory_write', 'allocation', 'free')
            **kwargs: Event-specific data

        Returns:
            Vulnerability info if found, None otherwise
        """
        # Handle allocation tracking
        if event_type == "allocation":
            address = kwargs.get("address")
            size = kwargs.get("size", 0)
            tag = kwargs.get("tag", "")

            if address is not None:
                try:
                    # Evaluate address to concrete value
                    if hasattr(address, "__class__") and hasattr(state.solver, "eval"):
                        concrete_addr = state.solver.eval(address)
                    else:
                        concrete_addr = int(address)

                    # Evaluate size to concrete value
                    if hasattr(size, "__class__") and hasattr(state.solver, "eval"):
                        concrete_size = state.solver.eval(size)
                    else:
                        concrete_size = int(size) if size else 0

                    self.track_allocation(state, concrete_addr, concrete_size, str(tag))
                except Exception:
                    pass
            return None

        # Handle free tracking
        if event_type == "free":
            address = kwargs.get("address")

            if address is not None:
                try:
                    # Evaluate address to concrete value
                    if hasattr(address, "__class__") and hasattr(state.solver, "eval"):
                        concrete_addr = state.solver.eval(address)
                    else:
                        concrete_addr = int(address)

                    self.track_free(state, concrete_addr)
                except Exception:
                    pass
            return None

        # Check for use-after-free on memory access
        if event_type in ["memory_read", "memory_write"]:
            address = kwargs.get("address")
            size = kwargs.get("size", 1)

            if address is None:
                return None

            try:
                # Get concrete address
                if hasattr(address, "symbolic") and address.symbolic:
                    # Can't check symbolic addresses effectively
                    return None

                concrete_addr = state.solver.eval(address) if hasattr(address, "__class__") else int(address)
                concrete_size = state.solver.eval(size) if hasattr(size, "__class__") else int(size)

                # Check if this address was freed
                freed_info = self._check_address_in_freed_region(concrete_addr, concrete_size)

                if freed_info:
                    freed_base, (freed_size, free_location, tag) = freed_info

                    access_type = "read" if event_type == "memory_read" else "write"

                    return self.create_vulnerability_info(
                        title=f"use-after-free ({access_type})",
                        description=f"Accessing freed memory at {hex(concrete_addr)}",
                        state=state,
                        others={
                            "access_address": hex(concrete_addr),
                            "access_size": str(concrete_size),
                            "access_type": access_type,
                            "freed_base": hex(freed_base),
                            "freed_size": str(freed_size),
                            "free_location": hex(free_location),
                            "pool_tag": tag if tag else "unknown",
                            "offset_in_freed": str(concrete_addr - freed_base),
                            "exploitation": "Can lead to arbitrary code execution or information disclosure",
                        },
                    )

            except:
                pass

        return None

    def check_exfreepool(self, state: SimState, pool_address: Any, tag: Any = None) -> dict[str, Any] | None:
        """Check for double-free when ExFreePool is called.

        Args:
            state: Current simulation state
            pool_address: Address being freed
            tag: Pool tag (optional)

        Returns:
            Vulnerability info if double-free detected, None otherwise
        """
        if pool_address is None:
            return None

        try:
            concrete_addr = state.solver.eval(pool_address) if hasattr(pool_address, "__class__") else int(pool_address)

            # Check if already freed (double-free)
            if concrete_addr in self.freed_regions:
                _, free_location, old_tag = self.freed_regions[concrete_addr]

                return self.create_vulnerability_info(
                    title="double-free vulnerability",
                    description=f"Freeing already freed memory at {hex(concrete_addr)}",
                    state=state,
                    others={
                        "freed_address": hex(concrete_addr),
                        "first_free_location": hex(free_location),
                        "second_free_location": hex(state.addr if hasattr(state, "addr") else 0),
                        "pool_tag": str(tag) if tag else old_tag,
                        "exploitation": "Can corrupt heap metadata and lead to arbitrary code execution",
                    },
                )

            # Track this free for UAF detection
            self.track_free(state, concrete_addr)

        except:
            pass

        return None


# Register the detector
detector_registry.register(UseAfterFreeDetector)
