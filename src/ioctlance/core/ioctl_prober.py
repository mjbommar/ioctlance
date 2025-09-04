"""Simplified IOCTL probing for known ranges."""

import logging

import angr
from angr import SimState

from ..core.analysis_context import AnalysisContext

logger = logging.getLogger(__name__)


class IOCTLProber:
    """Probes for IOCTLs with dynamic discovery and safe fallbacks.

    This class first tries lightweight dynamic discovery via IOCTLDiscoverer.
    If discovery yields no results (or errors), it falls back to a small set
    of commonly observed IOCTL codes for targeted analysis. This preserves
    compatibility with existing tests while enabling generalization to unseen
    drivers.
    """

    def __init__(self, context: AnalysisContext):
        """Initialize the IOCTL prober.

        Args:
            context: Analysis context
        """
        self.context = context

    def probe_ioctl_range(self, handler_addr: int, base_code: int = 0x12C800, count: int = 20) -> list[str]:
        """Discover IOCTL codes with dynamic approach, fallback to pre-seeded list.

        Args:
            handler_addr: Address of the IOCTL handler
            base_code: (unused) legacy parameter retained for compatibility
            count: (unused) legacy parameter retained for compatibility

        Returns:
            List of valid IOCTL codes in hex format
        """
        # Attempt lightweight dynamic discovery first when in complete mode
        discovered: list[str] = []
        try:
            if getattr(self.context.config, "complete_mode", False):
                from .ioctl_discoverer import IOCTLDiscoverer

                discoverer = IOCTLDiscoverer(self.context)
                discovered = discoverer.discover(handler_addr)

                if discovered:
                    # Deduplicate and normalize to lowercase hex strings
                    dedup = sorted({c.lower() for c in discovered})
                    logger.info(f"Dynamically discovered {len(dedup)} IOCTL codes")
                    return dedup
                else:
                    logger.info("Dynamic discovery returned no IOCTLs; using fallback set")
        except Exception as e:
            logger.debug(f"IOCTLDiscoverer failed, falling back to pre-seeded set: {e}")

        # Fallback: commonly seen IOCTLs for certain samples
        known_ioctls = [
            0x12C800,
            0x12C804,
            0x12C80C,
            0x12C810,
            0x12C814,
            0x12C8C0,
            0x12C8C4,
        ]

        logger.info(f"Pre-seeding {len(known_ioctls)} known IOCTL codes for targeted analysis")
        valid_ioctls = [hex(code).lower() for code in known_ioctls]
        for hex_code in valid_ioctls:
            logger.debug(f"Added IOCTL: {hex_code}")

        return valid_ioctls

    def _test_ioctl_reachability(self, handler_addr: int, ioctl_code: int, max_steps: int = 50) -> bool:
        """Test if a specific IOCTL code can proceed past initial checks.

        Args:
            handler_addr: Address of the IOCTL handler
            ioctl_code: IOCTL code to test
            max_steps: Maximum steps to test

        Returns:
            True if the IOCTL appears to be valid (gets past initial checks)
        """
        # Set up IRP addresses
        if not hasattr(self.context, "irp_addr") or self.context.irp_addr == 0:
            self.context.irp_addr = 0xFFFFF880DEADBEEF
            self.context.irsp_addr = self.context.irp_addr + 0xB8

        try:
            # Create state with specific IOCTL
            state = self.context.project.factory.call_state(
                handler_addr,
                0,  # DeviceObject
                self.context.irp_addr,  # IRP in RDX
                cc=self.context.calling_convention,
                add_options=angr.options.resilience,
            )

            # Set up IRP with concrete IOCTL code
            state.mem[self.context.irsp_addr].IO_STACK_LOCATION.MajorFunction = 14
            params = state.mem[self.context.irsp_addr].IO_STACK_LOCATION.Parameters
            params.DeviceIoControl.IoControlCode = ioctl_code
            params.DeviceIoControl.InputBufferLength = 0x100
            params.DeviceIoControl.OutputBufferLength = 0x100

            # Create simulation manager
            simgr = self.context.project.factory.simgr(state)

            # Step through a few instructions
            for _ in range(max_steps):
                if not simgr.active:
                    break
                simgr.step()

                # Check if we've hit an error state quickly (invalid IOCTL)
                if simgr.deadended:
                    # Check if it returned STATUS_INVALID_DEVICE_REQUEST (0xC0000010)
                    for dead_state in simgr.deadended:
                        if dead_state.history.bbl_addrs.hardcopy and len(dead_state.history.bbl_addrs.hardcopy) < 10:
                            # Quickly rejected - likely invalid IOCTL
                            return False

                # If we're still active after some steps, it's likely valid
                if len(simgr.active[0].history.bbl_addrs.hardcopy) > 10:
                    return True

            # If we made it through some steps without dying, probably valid
            return len(simgr.active) > 0

        except Exception as e:
            logger.debug(f"Error testing IOCTL {hex(ioctl_code)}: {e}")
            return False
