"""Stack buffer overflow detector with canary and guard page detection."""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class StackBufferOverflowDetector(VulnerabilityDetector):
    """Detects stack buffer overflow including canary bypass and guard page violations."""

    name = "stack_buffer_overflow"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects stack buffer overflow with canary and guard page bypass detection"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the stack buffer overflow detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        self.detected_overflows = set()
        self.stack_canaries = {}  # Track stack canaries per frame
        self.guard_pages = set()  # Track guard page addresses

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect stack buffer overflow vulnerabilities.

        This detector hooks memory writes and checks if:
        1. The write target is on the stack
        2. The write crosses stack frame boundaries
        3. The write corrupts a stack canary
        4. The write accesses a guard page

        Args:
            state: Current simulation state

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # This is called from breakpoints, not directly
        # The actual detection happens in check_state
        return None

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for stack buffer overflow vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event (mem_read, mem_write, call, expr)
            **kwargs: Additional event-specific arguments

        Returns:
            Vulnerability information if detected
        """
        # We only care about memory writes for stack overflow
        if event_type != "mem_write":
            return None

        address = kwargs.get("address")
        size = kwargs.get("size", 0)
        value = kwargs.get("value")

        if address is None:
            return None

        # Debug: Log all memory writes to understand what's happening
        if self.context.config.debug:
            logger.info(f"Stack detector: mem_write at {address}, size={size}")

        # Check if the write is to stack memory
        stack_pointer = state.regs.rsp if hasattr(state.regs, "rsp") else state.regs.sp

        try:
            # Get concrete values for comparison
            if hasattr(address, "concrete"):
                addr_concrete = state.solver.eval_one(address)
            else:
                addr_concrete = address

            if hasattr(stack_pointer, "concrete"):
                sp_concrete = state.solver.eval_one(stack_pointer)
            else:
                sp_concrete = stack_pointer

            # Check if address is in stack range (typically stack grows down)
            # Stack usually spans from sp to sp + some reasonable range (e.g., 64KB)
            if not self._is_stack_address(addr_concrete, sp_concrete):
                return None

            # Check for various overflow conditions
            vuln = self._check_overflow_conditions(state, addr_concrete, sp_concrete, size, value)

            # Debug: Log what we're checking
            if self.context.config.debug and size:
                logger.info(f"Checking overflow: size={size} to stack addr")

            if vuln:
                # Create unique key for deduplication
                vuln_key = (state.addr, addr_concrete, vuln["title"])
                if vuln_key in self.detected_overflows:
                    return None
                self.detected_overflows.add(vuln_key)

                return vuln

        except Exception as e:
            logger.debug(f"Error checking stack overflow: {e}")

        return None

    def _is_stack_address(self, address: int, stack_pointer: int) -> bool:
        """Check if an address is within the stack range.

        Args:
            address: Memory address to check
            stack_pointer: Current stack pointer value

        Returns:
            True if address is likely on the stack
        """
        # Stack typically grows down, so valid range is [sp - reasonable_size, sp + frame_size]
        # Using 1MB as a reasonable maximum stack size
        max_stack_size = 1024 * 1024  # 1MB
        max_frame_size = 8192  # 8KB for current frame

        # Debug logging
        if self.context.config.debug:
            logger.info(f"Stack check: addr={hex(address)}, sp={hex(stack_pointer)}")

        # Check if address is within reasonable stack bounds
        return (stack_pointer - max_stack_size) <= address <= (stack_pointer + max_frame_size)

    def _check_overflow_conditions(
        self, state: SimState, address: int, stack_pointer: int, size: int, value: Any
    ) -> dict[str, Any] | None:
        """Check various stack overflow conditions.

        Args:
            state: Current simulation state
            address: Write target address
            stack_pointer: Current stack pointer
            size: Size of the write
            value: Value being written

        Returns:
            Vulnerability info if overflow detected
        """
        # Check 0: Simple large write to stack (potential overflow)
        # If we're writing a large, potentially symbolic amount to the stack, flag it
        if size and (
            (isinstance(size, int) and size > 256)  # Large concrete write
            or (hasattr(size, "symbolic") and size.symbolic)  # Symbolic size
            or (hasattr(value, "symbolic") and value.symbolic and size > 32)  # Tainted data > typical buffer
        ):
            # This is a potential overflow - writing user-controlled or large data to stack
            return self.create_vulnerability_info(
                title="stack buffer overflow - large/tainted write",
                description=f"Large or tainted write to stack (size={size})",
                state=state,
                parameters={
                    "write_address": hex(address),
                    "write_size": str(size),
                    "tainted": str(hasattr(value, "symbolic") and value.symbolic),
                },
                others={"severity": "HIGH", "exploitation": "Potential stack corruption"},
            )

        # Check 1: Return address overwrite
        # Return address is typically at [rbp + 8] on x64 or [ebp + 4] on x86
        frame_pointer = state.regs.rbp if hasattr(state.regs, "rbp") else state.regs.ebp
        if hasattr(frame_pointer, "concrete"):
            fp_concrete = state.solver.eval_one(frame_pointer)
        else:
            fp_concrete = frame_pointer

        ret_addr_offset = 8 if state.arch.bits == 64 else 4
        ret_addr_location = fp_concrete + ret_addr_offset

        # Check if write overlaps with return address
        if address <= ret_addr_location < (address + size):
            return self.create_vulnerability_info(
                title="stack buffer overflow - return address overwrite",
                description="Write operation can overwrite function return address",
                state=state,
                parameters={
                    "write_address": hex(address),
                    "write_size": size,
                    "return_address_location": hex(ret_addr_location),
                },
                others={"severity": "CRITICAL", "exploitation": "ROP/Code execution possible"},
            )

        # Check 2: Stack canary corruption
        if self._check_canary_corruption(state, address, size):
            return self.create_vulnerability_info(
                title="stack buffer overflow - canary bypass",
                description="Write operation can corrupt stack canary",
                state=state,
                parameters={"write_address": hex(address), "write_size": size},
                others={"severity": "HIGH", "exploitation": "Stack canary bypass detected"},
            )

        # Check 3: Guard page access
        if self._check_guard_page_access(address):
            return self.create_vulnerability_info(
                title="stack buffer overflow - guard page violation",
                description="Write operation accesses guard page",
                state=state,
                parameters={"write_address": hex(address), "write_size": size},
                others={"severity": "HIGH", "exploitation": "Guard page protection bypassed"},
            )

        # Check 4: Large stack write with tainted data
        if size > 256 and self._is_tainted_write(value):
            return self.create_vulnerability_info(
                title="stack buffer overflow - large tainted write",
                description=f"Large tainted write to stack ({size} bytes)",
                state=state,
                parameters={
                    "write_address": hex(address),
                    "write_size": size,
                    "value": str(value)[:100],  # Truncate for readability
                },
                others={"severity": "MEDIUM", "exploitation": "Potential stack corruption"},
            )

        return None

    def _check_canary_corruption(self, state: SimState, address: int, size: int) -> bool:
        """Check if a write would corrupt a stack canary.

        Args:
            state: Current simulation state
            address: Write address
            size: Write size

        Returns:
            True if canary would be corrupted
        """
        # Stack canaries are typically placed between local variables and return address
        # Check if we have any known canary locations for this frame
        frame_id = id(state.callstack)

        if frame_id in self.stack_canaries:
            canary_addr = self.stack_canaries[frame_id]
            # Check if write overlaps with canary
            if address <= canary_addr < (address + size):
                return True

        # Heuristic: Check for common canary patterns
        # Canaries often end in 00 (null terminator) on x64
        # or have specific patterns like 0xDEADBEEF
        return False

    def _check_guard_page_access(self, address: int) -> bool:
        """Check if an address is in a guard page.

        Args:
            address: Address to check

        Returns:
            True if address is in a guard page
        """
        # Guard pages are typically aligned to page boundaries (4KB)
        page_size = 4096
        page_addr = address & ~(page_size - 1)

        # Check if this page is marked as a guard page
        return page_addr in self.guard_pages

    def _is_tainted_write(self, value: Any) -> bool:
        """Check if the value being written is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if value is tainted
        """
        if hasattr(value, "symbolic"):
            return value.symbolic
        elif hasattr(value, "variables"):
            return len(value.variables) > 0
        return False

    def setup_canary(self, state: SimState, address: int) -> None:
        """Set up a stack canary at the given address.

        Args:
            state: Current simulation state
            address: Address where canary is placed
        """
        frame_id = id(state.callstack)
        self.stack_canaries[frame_id] = address
        logger.debug(f"Stack canary set at {hex(address)} for frame {frame_id}")

    def add_guard_page(self, address: int) -> None:
        """Mark a page as a guard page.

        Args:
            address: Page address
        """
        page_size = 4096
        page_addr = address & ~(page_size - 1)
        self.guard_pages.add(page_addr)
        logger.debug(f"Guard page added at {hex(page_addr)}")


# Register the detector
detector_registry.register(StackBufferOverflowDetector)
