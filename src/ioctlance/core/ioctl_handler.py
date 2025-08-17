"""IOCTL handler discovery module for IOCTLance."""

import logging
from pathlib import Path
from typing import Any, cast

import angr
import archinfo
import claripy
from angr import SimState

from ..models import IOCTLHandler

logger = logging.getLogger(__name__)


class IOCTLHandlerFinder:
    """Discovers IOCTL handlers in Windows drivers using symbolic execution."""

    def __init__(
        self,
        driver_path: Path | str,
        timeout: int = 120,
        global_var_size: int = 0,
        complete_mode: bool = False,
    ) -> None:
        """Initialize the IOCTL handler finder.

        Args:
            driver_path: Path to the driver file
            timeout: Maximum time in seconds for analysis
            global_var_size: Size of .data section to symbolize (in bytes)
            complete_mode: Whether to continue analysis until STATUS_SUCCESS
        """
        from ..core.analysis_context import AnalysisConfig, AnalysisContext

        self.driver_path = Path(driver_path) if isinstance(driver_path, str) else driver_path
        self.timeout = timeout
        self.global_var_size = global_var_size
        self.complete_mode = complete_mode

        # Create analysis context
        config = AnalysisConfig(timeout=timeout, global_var_size=global_var_size, complete_mode=complete_mode)
        self.context = AnalysisContext.create_for_driver(self.driver_path, config)

        # Use context's project and attributes
        self.project = self.context.project
        self.cfg = self.context.cfg
        self.calling_convention = self.context.calling_convention

        # Track discovered IOCTL handler
        self.ioctl_handler_addr: int | None = None

    def _setup_initial_state(self) -> SimState:
        """Set up the initial state for symbolic execution.

        Returns:
            Configured initial state starting from DriverEntry
        """
        # Allocate symbolic addresses for driver object and registry path
        driver_object_addr = self._next_base_addr()
        registry_path_addr = self._next_base_addr()

        # Create initial state at DriverEntry with resilience options
        # to handle unsupported VEX operations like Iop_32Uto64
        state = self.project.factory.call_state(
            self.project.entry,
            driver_object_addr,
            registry_path_addr,
            cc=self.calling_convention,
            add_options=angr.options.resilience,
        )

        # Initialize state globals
        globals_dict = cast(dict[str, Any], state.globals)
        globals_dict["open_section_handles"] = ()
        globals_dict["tainted_unicode_strings"] = ()
        globals_dict["ioctl_handler"] = 0

        # Symbolize global variables if requested
        if self.global_var_size:
            self._symbolize_data_section(state)

        # Symbolize driver object and registry path in complete mode
        if self.complete_mode:
            driver_object = claripy.BVS("driver_object", 8 * 0x100)
            state.memory.store(driver_object_addr, driver_object)
            registry_path = claripy.BVS("registry_path", 8 * 0x100)
            state.memory.store(registry_path_addr, registry_path)

        # Set up breakpoints to detect IOCTL handler writes
        self._setup_breakpoints(state, driver_object_addr)

        return state

    def _symbolize_data_section(self, state: SimState) -> None:
        """Symbolize the .data section of the driver.

        Args:
            state: The simulation state to modify
        """
        for segment in self.project.loader.main_object.segments:
            if ".data" in segment.name:
                size = min(segment.memsize, self.global_var_size)
                data = claripy.BVS(".data", 8 * size).reversed
                state.memory.store(segment.vaddr, data, size)
                break

    def _setup_breakpoints(self, state: SimState, driver_object_addr: int) -> None:
        """Set up breakpoints to detect IOCTL handler writes.

        Args:
            state: The simulation state to modify
            driver_object_addr: Address of the driver object
        """
        # IRP_MJ_DEVICE_CONTROL offset in driver object
        if self.project.arch.name == archinfo.ArchAMD64.name:
            ioctl_offset = 0xE0  # 64-bit offset
            startio_offset = 0x60
        else:
            ioctl_offset = 0x70  # 32-bit offset
            startio_offset = 0x30

        # Set breakpoint for IOCTL handler write
        state.inspect.b(
            "mem_write",
            mem_write_address=driver_object_addr + ioctl_offset,
            when=angr.BP_AFTER,
            action=self._on_ioctl_handler_write,
        )

        # Set breakpoint for DriverStartIo write
        state.inspect.b(
            "mem_write",
            mem_write_address=driver_object_addr + startio_offset,
            when=angr.BP_AFTER,
            action=self._on_driver_startio_write,
        )

    def _on_ioctl_handler_write(self, state: SimState) -> None:
        """Callback when IOCTL handler is written to driver object.

        Args:
            state: The current simulation state
        """
        # Import and call the real breakpoint function
        from ..symbolic.breakpoints import b_mem_write_ioctl_handler

        # Create a temporary context for the breakpoint
        # The breakpoint will update the context's ioctl_handler
        b_mem_write_ioctl_handler(state, self.context)

        # Update our local tracking
        if self.context.ioctl_handler:
            self.ioctl_handler_addr = self.context.ioctl_handler
            logger.info(f"Found IOCTL handler at: 0x{self.ioctl_handler_addr:x}")
            self.context.print_info(f"[PHASE 1] Found IOCTL handler at: 0x{self.ioctl_handler_addr:x}")

    def _on_driver_startio_write(self, state: SimState) -> None:
        """Callback when DriverStartIo is written to driver object.

        Args:
            state: The current simulation state
        """
        # Handle DriverStartIo if needed
        pass

    def _next_base_addr(self) -> int:
        """Get the next available base address for allocation.

        Returns:
            Next available address
        """
        # Simple allocation strategy - use high addresses
        if not hasattr(self, "_next_addr"):
            self._next_addr = 0x80000000
        self._next_addr += 0x10000
        return self._next_addr

    def _should_continue(self, state: SimState) -> bool:
        """Check if state should continue exploration.

        Args:
            state: The current simulation state

        Returns:
            True if exploration should continue
        """
        # Check if IOCTL handler was found
        globals_dict = cast(dict[str, Any], state.globals)
        if not globals_dict.get("ioctl_handler"):
            return False

        # In complete mode, continue until STATUS_SUCCESS
        if self.complete_mode:
            retval = self.calling_convention.return_val(angr.types.BASIC_TYPES["long int"]).get_value(state)
            return state.solver.satisfiable(extra_constraints=[retval == 0])

        return True

    def find(self) -> tuple[IOCTLHandler | None, SimState | None]:
        """Find the IOCTL handler in the driver.

        Returns:
            Tuple of (IOCTLHandler, SimState) if found, (None, None) otherwise
        """
        # Set up initial state
        initial_state = self._setup_initial_state()

        # Create simulation manager
        simgr = self.project.factory.simgr(initial_state)
        simgr.use_technique(angr.exploration_techniques.DFS())

        # Add LoopSeer to detect and handle loops if configured
        if self.context.config.bound:
            simgr.use_technique(
                angr.exploration_techniques.LoopSeer(
                    cfg=self.cfg, bound=self.context.config.bound, limit_concrete_loops=True
                )
            )
        else:
            # Use a default bound for handler discovery even if not configured
            simgr.use_technique(
                angr.exploration_techniques.LoopSeer(
                    cfg=self.cfg,
                    bound=1,  # Minimal bound for handler discovery
                    limit_concrete_loops=True,
                )
            )

        # Add LengthLimiter to prevent excessively long paths
        if self.context.config.length:
            simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=self.context.config.length))
        else:
            # Use a default limit for handler discovery
            simgr.use_technique(
                angr.exploration_techniques.LengthLimiter(
                    max_length=500  # Conservative limit for handler discovery
                )
            )

        # Don't use ExplosionDetector in phase 1 - it's only for phase 2
        # Phase 1 only finds the handler address, not IOCTL codes

        # Explore to find IOCTL handler
        import time

        start_time = time.time()
        step_count = 0
        max_steps = 0x100000  # Reduced from 0x200000 to match old code

        while step_count < max_steps:
            # Check timeout
            if self.timeout and (time.time() - start_time) > self.timeout:
                logger.info(f"Phase 1 timeout reached: {self.timeout} seconds")
                self.context.print_info(f"[PHASE 1] Timeout after {step_count} steps")
                break

            try:
                simgr.step(num_inst=1)
                step_count += 1

                # Track unique addresses for metrics
                for state in simgr.active:
                    for addr in state.history.bbl_addrs:
                        self.context.unique_addresses.add(addr)

                # Log progress every 10000 steps
                if step_count % 10000 == 0:
                    self.context.print_debug(
                        f"[PHASE 1] Step {step_count}: active={len(simgr.active)}, "
                        f"deferred={len(simgr.deferred) if hasattr(simgr, 'deferred') else 0}, "
                        f"found={len(simgr.found)}, handler_found={self.ioctl_handler_addr is not None}"
                    )

            except Exception as e:
                import traceback

                # This specific error happens in angr when it tries to create a block at an invalid address
                # It's non-fatal and angr recovers from it
                if "unsupported operand type(s) for -: 'NoneType' and 'bool'" not in str(e):
                    logger.error(f"Error during exploration: {e}")
                    logger.debug(f"Traceback: {traceback.format_exc()}")
                else:
                    logger.debug(f"Known angr issue during exploration (non-fatal): {e}")
                simgr.move(from_stash="active", to_stash="_Drop")

            # Check for deadended states that satisfy our conditions
            simgr.move(from_stash="deadended", to_stash="found", filter_func=self._should_continue)

            # Check if we found the handler or exhausted paths
            if simgr.found or (not simgr.active and not simgr.deferred):
                break

        # Log completion
        elapsed = time.time() - start_time
        self.context.print_info(
            f"[PHASE 1] Complete after {step_count} steps, {elapsed:.1f}s. "
            f"Found={len(simgr.found)}, Handler={self.ioctl_handler_addr is not None}"
        )

        # Extract result if found
        if simgr.found and self.ioctl_handler_addr:
            handler = IOCTLHandler(
                address=f"0x{self.ioctl_handler_addr:x}",
                ioctl_codes=[],  # IOCTL codes are discovered in phase 2, not phase 1
            )
            self.context.print_info(f"[PHASE 1] SUCCESS: Returning handler at {handler.address}")
            # Return the first found state that has the handler
            return handler, simgr.found[0]

        self.context.print_error("[PHASE 1] FAILED: No IOCTL handler found")
        return None, None

    def discover_ioctl_codes(self, handler: IOCTLHandler, state: SimState | None = None) -> list[str]:
        """Discover IOCTL codes supported by the handler.

        Args:
            handler: The IOCTL handler to analyze
            state: Optional base state to use

        Returns:
            List of discovered IOCTL codes in hex format
        """
        # This would require further symbolic execution of the handler
        # For now, return empty list - to be implemented
        return []


def find_ioctl_handler(
    driver_path: Path | str,
    timeout: int = 120,
    global_var_size: int = 0,
    complete_mode: bool = False,
) -> tuple[IOCTLHandler | None, SimState | None]:
    """Find the IOCTL handler in a Windows driver.

    Args:
        driver_path: Path to the driver file
        timeout: Maximum time in seconds for analysis
        global_var_size: Size of .data section to symbolize (in bytes)
        complete_mode: Whether to continue analysis until STATUS_SUCCESS

    Returns:
        Tuple of (IOCTLHandler, SimState) if found, (None, None) otherwise
    """
    finder = IOCTLHandlerFinder(
        driver_path, timeout=timeout, global_var_size=global_var_size, complete_mode=complete_mode
    )
    return finder.find()
