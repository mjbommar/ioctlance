"""Lightweight IOCTL discovery phase for efficient code enumeration."""

import logging
import time

import angr
from angr import SimState

from ..core.analysis_context import AnalysisContext

logger = logging.getLogger(__name__)


class IOCTLDiscoverer:
    """Discovers IOCTL codes using minimal memory before vulnerability hunting.

    This class implements a lightweight exploration phase that:
    - Uses symbolic IoControlCode to explore all branches
    - Tracks IOCTL comparisons without vulnerability detection
    - Uses BFS for broader coverage
    - Exits quickly once IOCTLs are found
    """

    def __init__(self, context: AnalysisContext):
        """Initialize the IOCTL discoverer.

        Args:
            context: Analysis context with project and configuration
        """
        self.context = context
        self.discovered_ioctls: set[str] = set()
        self.comparison_count = 0

    def discover(self, handler_addr: int, handler_state: SimState | None = None) -> list[str]:
        """Discover all reachable IOCTL codes with minimal memory usage.

        Args:
            handler_addr: Address of the IOCTL handler
            handler_state: Optional initial state from handler discovery

        Returns:
            List of discovered IOCTL codes in hex format
        """
        start_time = time.time()
        logger.info("Starting lightweight IOCTL discovery phase...")

        # Set up IRP addresses if not already set
        if not hasattr(self.context, "irp_addr") or self.context.irp_addr == 0:
            self.context.irp_addr = 0xFFFFF880DEADBEEF
            self.context.irsp_addr = self.context.irp_addr + 0xB8

        # Always create fresh state for discovery - handler_state might have constraints
        # Create call state at handler address with IRP in RDX
        import claripy

        state = self.context.project.factory.call_state(
            handler_addr,
            0,  # DeviceObject (don't care)
            self.context.irp_addr,  # IRP in RDX
            cc=self.context.calling_convention,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            },
        )

        # Store context in state globals so hooks can access it
        if not hasattr(state, "globals"):
            state.globals = {}
        state.globals["analysis_context"] = self.context

        # Create symbolic IoControlCode
        io_control_code = claripy.BVS("IoControlCode", 32)
        self.context.io_control_code = io_control_code

        # Set up minimal IRP structure
        irp = claripy.BVS("irp_buf", 8 * 0x100)
        state.memory.store(self.context.irp_addr, irp)

        # Set up IO_STACK_LOCATION with IoControlCode
        state.mem[self.context.irsp_addr].IO_STACK_LOCATION.MajorFunction = 14  # IRP_MJ_DEVICE_CONTROL
        params = state.mem[self.context.irsp_addr].IO_STACK_LOCATION.Parameters
        params.DeviceIoControl.IoControlCode.val = io_control_code

        # Also set some reasonable values for buffer lengths
        params.DeviceIoControl.InputBufferLength.val = 0x100
        params.DeviceIoControl.OutputBufferLength.val = 0x100

        # Set up lightweight comparison detection
        state.inspect.b("symbolic_variable", when=angr.BP_AFTER, action=self._on_symbolic_variable)
        state.inspect.b("constraints", when=angr.BP_AFTER, action=self._on_constraints_added)

        # Store IoControlCode reference in state globals
        if not hasattr(state, "globals"):
            state.globals = {}
        state.globals["IoControlCode_sym"] = io_control_code
        state.globals["discoverer"] = self

        # Create simulation manager with BFS for broad exploration
        simgr = self.context.project.factory.simgr(state)

        # Store simulation manager in context for techniques to use
        self.context.simulation_manager = simgr

        # Remove verbose techniques
        simgr._techniques = [t for t in simgr._techniques if not isinstance(t, angr.exploration_techniques.Suggestions)]

        # Don't use DFS - default exploration is more breadth-first-like
        # This gives us wider coverage for IOCTL discovery

        # Add the ExplosionDetector which also tracks IOCTLs
        from ..symbolic.techniques import ExplosionDetector

        explosion_detector = ExplosionDetector(self.context)
        simgr.use_technique(explosion_detector)

        # Log initial state
        logger.debug(f"Starting discovery with {len(simgr.active)} active states at addr {hex(handler_addr)}")
        if simgr.active:
            logger.debug(f"Initial state IP: {hex(simgr.active[0].addr)}")

        # Exploration limits
        max_steps = 500  # Aggressive limit for discovery phase
        steps_without_discovery = 0
        max_steps_without_discovery = 50
        step_count = 0

        # Check if we have any active states
        if not simgr.active:
            logger.warning("No active states to explore in discovery phase")
            return []

        while simgr.active and step_count < max_steps:
            old_count = len(self.discovered_ioctls)

            # Log current state count
            if step_count % 10 == 0 or step_count == 0:
                logger.debug(f"Discovery step {step_count}: {len(simgr.active)} active states")

            try:
                # Single step with timeout
                simgr.step()
                step_count += 1

                # Log state distribution after step
                logger.debug(
                    f"After step {step_count}: active={len(simgr.active)}, errored={len(simgr.errored)}, deadended={len(simgr.deadended)}"
                )

                # Check for errors
                if simgr.errored:
                    for err_state in simgr.errored:
                        logger.debug(f"State errored: {err_state.error}")

                # Check each active state for IOCTL values
                for active_state in simgr.active[:]:  # Slice to avoid modification during iteration
                    self._check_state_for_ioctls(active_state, io_control_code)

                    # Prune states that go too deep
                    if len(active_state.history.bbl_addrs) > 100:
                        simgr.move("active", "pruned", lambda s, state_to_prune=active_state: s is state_to_prune)

                # Check if we found new IOCTLs
                if len(self.discovered_ioctls) > old_count:
                    steps_without_discovery = 0
                    logger.info(f"Step {step_count}: Found {len(self.discovered_ioctls)} IOCTLs so far")
                else:
                    steps_without_discovery += 1

                # Stop if we haven't found anything new recently
                if steps_without_discovery >= max_steps_without_discovery:
                    logger.info(f"No new IOCTLs found in {steps_without_discovery} steps, stopping discovery")
                    break

                # Log progress
                if step_count % 50 == 0:
                    logger.debug(
                        f"Discovery step {step_count}: {len(simgr.active)} active, {len(self.discovered_ioctls)} IOCTLs found"
                    )

            except Exception as e:
                logger.debug(f"Error during discovery step {step_count}: {e}")
                # Try to continue with remaining states
                if not simgr.active:
                    logger.debug("No more active states after error, stopping discovery")
                    break
                continue

        # Final attempt to extract IOCTLs from remaining states
        for state in simgr.active:
            self._check_state_for_ioctls(state, io_control_code)

        elapsed = time.time() - start_time
        logger.info(
            f"IOCTL discovery complete: Found {len(self.discovered_ioctls)} IOCTLs "
            f"in {step_count} steps ({elapsed:.1f}s)"
        )

        # Store discovered IOCTLs in context
        discovered_list = list(self.discovered_ioctls)
        if discovered_list:
            self.context.ioctl_codes = discovered_list
            logger.info(f"Discovered IOCTLs: {', '.join(sorted(discovered_list))}")

        return discovered_list

    def _check_state_for_ioctls(self, state: SimState, io_control_code) -> None:
        """Check a state for possible IOCTL values.

        Args:
            state: The state to check
            io_control_code: The symbolic IoControlCode variable
        """
        if io_control_code is None:
            return

        try:
            # Check if IoControlCode has been constrained to specific values
            if state.solver.symbolic(io_control_code):
                # Get possible concrete values (up to 20)
                possible_values = state.solver.eval_upto(io_control_code, 20)

                for val in possible_values:
                    # Filter to reasonable IOCTL range
                    if 0x10000 <= val <= 0xFFFFFF:
                        hex_val = hex(val)
                        if hex_val not in self.discovered_ioctls:
                            self.discovered_ioctls.add(hex_val)
                            logger.info(f"Discovered IOCTL: {hex_val}")
            else:
                # IoControlCode is concrete
                val = state.solver.eval(io_control_code)
                if 0x10000 <= val <= 0xFFFFFF:
                    hex_val = hex(val)
                    if hex_val not in self.discovered_ioctls:
                        self.discovered_ioctls.add(hex_val)
                        logger.info(f"Discovered IOCTL: {hex_val}")

        except Exception as e:
            logger.debug(f"Could not evaluate IoControlCode: {e}")

    def _on_symbolic_variable(self, state: SimState) -> None:
        """Breakpoint callback for symbolic variable creation.

        Args:
            state: Current simulation state
        """
        # Track when IoControlCode comparisons happen
        if state.inspect.symbolic_name == "IoControlCode":
            self.comparison_count += 1

    def _on_constraints_added(self, state: SimState) -> None:
        """Breakpoint callback for constraint additions.

        Args:
            state: Current simulation state
        """
        if not hasattr(state.inspect, "added_constraints") or state.inspect.added_constraints is None:
            return

        # Check if any constraints involve IoControlCode
        io_control_code = state.globals.get("IoControlCode_sym")
        if io_control_code is None:
            return

        for constraint in state.inspect.added_constraints:
            # Check if this constraint involves our IoControlCode
            if io_control_code in constraint.variables:
                # This is a constraint on IoControlCode, check for concrete values
                self._check_state_for_ioctls(state, io_control_code)
