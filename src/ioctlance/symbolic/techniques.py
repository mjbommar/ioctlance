"""Custom angr exploration techniques for IOCTLance."""

import time
from typing import Any, cast

import angr
from angr import SimState
from angr.sim_manager import SimulationManager

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import get_state_globals, safe_hex


class ExplosionDetector(angr.exploration_techniques.ExplorationTechnique):
    """Detects and handles state explosion during symbolic execution.

    This technique monitors the number of active states and implements
    various strategies to prevent state explosion:
    - Detects recursion in the call stack
    - Implements per-IOCTL timeouts
    - Drops states when thresholds are exceeded
    """

    def __init__(
        self,
        context: AnalysisContext,
        stashes: tuple[str, ...] = ("active", "deferred", "errored"),
        threshold: int = 10000,
    ) -> None:
        """Initialize the explosion detector.

        Args:
            context: Analysis context for accessing configuration and state
            stashes: Stashes to monitor for state count
            threshold: Maximum number of states before declaring explosion
        """
        super().__init__()
        self.context = context
        self._stashes = stashes
        self._threshold = threshold
        self.total_time = time.time()
        self.ioctl_history: list[int] = []
        self.ioctl_timer: dict[int, float] = {}
        self.state_exploded_bool = False

    def detect_recursion(self, state: SimState) -> bool:
        """Check if recursion is detected in the call stack.

        Args:
            state: State to check for recursion

        Returns:
            True if recursion is detected, False otherwise
        """
        if not self.context.config.recursion_kill:
            return False

        callstack_func_addrs = [c.func_addr for c in state.callstack]
        if len(callstack_func_addrs) != len(set(callstack_func_addrs)):
            self.context.print_debug(f"Recursion detected in state {state}")
            return True
        return False

    def detect_timeout(self, state: SimState, ioctl: int) -> bool:
        """Check if a specific IOCTL has timed out.

        Args:
            state: State to check
            ioctl: IOCTL code to check for timeout

        Returns:
            True if the IOCTL has timed out, False otherwise
        """
        if "IoControlCode" in state.globals:
            return state.globals["IoControlCode"] == ioctl
        return False

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs: Any) -> SimulationManager:
        """Step the simulation manager with explosion detection.

        Args:
            simgr: Simulation manager to step
            stash: Stash to step from
            **kwargs: Additional arguments for stepping

        Returns:
            Updated simulation manager
        """
        # Step the simulation
        simgr = simgr.step(stash=stash, **kwargs)

        # Process active states
        for state in simgr.active:
            # Try to evaluate and track IOCTL codes
            globals_dict = get_state_globals(state)
            if "IoControlCode" not in globals_dict and self.context.io_control_code is not None:
                try:
                    # Evaluate the IoControlCode and store it
                    ioctl = state.solver.eval_one(self.context.io_control_code)
                    globals_dict["IoControlCode"] = ioctl

                    if ioctl not in self.ioctl_history:
                        self.context.print_info(f"Starting test of IoControlCode {hex(ioctl)}")
                        self.context.ioctl_codes.append(hex(ioctl))
                        self.ioctl_history.append(ioctl)
                        self.ioctl_timer[ioctl] = time.time()

                except angr.errors.SimValueError:
                    # IoControlCode is still symbolic
                    pass

            elif "IoControlCode" in globals_dict:
                # Check for per-IOCTL timeout
                ioctl = globals_dict["IoControlCode"]
                if (
                    self.context.config.ioctl_timeout > 0
                    and ioctl in self.ioctl_timer
                    and time.time() - self.ioctl_timer[ioctl] > self.context.config.ioctl_timeout
                ):
                    # Drop states for this IOCTL
                    for st in self._stashes:
                        simgr.move(
                            from_stash=st,
                            to_stash="_Drop",
                            filter_func=lambda s, ioctl_code=ioctl: self.detect_timeout(s, ioctl_code),
                        )
                    self.context.print_info(
                        f"IoControlCode {hex(ioctl)} timeout: {self.context.config.ioctl_timeout} seconds"
                    )

        # Drop states with recursion
        if self.context.config.recursion_kill:
            for stash in self._stashes:
                simgr.move(from_stash=stash, to_stash="_Drop", filter_func=self.detect_recursion)

        # Check unconstrained states for vulnerabilities before dropping
        if len(simgr.unconstrained) > 0:
            # Unconstrained states often indicate buffer overflows
            self.context.print_info(f"[POTENTIAL VULN] Found {len(simgr.unconstrained)} unconstrained states")

            for state in simgr.unconstrained:
                try:
                    # Check if PC is symbolic (controllable)
                    if state.regs.pc.symbolic:
                        # Get IOCTL code if available
                        ioctl_code = "0x0"
                        if hasattr(state, "globals") and "IoControlCode" in state.globals:
                            ioctl_code = hex(state.globals["IoControlCode"])
                        elif self.context.io_control_code:
                            try:
                                ioctl_code = hex(state.solver.eval(self.context.io_control_code))
                            except:
                                pass

                        vuln_info = {
                            "title": "Buffer Overflow - Controllable PC",
                            "description": "Unconstrained state with symbolic program counter (likely buffer overflow)",
                            "state": str(state),
                            "eval": {"IoControlCode": ioctl_code, "pc_symbolic": "True"},
                            "others": {"severity": "CRITICAL", "type": "unconstrained_state"},
                        }
                        self.context.add_vulnerability(vuln_info)
                        self.context.print_info(
                            f"[VULN CONFIRMED] Buffer overflow in IOCTL {ioctl_code} - PC is symbolic!"
                        )
                except Exception as e:
                    self.context.print_debug(f"Error checking unconstrained state: {e}")

            # Now drop the unconstrained states
            simgr.move(from_stash="unconstrained", to_stash="_Drop", filter_func=lambda _: True)

        # Count total states
        total = sum(len(getattr(simgr, st)) for st in self._stashes if hasattr(simgr, st))

        # Check for state explosion or total timeout
        time_elapsed = time.time() - self.total_time
        total_timeout = self.context.config.timeout

        if total >= self._threshold or (total_timeout > 0 and time_elapsed > total_timeout):
            if total >= self._threshold:
                self.context.print_info(f"State explosion detected: {total} states exceed threshold {self._threshold}")
                self.state_exploded_bool = True
            else:
                self.context.print_info(f"Total timeout reached: {total_timeout} seconds")

            # Drop all states
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash="_Drop", filter_func=lambda _: True)

        return simgr
