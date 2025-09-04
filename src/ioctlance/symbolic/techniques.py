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
        try:
            if "IoControlCode" in state.globals:
                return state.globals["IoControlCode"] == ioctl
            # Fallback: if the context's IoControlCode is concretized, compare it
            icc = self.context.io_control_code
            if icc is not None and not state.solver.symbolic(icc):
                try:
                    return state.solver.eval(icc) == ioctl
                except Exception:
                    return False
        except Exception:
            return False
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
                    # IoControlCode is still symbolic - track values if needed
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
                            "state": state,  # Pass the actual state object
                            "state_str": str(state),  # Keep string version for backward compatibility
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


class BeamExplorer(angr.exploration_techniques.ExplorationTechnique):
    """Priority-driven beam search with optional triage window.

    Keeps at most `beam_width` active states after each step based on a
    heuristic score that approximates "risk" (likelihood of reaching a sink)
    while promoting IOCTL diversity.
    """

    def __init__(
        self, context: AnalysisContext, beam_width: int, triage_steps: int = 0, triage_beam_width: int | None = None
    ) -> None:
        super().__init__()
        self.context = context
        self.beam_width = max(1, int(beam_width))
        self.triage_steps = max(0, int(triage_steps or 0))
        self.triage_beam_width = max(1, int(triage_beam_width if triage_beam_width is not None else self.beam_width))
        self._steps = 0

    # -------------- scoring helpers --------------
    def _ioctl_key(self, state: SimState) -> object | None:
        try:
            # Cache-per-state to avoid repeated solver work
            key_cached = getattr(state, "globals", {}).get("__ioctl_key") if hasattr(state, "globals") else None
            if key_cached is not None:
                return key_cached

            icc = self.context.io_control_code
            key: object | None
            if icc is None:
                key = None
            elif state.solver.symbolic(icc):
                # Cheap sample
                vals = []
                try:
                    vals = state.solver.eval_upto(icc, 3)
                except Exception:
                    vals = []
                if len(vals) == 1:
                    key = vals[0]
                elif 1 < len(vals) <= 3:
                    key = tuple(sorted(vals))
                else:
                    key = None
            else:
                key = state.solver.eval(icc)

            if hasattr(state, "globals"):
                state.globals["__ioctl_key"] = key
            return key
        except Exception:
            return None

    def _group_counts(self, states: list[SimState]) -> dict[object, int]:
        counts: dict[object, int] = {}
        for s in states:
            k = self._ioctl_key(s)
            counts[k] = counts.get(k, 0) + 1
        return counts

    def _recent_call_risk(self, state: SimState) -> float:
        try:
            name = getattr(state, "globals", {}).get("__recent_call_name")
            if not name:
                return 0.0
            n = str(name)
            # Boost risky families; higher for memory/process/system primitives
            if n.startswith(("Zw", "Nt")):
                base = 8.0
            elif n.startswith(("Mm", "Ps")):
                base = 12.0
            elif n.startswith(("Dbg", "Kd")):
                base = 5.0
            else:
                base = 3.0

            # Extra bump for specific sinks
            specials = {
                "ZwMapViewOfSection": 15.0,
                "MmCopyMemory": 12.0,
                "MmMapIoSpace": 12.0,
                "ZwTerminateProcess": 15.0,
                "ZwCreateFile": 10.0,
                "ZwOpenFile": 8.0,
                "DbgPrint": 6.0,
                "KdPrint": 6.0,
                "extern_call": 6.0,
                "unknown_call": 2.0,
            }
            return specials.get(n, base)
        except Exception:
            return 0.0

    def _validated_count(self, state: SimState) -> int:
        try:
            g = getattr(state, "globals", {})
            return sum(
                len(g.get(k, ())) for k in ("tainted_ProbeForRead", "tainted_ProbeForWrite", "tainted_MmIsAddressValid")
            )
        except Exception:
            return 0

    def _depth_score(self, state: SimState) -> float:
        try:
            # Reward some progress, but saturate to avoid preferring only deep states
            d = len(state.history.bbl_addrs)
            return min(25.0, d / 200.0)
        except Exception:
            return 0.0

    def _ioctl_specificity(self, state: SimState) -> float:
        try:
            icc = self.context.io_control_code
            if icc is None:
                return 0.0
            if state.solver.symbolic(icc):
                try:
                    vals = state.solver.eval_upto(icc, 3)
                    if len(vals) == 1:
                        return 15.0
                    if 1 < len(vals) <= 3:
                        return 8.0
                    return 0.0
                except Exception:
                    return 0.0
            else:
                return 15.0
        except Exception:
            return 0.0

    def _score(self, state: SimState, group_counts: dict[object, int]) -> float:
        s = 0.0
        # Heuristics
        s += self._recent_call_risk(state)
        s += min(30.0, float(self._validated_count(state) * 2))
        s += self._depth_score(state)
        s += self._ioctl_specificity(state)

        # Diversity penalty: overrepresented IOCTL group gets a small penalty
        key = self._ioctl_key(state)
        count = group_counts.get(key, 1)
        s -= 0.5 * max(0, count - 1)
        return s

    # -------------- angr ExplorationTechnique API --------------
    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs: Any) -> SimulationManager:
        # Delegate actual stepping down the technique stack
        simgr = simgr.step(stash=stash, **kwargs)
        self._steps += 1

        # Determine current beam width (triage window uses a tighter beam)
        current_width = self.beam_width
        if self.triage_steps and self._steps <= self.triage_steps:
            current_width = min(self.triage_beam_width, self.beam_width)

        # Nothing to prune
        if len(simgr.active) <= current_width:
            return simgr

        # Score and keep top-k
        states = list(simgr.active)
        group_counts = self._group_counts(states)
        try:
            scored = [(self._score(s, group_counts), i, s) for i, s in enumerate(states)]
        except Exception:
            # Fallback: shallow heuristic by path length only
            scored = [(len(getattr(s.history, "bbl_addrs", [])), i, s) for i, s in enumerate(states)]

        scored.sort(key=lambda x: x[0], reverse=True)
        keep = {s for _, _, s in scored[:current_width]}

        # Move the rest to _Drop to enforce the beam
        def drop_filter(state: SimState) -> bool:
            return state not in keep

        simgr.move(from_stash="active", to_stash="_Drop", filter_func=drop_filter)

        # Keep deferred under a soft cap to avoid backlog memory growth
        try:
            if hasattr(simgr, "deferred") and isinstance(simgr.deferred, list):
                max_deferred = max(self.beam_width * 2, current_width * 2)
                if len(simgr.deferred) > max_deferred:
                    # Drop oldest (front) portion
                    simgr.deferred = simgr.deferred[-max_deferred:]
        except Exception:
            pass
        return simgr
