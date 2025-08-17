"""Integer overflow and underflow vulnerability detector."""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from .base import VulnerabilityDetector

logger = logging.getLogger(__name__)


class IntegerOverflowDetector(VulnerabilityDetector):
    """Detects integer overflow and underflow vulnerabilities."""

    name = "integer_overflow"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects integer overflow and underflow in arithmetic operations"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the integer overflow detector.

        Args:
            context: Analysis context
        """
        super().__init__(context)
        self.detected_overflows = set()

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Detect integer overflow/underflow vulnerabilities.

        This detector hooks arithmetic operations and checks if:
        1. The operands are tainted (user-controlled)
        2. The result could overflow or underflow

        Args:
            state: Current simulation state

        Returns:
            Vulnerability information if detected, None otherwise
        """
        # This is called from breakpoints, not directly
        # The actual detection happens in check_arithmetic_operation
        return None

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for integer overflow vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event (mem_read, mem_write, call, expr)
            **kwargs: Additional event-specific arguments

        Returns:
            Vulnerability information if detected
        """
        # We only care about expression events for arithmetic operations
        if event_type != "expr":
            return None

        # The actual detection is done in check_arithmetic_operation
        # which is called from the b_vex_expr breakpoint
        return None

    def check_arithmetic_operation(
        self, state: SimState, op: str, result: Any, operand1: Any, operand2: Any = None
    ) -> dict[str, Any] | None:
        """Check an arithmetic operation for overflow/underflow.

        Args:
            state: Current simulation state
            op: Operation type (ADD, SUB, MUL, DIV)
            result: Result of the operation
            operand1: First operand
            operand2: Second operand (if binary operation)

        Returns:
            Vulnerability information if detected
        """
        # Check if operands are symbolic (tainted)
        is_tainted = False

        if hasattr(operand1, "symbolic"):
            is_tainted = is_tainted or operand1.symbolic
        if operand2 is not None and hasattr(operand2, "symbolic"):
            is_tainted = is_tainted or operand2.symbolic

        if not is_tainted:
            return None

        # Check for overflow/underflow conditions
        vuln_type = None
        details = {}

        if op == "ADD":
            # Check for addition overflow
            if self._check_add_overflow(state, result, operand1, operand2):
                vuln_type = "integer overflow (addition)"
                details = {
                    "operation": "ADD",
                    "operand1": str(operand1),
                    "operand2": str(operand2),
                    "result": str(result),
                }

        elif op == "SUB":
            # Check for subtraction underflow
            if self._check_sub_underflow(state, result, operand1, operand2):
                vuln_type = "integer underflow (subtraction)"
                details = {
                    "operation": "SUB",
                    "operand1": str(operand1),
                    "operand2": str(operand2),
                    "result": str(result),
                }

        elif op == "MUL":
            # Check for multiplication overflow
            if self._check_mul_overflow(state, result, operand1, operand2):
                vuln_type = "integer overflow (multiplication)"
                details = {
                    "operation": "MUL",
                    "operand1": str(operand1),
                    "operand2": str(operand2),
                    "result": str(result),
                }

        if vuln_type:
            # Create unique key for deduplication
            vuln_key = (state.addr, op, vuln_type)
            if vuln_key in self.detected_overflows:
                return None
            self.detected_overflows.add(vuln_key)

            # Create vulnerability report
            vuln = {
                "title": vuln_type,
                "description": f"Tainted arithmetic operation can cause {vuln_type}",
                "state": repr(state),
                "eval": {
                    "IoControlCode": (
                        hex(self.context.io_control_code) if self.context.io_control_code is not None else "N/A"
                    ),
                },
                "parameters": details,
                "others": {
                    "instruction_address": hex(state.addr),
                    "severity": "HIGH" if "overflow" in vuln_type else "MEDIUM",
                },
            }

            self.context.print_info(f"[VULN] {vuln_type} at {state.addr:#x}")
            return vuln

        return None

    def _check_add_overflow(self, state: SimState, result: Any, op1: Any, op2: Any) -> bool:
        """Check if addition can overflow.

        For unsigned: result < op1 or result < op2
        For signed: signs same and result sign different
        """
        try:
            # Create a test state to check overflow conditions
            test_state = state.copy()

            # For simplicity, check if result can be less than operands (unsigned overflow)
            if hasattr(result, "length"):
                max_val = 2 ** result.length() - 1

                # Check if we can make the addition overflow
                test_state.solver.add(op1 + op2 > max_val)
                if test_state.satisfiable():
                    return True

            # Check for signed overflow (both positive but result negative)
            if result.length() >= 8:
                sign_bit = result.length() - 1
                test_state2 = state.copy()

                # Both operands positive
                test_state2.solver.add(op1[sign_bit] == 0)
                test_state2.solver.add(op2[sign_bit] == 0)
                # Result negative
                test_state2.solver.add(result[sign_bit] == 1)

                if test_state2.satisfiable():
                    return True

        except Exception as e:
            logger.debug(f"Error checking add overflow: {e}")

        return False

    def _check_sub_underflow(self, state: SimState, result: Any, op1: Any, op2: Any) -> bool:
        """Check if subtraction can underflow.

        For unsigned: result > op1
        For signed: different signs and result sign wrong
        """
        try:
            test_state = state.copy()

            # Check unsigned underflow (result > op1)
            test_state.solver.add(result > op1)
            if test_state.satisfiable():
                return True

            # Check signed underflow
            if result.length() >= 8:
                sign_bit = result.length() - 1
                test_state2 = state.copy()

                # op1 negative, op2 positive, result positive (should be more negative)
                test_state2.solver.add(op1[sign_bit] == 1)
                test_state2.solver.add(op2[sign_bit] == 0)
                test_state2.solver.add(result[sign_bit] == 0)

                if test_state2.satisfiable():
                    return True

        except Exception as e:
            logger.debug(f"Error checking sub underflow: {e}")

        return False

    def _check_mul_overflow(self, state: SimState, result: Any, op1: Any, op2: Any) -> bool:
        """Check if multiplication can overflow.

        Check if op1 * op2 > MAX_VALUE
        """
        try:
            if not hasattr(result, "length"):
                return False

            test_state = state.copy()
            max_val = 2 ** result.length() - 1

            # Check if multiplication can exceed max value
            # We need to be careful here as the multiplication itself might overflow
            # Check if either operand can be large enough to cause overflow

            # If op2 != 0, then overflow if op1 > MAX / op2
            test_state.solver.add(op2 != 0)
            test_state.solver.add(op1 > (max_val / op2))

            if test_state.satisfiable():
                return True

        except Exception as e:
            logger.debug(f"Error checking mul overflow: {e}")

        return False


# Register the detector
from .base import detector_registry

detector_registry.register(IntegerOverflowDetector)
