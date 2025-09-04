"""Centralized error handling for symbolic execution errors."""

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SymbolicExecutionErrorHandler:
    """Central handler for common symbolic execution errors."""

    # Known non-fatal errors that can be safely ignored
    NON_FATAL_ERRORS = [
        "Invalid cc_op",
        "ClaripyOperationError",
        "testing Expressions for truthiness",
        "Invalid condition code operation",
        "Unknown cc_op value",
    ]

    @classmethod
    def handle_cc_op_error(cls, error: Exception, state: Any = None) -> Any | None:
        """Handle invalid cc_op errors from angr's condition code calculations.

        Args:
            error: The exception that was raised
            state: The symbolic state (if available)

        Returns:
            A symbolic value to use as fallback, or None if error should propagate
        """
        if isinstance(error, KeyError) and isinstance(error.args[0], int):
            # This is likely an invalid cc_op value
            cc_op_value = error.args[0]
            logger.debug(f"Invalid cc_op {cc_op_value} encountered, returning symbolic value")

            if state and hasattr(state, "solver"):
                # Return a symbolic value that represents unknown condition codes
                return state.solver.BVS("invalid_cc_rdata", 64)
            return None

        # Let other errors propagate
        return None

    @classmethod
    def handle_claripy_error(cls, error: Exception, context: str = "") -> bool:
        """Handle ClaripyOperationError for symbolic value operations.

        Args:
            error: The exception that was raised
            context: Context about where the error occurred

        Returns:
            True if error was handled and should be ignored, False otherwise
        """
        error_str = str(error)

        # Check if this is the common truthiness error
        if "testing Expressions for truthiness" in error_str:
            logger.debug(f"Ignoring ClaripyOperationError in {context}: symbolic truthiness check")
            return True

        # Check for other known Claripy errors
        if "ClaripyOperationError" in error_str:
            logger.debug(f"Ignoring ClaripyOperationError in {context}: {error_str[:100]}")
            return True

        return False

    @classmethod
    def is_non_fatal_error(cls, error: Exception) -> bool:
        """Check if an error is known to be non-fatal and can be ignored.

        Args:
            error: The exception to check

        Returns:
            True if error is non-fatal and can be ignored
        """
        error_str = str(error)

        # Check against known non-fatal patterns
        for pattern in cls.NON_FATAL_ERRORS:
            if pattern in error_str:
                return True

        # Special handling for KeyError with large numeric values (invalid cc_op)
        if isinstance(error, KeyError):
            if isinstance(error.args[0], int) and error.args[0] > 1000000:
                return True

        return False

    @classmethod
    def handle_step_error(cls, error: Exception, step_count: int, context: Any = None) -> bool:
        """Handle errors during symbolic execution steps.

        Args:
            error: The exception that occurred
            step_count: Current step count in execution
            context: Analysis context (if available)

        Returns:
            True if execution should continue, False if it should stop
        """
        # Check if it's a known non-fatal error
        if cls.is_non_fatal_error(error):
            logger.debug(f"Non-fatal error at step {step_count}: {error}")
            return True  # Continue execution

        # Log the error for debugging
        logger.warning(f"Error during step {step_count}: {error}")

        # Check if we have context to add more info
        if context and hasattr(context, "add_error"):
            context.add_error(f"Step {step_count}: {error}")

        # For unknown errors, it's safer to stop
        return False

    @classmethod
    def safe_symbolic_check(cls, value: Any) -> bool:
        """Safely check if a value is symbolic without causing ClaripyOperationError.

        Args:
            value: Value to check

        Returns:
            True if value is symbolic, False otherwise
        """
        # First check if value is None
        if value is None:
            return False

        # Check if it has symbolic attribute (Claripy BVS/BVV)
        if hasattr(value, "symbolic"):
            return value.symbolic

        # Check if it has is_symbolic method
        if hasattr(value, "is_symbolic"):
            return value.is_symbolic()

        # Not a symbolic value
        return False

    @classmethod
    def safe_eval(cls, state: Any, value: Any, default: Any = 0) -> Any:
        """Safely evaluate a potentially symbolic value.

        Args:
            state: Symbolic state with solver
            value: Value to evaluate
            default: Default value if evaluation fails

        Returns:
            Concrete value or default if evaluation fails
        """
        try:
            if value is None:
                return default

            if not cls.safe_symbolic_check(value):
                # Already concrete
                return value

            # Try to evaluate
            if hasattr(state, "solver"):
                return state.solver.eval(value)

            return default

        except Exception as e:
            logger.debug(f"Failed to evaluate symbolic value: {e}")
            return default
