"""Base hook class for Windows kernel API simulation."""

from angr import SimProcedure


class BaseHook(SimProcedure):
    """Base class for Windows kernel API hooks.

    Provides common functionality for all hook implementations.
    """

    # Whether this hook is enabled
    enabled = True

    # Whether to log calls to this hook
    log_calls = False

    def __init__(self, *args, **kwargs) -> None:
        """Initialize the hook."""
        super().__init__(*args, **kwargs)

    def log_call(self, func_name: str, *args) -> None:
        """Log a function call if logging is enabled.

        Args:
            func_name: Name of the function being hooked
            *args: Arguments passed to the function
        """
        if self.log_calls:
            ", ".join(f"{hex(arg) if isinstance(arg, int) else arg}" for arg in args)

    def get_context(self):
        """Get the analysis context from state globals.

        Returns:
            AnalysisContext or None if not available
        """
        return self.state.globals.get("analysis_context")

    def return_success(self) -> int:
        """Return STATUS_SUCCESS (0)."""
        return 0

    def return_failure(self) -> int:
        """Return a generic failure status."""
        return 0xC0000001  # STATUS_UNSUCCESSFUL
