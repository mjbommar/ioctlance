"""Base hook class for Windows kernel API simulation."""

import logging
import archinfo
from typing import Any
from angr import SimProcedure
from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCStdcall

from ..utils.error_handler import SymbolicExecutionErrorHandler

logger = logging.getLogger(__name__)


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
        if not self.log_calls:
            # Allow debug logging when context is verbose/debug
            ctx = self.get_context()
            if not (ctx and getattr(ctx.config, "debug", False)):
                return
        try:
            rendered = ", ".join(f"{hex(arg) if isinstance(arg, int) else str(arg)}" for arg in args)
            logger.debug(
                f"[HOOK] {func_name}({rendered}) @ {hex(self.state.addr) if hasattr(self.state, 'addr') else ''}"
            )
        except Exception:
            # Logging must not break execution
            pass

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

    def safe_symbolic_check(self, value: Any) -> bool:
        """Safely check if a value is symbolic without causing ClaripyOperationError.

        Args:
            value: Value to check

        Returns:
            True if value is symbolic, False otherwise
        """
        return SymbolicExecutionErrorHandler.safe_symbolic_check(value)

    def safe_eval(self, value: Any, default: Any = 0) -> Any:
        """Safely evaluate a potentially symbolic value.

        Args:
            value: Value to evaluate
            default: Default value if evaluation fails

        Returns:
            Concrete value or default if evaluation fails
        """
        return SymbolicExecutionErrorHandler.safe_eval(self.state, value, default)

    @staticmethod
    def get_calling_convention(project):
        """Get the appropriate calling convention for the project's architecture.

        Args:
            project: angr project to determine calling convention for

        Returns:
            Appropriate calling convention (SimCCStdcall for x86, SimCCMicrosoftAMD64 for x64)
        """
        if project.arch.name == archinfo.ArchX86.name:
            return SimCCStdcall(project.arch)
        else:
            return SimCCMicrosoftAMD64(project.arch)
