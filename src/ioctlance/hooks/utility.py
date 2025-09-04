"""Utility hooks for Windows kernel API simulation."""

from .base import BaseHook


class HookDoNothing(BaseHook):
    """Hook that does nothing - used as a placeholder."""

    def run(self, *args, **kwargs) -> int:
        """Do nothing and return success."""
        return self.return_success()


class HookVsnprintf(BaseHook):
    """Hook for vsnprintf - formatted string output."""

    def run(self, buffer, count, format, argptr) -> int:
        """Call detectors for format string analysis and return success."""
        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                if hasattr(detector, "check_state") and detector.enabled:
                    try:
                        result = detector.check_state(
                            self.state,
                            "call",
                            func_name="vsnprintf",
                            buffer=buffer,
                            size=count,
                            format_str=format,
                            args=argptr,
                        )
                        if result:
                            context.add_vulnerability(result)
                    except Exception:
                        continue
        return 0


class HookFltGetRoutineAddress(BaseHook):
    """Hook for FltGetRoutineAddress - gets filter manager routine address."""

    def run(self, FltRoutineName):
        """Get filter manager routine address."""
        context = self.get_context()
        # Return a symbolic address for filter routines
        routine_addr = context.next_base_addr() if context else 0x70000000
        return routine_addr


def register_hooks(project) -> None:
    """Register hooks with the project.

    Args:
        project: angr project to register hooks with
    """
    # Get calling convention
    cc = BaseHook.get_calling_convention(project)

    hooks = {
        "DoNothing": HookDoNothing,
        "Vsnprintf": HookVsnprintf,
        "vsnprintf": HookVsnprintf,
        "FltGetRoutineAddress": HookFltGetRoutineAddress,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookDoNothing",
    "HookVsnprintf",
    "HookFltGetRoutineAddress",
]
