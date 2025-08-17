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
        """Stub implementation of vsnprintf."""
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
    import archinfo
    from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCStdcall

    if project.arch.name == archinfo.ArchX86.name:
        cc = SimCCStdcall(project.arch)
    else:
        cc = SimCCMicrosoftAMD64(project.arch)

    hooks = {
        "DoNothing": HookDoNothing,
        "Vsnprintf": HookVsnprintf,
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
