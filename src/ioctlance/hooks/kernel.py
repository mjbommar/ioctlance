"""Kernel hooks for Windows kernel API simulation."""

from .base import BaseHook


class HookKeWaitForSingleObject(BaseHook):
    """Hook for KeWaitForSingleObject."""

    def run(self, Object, WaitReason, WaitMode, Alertable, Timeout) -> int:
        """Wait for single object (stub)."""
        return 0


class HookKeReleaseMutex(BaseHook):
    """Hook for KeReleaseMutex."""

    def run(self, Mutex, Wait) -> int:
        """Release mutex (stub)."""
        return 0


class HookKeQueryActiveGroupCount(BaseHook):
    """Hook for KeQueryActiveGroupCount."""

    def run(self) -> int:
        """Return active group count."""
        return 1


class HookKeQueryActiveProcessors(BaseHook):
    """Hook for KeQueryActiveProcessors."""

    def run(self) -> int:
        """Return active processors."""
        return 1


class HookKeQueryActiveProcessorCountEx(BaseHook):
    """Hook for KeQueryActiveProcessorCountEx."""

    def run(self, GroupNumber) -> int:
        """Return active processor count."""
        return 1


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
        "KeWaitForSingleObject": HookKeWaitForSingleObject,
        "KeReleaseMutex": HookKeReleaseMutex,
        "KeQueryActiveGroupCount": HookKeQueryActiveGroupCount,
        "KeQueryActiveProcessors": HookKeQueryActiveProcessors,
        "KeQueryActiveProcessorCountEx": HookKeQueryActiveProcessorCountEx,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookKeWaitForSingleObject",
    "HookKeReleaseMutex",
    "HookKeQueryActiveGroupCount",
    "HookKeQueryActiveProcessors",
    "HookKeQueryActiveProcessorCountEx",
]
