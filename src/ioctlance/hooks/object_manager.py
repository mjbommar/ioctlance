"""Object Manager hooks for Windows kernel API simulation."""

from .base import BaseHook


class HookObReferenceObjectByHandle(BaseHook):
    """Hook for ObReferenceObjectByHandle."""

    def run(self, Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation) -> int:
        """Reference object by handle (stub)."""
        return 0


class HookObDereferenceObject(BaseHook):
    """Hook for ObDereferenceObject."""

    def run(self, Object) -> None:
        """Dereference object (stub)."""
        return None


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
        "ObReferenceObjectByHandle": HookObReferenceObjectByHandle,
        "ObDereferenceObject": HookObDereferenceObject,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookObReferenceObjectByHandle",
    "HookObDereferenceObject",
]
