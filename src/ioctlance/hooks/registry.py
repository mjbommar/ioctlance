"""Registry hooks for Windows kernel API simulation."""

from .base import BaseHook


class HookRtlWriteRegistryValue(BaseHook):
    """Hook for RtlWriteRegistryValue."""

    def run(self, RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength) -> int:
        """Write registry value (stub)."""
        return 0


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
        "RtlWriteRegistryValue": HookRtlWriteRegistryValue,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookRtlWriteRegistryValue",
]
