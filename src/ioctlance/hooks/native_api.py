"""Native API (Zw*) hooks for Windows kernel API simulation."""

import claripy

from .base import BaseHook


class HookZwQueryInformationProcess(BaseHook):
    """Hook for ZwQueryInformationProcess."""

    def run(
        self,
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength,
    ) -> int:
        """Query process information (stub)."""
        return 0


class HookZwOpenSection(BaseHook):
    """Hook for ZwOpenSection."""

    def run(self, SectionHandle, DesiredAccess, ObjectAttributes) -> int:
        """Open section and track handle."""
        self.get_context()

        # Track opened sections
        if "open_section_handles" not in self.state.globals:
            self.state.globals["open_section_handles"] = ()

        # Create symbolic section handle
        section_handle = claripy.BVS("section_handle", 64)
        self.state.memory.store(SectionHandle, section_handle, 8, disable_actions=True, inspect=False)

        self.state.globals["open_section_handles"] = self.state.globals["open_section_handles"] + (str(section_handle),)

        return 0


class HookZwClose(BaseHook):
    """Hook for ZwClose."""

    def run(self, Handle) -> int:
        """Close handle (stub)."""
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
        "ZwQueryInformationProcess": HookZwQueryInformationProcess,
        "ZwOpenSection": HookZwOpenSection,
        "ZwClose": HookZwClose,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookZwQueryInformationProcess",
    "HookZwOpenSection",
    "HookZwClose",
]
