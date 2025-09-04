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


class HookZwMapViewOfSection(BaseHook):
    """Hook for ZwMapViewOfSection to notify detectors."""

    def run(self, SectionHandle, ProcessHandle, BaseAddress, *args) -> int:
        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "call",
                            func_name="ZwMapViewOfSection",
                            section_handle=SectionHandle,
                            process_handle=ProcessHandle,
                            base_address=BaseAddress,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                except Exception:
                    continue
        return 0


class HookZwTerminateProcess(BaseHook):
    """Hook for ZwTerminateProcess to notify detectors."""

    def run(self, ProcessHandle, ExitStatus) -> int:
        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "call",
                            func_name="ZwTerminateProcess",
                            process_handle=ProcessHandle,
                            exit_status=ExitStatus,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                except Exception:
                    continue
        return 0


class HookZwOpenProcess(BaseHook):
    """Hook for ZwOpenProcess to notify detectors."""

    def run(self, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId, HandleAttributes) -> int:
        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "call",
                            func_name="ZwOpenProcess",
                            process_handle=ProcessHandle,
                            desired_access=DesiredAccess,
                            client_id=ClientId,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                except Exception:
                    continue
        return 0


class HookPsLookupProcessByProcessId(BaseHook):
    """Hook for PsLookupProcessByProcessId to notify detectors."""

    def run(self, ProcessId, Process) -> int:
        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "call",
                            func_name="PsLookupProcessByProcessId",
                            process_id=ProcessId,
                            process=Process,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                except Exception:
                    continue
        return 0


def register_hooks(project) -> None:
    """Register hooks with the project.

    Args:
        project: angr project to register hooks with
    """
    # Get calling convention
    cc = BaseHook.get_calling_convention(project)

    hooks = {
        "ZwQueryInformationProcess": HookZwQueryInformationProcess,
        "ZwOpenSection": HookZwOpenSection,
        "ZwClose": HookZwClose,
        "ZwMapViewOfSection": HookZwMapViewOfSection,
        "ZwTerminateProcess": HookZwTerminateProcess,
        "ZwOpenProcess": HookZwOpenProcess,
        "PsLookupProcessByProcessId": HookPsLookupProcessByProcessId,
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
