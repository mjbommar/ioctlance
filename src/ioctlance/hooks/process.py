"""Process/Thread hooks for Windows kernel API simulation."""

import claripy

from .base import BaseHook


class HookPsGetVersion(BaseHook):
    """Hook for PsGetVersion."""

    def run(self, MajorVersion, MinorVersion, BuildNumber, CSDVersion) -> int:
        """Get OS version (stub)."""
        return 0


class HookPsGetCurrentProcessId(BaseHook):
    """Hook for PsGetCurrentProcessId."""

    def run(self):
        """Return symbolic process ID."""
        return claripy.BVS("current_pid", 32)


class HookZwTerminateProcess(BaseHook):
    """Hook for ZwTerminateProcess - terminates a process."""

    def run(self, ProcessHandle, ExitStatus) -> int:
        """Terminate a process."""
        context = self.get_context()

        # Debug output
        if context:
            context.print_info(f"[HOOK] ZwTerminateProcess called: Handle={ProcessHandle}, ExitStatus={ExitStatus}")

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.process_termination import ProcessTerminationDetector

            detector = ProcessTerminationDetector(context)
            vuln = detector.check_zwterminateprocess(self.state, ProcessHandle, ExitStatus)
            if vuln:
                context.add_vulnerability(vuln)

        if context:
            context.print_debug(f"ZwTerminateProcess: Handle={ProcessHandle}, ExitStatus={ExitStatus}")

        # Return STATUS_SUCCESS (0)
        return 0


class HookPsLookupProcessByProcessId(BaseHook):
    """Hook for PsLookupProcessByProcessId - looks up process by PID."""

    def run(self, ProcessId, Process) -> int:
        """Look up process by PID."""
        context = self.get_context()

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.process_termination import ProcessTerminationDetector

            detector = ProcessTerminationDetector(context)
            vuln = detector.check_pslookupprocessbyprocessid(self.state, ProcessId, Process)
            if vuln:
                context.add_vulnerability(vuln)

        # Create symbolic EPROCESS structure
        eprocess_addr = context.next_base_addr() if context else 0x51000000
        eprocess = claripy.BVS("eprocess", 8 * 0x800)  # EPROCESS is large
        self.state.memory.store(eprocess_addr, eprocess, 0x800, disable_actions=True, inspect=False)

        # Store pointer to EPROCESS
        self.state.memory.store(Process, eprocess_addr, self.state.arch.bytes, disable_actions=True, inspect=False)

        if context:
            context.print_debug(f"PsLookupProcessByProcessId: PID={ProcessId} -> EPROCESS at {hex(eprocess_addr)}")

        # Return STATUS_SUCCESS (0)
        return 0


class HookZwOpenProcess(BaseHook):
    """Hook for ZwOpenProcess - opens a process handle."""

    def run(self, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId) -> int:
        """Open a process handle."""
        context = self.get_context()

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.process_termination import ProcessTerminationDetector

            detector = ProcessTerminationDetector(context)
            vuln = detector.check_zwopenprocess(self.state, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)
            if vuln:
                context.add_vulnerability(vuln)

        # Create symbolic handle
        handle = claripy.BVS("process_handle", self.state.arch.bits)

        # Store handle
        self.state.memory.store(ProcessHandle, handle, self.state.arch.bytes, disable_actions=True, inspect=False)

        if context:
            context.print_debug(f"ZwOpenProcess: DesiredAccess={DesiredAccess}, ClientId={ClientId}")

        # Return STATUS_SUCCESS (0)
        return 0


class HookObDereferenceObject(BaseHook):
    """Hook for ObDereferenceObject - dereferences an object."""

    def run(self, Object) -> None:
        """Dereference an object."""
        context = self.get_context()

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.process_termination import ProcessTerminationDetector

            detector = ProcessTerminationDetector(context)
            vuln = detector.check_obdereferenceobject(self.state, Object)
            if vuln:
                context.add_vulnerability(vuln)

        if context:
            context.print_debug(f"ObDereferenceObject: Object={Object}")

        return None


class HookObfDereferenceObject(BaseHook):
    """Hook for ObfDereferenceObject - fast dereference of an object."""

    def run(self, Object) -> None:
        """Fast dereference an object."""
        context = self.get_context()

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.process_termination import ProcessTerminationDetector

            detector = ProcessTerminationDetector(context)
            vuln = detector.check_obdereferenceobject(self.state, Object)
            if vuln:
                context.add_vulnerability(vuln)

        if context:
            context.print_debug(f"ObfDereferenceObject: Object={Object}")

        return None


class HookPsGetCurrentProcess(BaseHook):
    """Hook for PsGetCurrentProcess - gets current process."""

    def run(self):
        """Get current process."""
        context = self.get_context()

        # Return symbolic EPROCESS pointer
        eprocess_addr = context.next_base_addr() if context else 0x52000000

        if context:
            context.print_debug(f"PsGetCurrentProcess -> {hex(eprocess_addr)}")

        return eprocess_addr


class HookPsGetCurrentThread(BaseHook):
    """Hook for PsGetCurrentThread - gets current thread."""

    def run(self):
        """Get current thread."""
        context = self.get_context()

        # Return symbolic ETHREAD pointer
        ethread_addr = context.next_base_addr() if context else 0x53000000

        if context:
            context.print_debug(f"PsGetCurrentThread -> {hex(ethread_addr)}")

        return ethread_addr


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
        "PsGetVersion": HookPsGetVersion,
        "PsGetCurrentProcessId": HookPsGetCurrentProcessId,
        "ZwTerminateProcess": HookZwTerminateProcess,
        "PsLookupProcessByProcessId": HookPsLookupProcessByProcessId,
        "ZwOpenProcess": HookZwOpenProcess,
        "ObDereferenceObject": HookObDereferenceObject,
        "ObfDereferenceObject": HookObfDereferenceObject,
        "PsGetCurrentProcess": HookPsGetCurrentProcess,
        "PsGetCurrentThread": HookPsGetCurrentThread,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookPsGetVersion",
    "HookPsGetCurrentProcessId",
    "HookZwTerminateProcess",
    "HookPsLookupProcessByProcessId",
    "HookZwOpenProcess",
    "HookObDereferenceObject",
    "HookObfDereferenceObject",
    "HookPsGetCurrentProcess",
    "HookPsGetCurrentThread",
]
