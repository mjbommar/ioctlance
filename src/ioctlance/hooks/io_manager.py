"""I/O Manager hooks for Windows kernel API simulation."""

import claripy

from .base import BaseHook


class HookIoStartPacket(BaseHook):
    """Hook for IoStartPacket - starts I/O packet processing."""

    def run(self, DeviceObject, Irp, Key, CancelFunction):
        """Call DriverStartIo when IoStartPacket is called."""
        context = self.get_context()
        if context and hasattr(context, "DriverStartIo") and context.DriverStartIo:
            import angr
            new_state = self.state.project.factory.call_state(
                addr=context.DriverStartIo, args=(DeviceObject, Irp), base_state=self.state,
                add_options=angr.options.resilience
            )
            if context.simulation_manager:
                context.simulation_manager.deferred.append(new_state)
        return self.return_success()


class HookIoCreateDevice(BaseHook):
    """Hook for IoCreateDevice - creates a device object."""

    def run(
        self,
        DriverObject,
        DeviceExtensionSize,
        DeviceName,
        DeviceType,
        DeviceCharacteristics,
        Exclusive,
        DeviceObject,
    ):
        """Initialize device object."""
        context = self.get_context()

        # Initialize device object
        devobjaddr = context.next_base_addr() if context else 0x50000000
        self.state.globals["device_object_addr"] = devobjaddr
        device_object = claripy.BVS("device_object", 8 * 0x400)
        self.state.memory.store(devobjaddr, device_object, 0x400, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.Flags = 0
        self.state.mem[DeviceObject].PDEVICE_OBJECT = devobjaddr

        # Initialize device extension
        new_device_extension_addr = context.next_base_addr() if context else 0x51000000
        size = self.state.solver.min(DeviceExtensionSize)
        device_extension = claripy.BVV(0, 8 * size)
        self.state.memory.store(new_device_extension_addr, device_extension, size, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.DeviceExtension = new_device_extension_addr

        return self.return_success()


class HookIoCreateSymbolicLink(BaseHook):
    """Hook for IoCreateSymbolicLink - creates a symbolic link."""

    def run(self, SymbolicLinkName, DeviceName):
        """Create symbolic link (stub implementation)."""
        return self.return_success()


class HookIoIs32bitProcess(BaseHook):
    """Hook for IoIs32bitProcess - checks if current process is 32-bit."""

    def run(self) -> int:
        """Return 0 (not 32-bit process)."""
        return 0


class HookIoGetDeviceProperty(BaseHook):
    """Hook for IoGetDeviceProperty - gets device property."""

    def run(self, DeviceObject, DeviceProperty, BufferLength, PropertyBuffer, ResultLength):
        """Get device property (stub implementation)."""
        return self.return_success()


class HookIoAllocateMdl(BaseHook):
    """Hook for IoAllocateMdl - allocates an MDL."""

    def run(self, VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp):
        """Allocate MDL."""
        context = self.get_context()
        mdl_addr = context.next_base_addr() if context else 0x52000000

        # Create MDL structure
        mdl = claripy.BVS("mdl", 8 * 0x100)
        self.state.memory.store(mdl_addr, mdl, 0x100, disable_actions=True, inspect=False)

        # If Irp is provided, store MDL in IRP
        if Irp != 0:
            self.state.mem[Irp].IRP.MdlAddress = mdl_addr

        return mdl_addr


class HookIoFreeMdl(BaseHook):
    """Hook for IoFreeMdl - frees an MDL."""

    def run(self, Mdl) -> None:
        """Free MDL (no-op in symbolic execution)."""
        return None


class HookIofCompleteRequest(BaseHook):
    """Hook for IofCompleteRequest - completes an I/O request."""

    def run(self, Irp, PriorityBoost) -> None:
        """Complete I/O request (stub implementation)."""
        return None


class HookIoGetCurrentProcess(BaseHook):
    """Hook for IoGetCurrentProcess - gets current process."""

    def run(self):
        """Return symbolic EPROCESS pointer."""
        context = self.get_context()
        eprocess_addr = context.next_base_addr() if context else 0x53000000

        # Create EPROCESS structure if not exists
        if "current_eprocess" not in self.state.globals:
            eprocess = claripy.BVS("eprocess", 8 * 0x800)
            self.state.memory.store(eprocess_addr, eprocess, 0x800, disable_actions=True, inspect=False)
            self.state.globals["current_eprocess"] = eprocess_addr
        else:
            eprocess_addr = self.state.globals["current_eprocess"]

        return eprocess_addr


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
        "IoStartPacket": HookIoStartPacket,
        "IoCreateDevice": HookIoCreateDevice,
        "IoCreateSymbolicLink": HookIoCreateSymbolicLink,
        "IoIs32bitProcess": HookIoIs32bitProcess,
        "IoGetDeviceProperty": HookIoGetDeviceProperty,
        "IoAllocateMdl": HookIoAllocateMdl,
        "IoFreeMdl": HookIoFreeMdl,
        "IofCompleteRequest": HookIofCompleteRequest,
        "IoGetCurrentProcess": HookIoGetCurrentProcess,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookIoStartPacket",
    "HookIoCreateDevice",
    "HookIoCreateSymbolicLink",
    "HookIoIs32bitProcess",
    "HookIoGetDeviceProperty",
    "HookIoAllocateMdl",
    "HookIoFreeMdl",
    "HookIofCompleteRequest",
    "HookIoGetCurrentProcess",
]
