"""Memory Manager hooks for Windows kernel API simulation."""

import claripy

from .base import BaseHook


class HookProbeForRead(BaseHook):
    """Hook for ProbeForRead - validates user-mode buffer for reading."""

    def run(self, Address, Length, Alignment) -> None:
        """Mark buffer as validated for read operations."""
        context = self.get_context()

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.probe_bypass import ProbeBypassDetector

            detector = ProbeBypassDetector(context)
            vuln = detector.check_probe_for_read(self.state, Address, Length, Alignment)
            if vuln:
                context.add_vulnerability(vuln)

        # Track this address as validated
        if "tainted_ProbeForRead" not in self.state.globals:
            self.state.globals["tainted_ProbeForRead"] = ()

        self.state.globals["tainted_ProbeForRead"] = self.state.globals["tainted_ProbeForRead"] + (str(Address),)

        if context:
            context.print_debug(f"ProbeForRead: Address={Address}, Length={Length}")

        return None


class HookProbeForWrite(BaseHook):
    """Hook for ProbeForWrite - validates user-mode buffer for writing."""

    def run(self, Address, Length, Alignment) -> None:
        """Mark buffer as validated for write operations."""
        context = self.get_context()

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.probe_bypass import ProbeBypassDetector

            detector = ProbeBypassDetector(context)
            vuln = detector.check_probe_for_write(self.state, Address, Length, Alignment)
            if vuln:
                context.add_vulnerability(vuln)

        # Track this address as validated
        if "tainted_ProbeForWrite" not in self.state.globals:
            self.state.globals["tainted_ProbeForWrite"] = ()

        self.state.globals["tainted_ProbeForWrite"] = self.state.globals["tainted_ProbeForWrite"] + (str(Address),)

        if context:
            context.print_debug(f"ProbeForWrite: Address={Address}, Length={Length}")

        return None


class HookMmIsAddressValid(BaseHook):
    """Hook for MmIsAddressValid - checks if address is valid."""

    def run(self, VirtualAddress):
        """Check if address is valid and track it."""
        context = self.get_context()

        # Track this address as validated
        if "tainted_MmIsAddressValid" not in self.state.globals:
            self.state.globals["tainted_MmIsAddressValid"] = ()

        self.state.globals["tainted_MmIsAddressValid"] = self.state.globals["tainted_MmIsAddressValid"] + (
            str(VirtualAddress),
        )

        if context:
            context.print_debug(f"MmIsAddressValid: VirtualAddress={VirtualAddress}")

        # Return symbolic value to explore both paths
        return claripy.BVS("MmIsAddressValid_ret", 8)


class HookMmAllocateNonCachedMemory(BaseHook):
    """Hook for MmAllocateNonCachedMemory - allocates non-cached memory."""

    def run(self, NumberOfBytes):
        """Allocate non-cached memory."""
        context = self.get_context()
        size = self.state.solver.min(NumberOfBytes)

        # Allocate memory
        mem_addr = context.next_base_addr() if context else 0x60000000
        memory = claripy.BVS("non_cached_memory", 8 * size)
        self.state.memory.store(mem_addr, memory, size, disable_actions=True, inspect=False)

        return mem_addr


class HookMmFreeNonCachedMemory(BaseHook):
    """Hook for MmFreeNonCachedMemory - frees non-cached memory."""

    def run(self, BaseAddress, NumberOfBytes) -> None:
        """Free non-cached memory (no-op in symbolic execution)."""
        return None


class HookMmMapIoSpace(BaseHook):
    """Hook for MmMapIoSpace - maps I/O space to virtual address."""

    def run(self, PhysicalAddress, NumberOfBytes, CacheType):
        """Map I/O space."""
        context = self.get_context()

        # Check for vulnerabilities with our detector
        if context:
            from ..detectors.physical_memory import PhysicalMemoryDetector

            # Try to get existing detector instance or create new one
            detector = PhysicalMemoryDetector(context)
            vuln = detector.check_mmmapiosspace(self.state, PhysicalAddress, NumberOfBytes, CacheType)
            if vuln:
                context.add_vulnerability(vuln)

        size = self.state.solver.min(NumberOfBytes)

        # Create mapped I/O space
        io_addr = context.next_base_addr() if context else 0x61000000
        io_space = claripy.BVS("io_space", 8 * size)
        self.state.memory.store(io_addr, io_space, size, disable_actions=True, inspect=False)

        return io_addr


class HookMmUnmapIoSpace(BaseHook):
    """Hook for MmUnmapIoSpace - unmaps I/O space."""

    def run(self, BaseAddress, NumberOfBytes) -> None:
        """Unmap I/O space (no-op in symbolic execution)."""
        return None


class HookMmBuildMdlForNonPagedPool(BaseHook):
    """Hook for MmBuildMdlForNonPagedPool - builds MDL for non-paged pool."""

    def run(self, MemoryDescriptorList) -> None:
        """Build MDL for non-paged pool (stub implementation)."""
        return None


class HookMmGetSystemRoutineAddress(BaseHook):
    """Hook for MmGetSystemRoutineAddress - gets system routine address."""

    def run(self, SystemRoutineName):
        """Get system routine address."""
        context = self.get_context()

        # Return a symbolic address for unknown routines
        routine_addr = context.next_base_addr() if context else 0x62000000

        # Could check SystemRoutineName and return specific addresses
        # for known routines if needed

        return routine_addr


class HookMmGetPhysicalAddress(BaseHook):
    """Hook for MmGetPhysicalAddress - gets physical address."""

    def run(self, BaseAddress):
        """Get physical address for virtual address."""
        # Return symbolic physical address
        return claripy.BVS("physical_address", 64)


class HookMmAllocateContiguousMemory(BaseHook):
    """Hook for MmAllocateContiguousMemory - allocates contiguous memory."""

    def run(self, NumberOfBytes, HighestAcceptableAddress):
        """Allocate contiguous memory."""
        context = self.get_context()
        size = self.state.solver.min(NumberOfBytes)

        # Allocate memory
        mem_addr = context.next_base_addr() if context else 0x63000000
        memory = claripy.BVS("contiguous_memory", 8 * size)
        self.state.memory.store(mem_addr, memory, size, disable_actions=True, inspect=False)

        return mem_addr


class HookMmFreeContiguousMemory(BaseHook):
    """Hook for MmFreeContiguousMemory - frees contiguous memory."""

    def run(self, BaseAddress) -> None:
        """Free contiguous memory (no-op in symbolic execution)."""
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
        "ProbeForRead": HookProbeForRead,
        "ProbeForWrite": HookProbeForWrite,
        "MmIsAddressValid": HookMmIsAddressValid,
        "MmAllocateNonCachedMemory": HookMmAllocateNonCachedMemory,
        "MmFreeNonCachedMemory": HookMmFreeNonCachedMemory,
        "MmMapIoSpace": HookMmMapIoSpace,
        "MmUnmapIoSpace": HookMmUnmapIoSpace,
        "MmBuildMdlForNonPagedPool": HookMmBuildMdlForNonPagedPool,
        "MmGetSystemRoutineAddress": HookMmGetSystemRoutineAddress,
        "MmGetPhysicalAddress": HookMmGetPhysicalAddress,
        "MmAllocateContiguousMemory": HookMmAllocateContiguousMemory,
        "MmFreeContiguousMemory": HookMmFreeContiguousMemory,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookProbeForRead",
    "HookProbeForWrite",
    "HookMmIsAddressValid",
    "HookMmAllocateNonCachedMemory",
    "HookMmFreeNonCachedMemory",
    "HookMmMapIoSpace",
    "HookMmUnmapIoSpace",
    "HookMmBuildMdlForNonPagedPool",
    "HookMmGetSystemRoutineAddress",
    "HookMmGetPhysicalAddress",
    "HookMmAllocateContiguousMemory",
    "HookMmFreeContiguousMemory",
]
