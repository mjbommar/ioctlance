"""Executive hooks for Windows kernel API simulation."""

import claripy

from .base import BaseHook


class HookExInitializeResourceLite(BaseHook):
    """Hook for ExInitializeResourceLite."""

    def run(self, Resource) -> int:
        """Initialize resource (stub)."""
        return 0


class HookExQueryDepthSList(BaseHook):
    """Hook for ExQueryDepthSList."""

    def run(self, SListHead) -> int:
        """Query SList depth."""
        return 0


class HookExGetPreviousMode(BaseHook):
    """Hook for ExGetPreviousMode."""

    def run(self) -> int:
        """Return UserMode (1)."""
        return 1


class HookExAllocatePool(BaseHook):
    """Hook for ExAllocatePool - allocates pool memory."""

    def run(self, PoolType, NumberOfBytes):
        """Allocate pool memory."""
        context = self.get_context()

        # Allocate memory
        size = self.state.solver.min(NumberOfBytes) if not isinstance(NumberOfBytes, int) else NumberOfBytes
        mem_addr = context.next_base_addr() if context else 0x50000000

        # Notify detectors about allocation
        if context and hasattr(context, "detectors"):
            for detector in context.detectors:
                if detector.enabled and hasattr(detector, "check_state"):
                    detector.check_state(self.state, "allocation", address=mem_addr, size=NumberOfBytes, tag="")
        memory = claripy.BVS("pool_memory", 8 * size)
        self.state.memory.store(mem_addr, memory, size, disable_actions=True, inspect=False)

        if context:
            context.print_debug(f"ExAllocatePool: Type={PoolType}, Size={NumberOfBytes} -> {hex(mem_addr)}")

        return mem_addr


class HookExAllocatePoolWithTag(BaseHook):
    """Hook for ExAllocatePoolWithTag - allocates pool memory with tag."""

    def run(self, PoolType, NumberOfBytes, Tag):
        """Allocate pool memory with tag."""
        context = self.get_context()

        # Allocate memory
        size = self.state.solver.min(NumberOfBytes) if not isinstance(NumberOfBytes, int) else NumberOfBytes
        mem_addr = context.next_base_addr() if context else 0x50000000

        # Notify detectors about allocation
        if context and hasattr(context, "detectors"):
            for detector in context.detectors:
                if detector.enabled and hasattr(detector, "check_state"):
                    detector.check_state(self.state, "allocation", address=mem_addr, size=NumberOfBytes, tag=Tag)
        memory = claripy.BVS("pool_memory_tagged", 8 * size)
        self.state.memory.store(mem_addr, memory, size, disable_actions=True, inspect=False)

        if context:
            context.print_debug(
                f"ExAllocatePoolWithTag: Type={PoolType}, Size={NumberOfBytes}, Tag={Tag} -> {hex(mem_addr)}"
            )

        return mem_addr


class HookExFreePool(BaseHook):
    """Hook for ExFreePool - frees pool memory."""

    def run(self, P) -> None:
        """Free pool memory."""
        context = self.get_context()

        # Notify detectors about free operation
        if context and hasattr(context, "detectors"):
            for detector in context.detectors:
                if detector.enabled:
                    # Check for double-free with specific method if available
                    if hasattr(detector, "check_exfreepool"):
                        vuln = detector.check_exfreepool(self.state, P)
                        if vuln:
                            context.add_vulnerability(vuln)
                    # Also notify through generic check_state
                    elif hasattr(detector, "check_state"):
                        detector.check_state(self.state, "free", address=P)

        if context:
            context.print_debug(f"ExFreePool: Ptr={P}")

        return None


class HookExFreePoolWithTag(BaseHook):
    """Hook for ExFreePoolWithTag - frees pool memory with tag."""

    def run(self, P, Tag) -> None:
        """Free pool memory with tag."""
        context = self.get_context()

        # Notify detectors about free operation
        if context and hasattr(context, "detectors"):
            for detector in context.detectors:
                if detector.enabled:
                    # Check for double-free with specific method if available
                    if hasattr(detector, "check_exfreepool"):
                        vuln = detector.check_exfreepool(self.state, P, Tag)
                        if vuln:
                            context.add_vulnerability(vuln)
                    # Also notify through generic check_state
                    elif hasattr(detector, "check_state"):
                        detector.check_state(self.state, "free", address=P, tag=Tag)

        if context:
            context.print_debug(f"ExFreePoolWithTag: Ptr={P}, Tag={Tag}")

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
        "ExInitializeResourceLite": HookExInitializeResourceLite,
        "ExQueryDepthSList": HookExQueryDepthSList,
        "ExGetPreviousMode": HookExGetPreviousMode,
        "ExAllocatePool": HookExAllocatePool,
        "ExAllocatePoolWithTag": HookExAllocatePoolWithTag,
        "ExFreePool": HookExFreePool,
        "ExFreePoolWithTag": HookExFreePoolWithTag,
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookExInitializeResourceLite",
    "HookExQueryDepthSList",
    "HookExGetPreviousMode",
    "HookExAllocatePool",
    "HookExAllocatePoolWithTag",
    "HookExFreePool",
    "HookExFreePoolWithTag",
]
