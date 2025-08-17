"""Object Manager hooks for Windows kernel API simulation."""

import claripy
import logging
from .base import BaseHook

logger = logging.getLogger(__name__)


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


class HookObOpenObjectByPointer(BaseHook):
    """Hook for ObOpenObjectByPointer - detects privilege escalation vulnerabilities."""

    def run(self, Object, HandleAttributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, Handle) -> int:
        """Open object by pointer with security checks.

        Args:
            Object: Pointer to the object (CRITICAL - user may control this)
            HandleAttributes: Attributes for the handle
            PassedAccessState: Access state
            DesiredAccess: Desired access rights (e.g., PROCESS_ALL_ACCESS)
            ObjectType: Type of object
            AccessMode: Kernel or User mode
            Handle: Output handle pointer

        Returns:
            STATUS_SUCCESS (0) or error code
        """
        context = self.get_context()

        # Check if Object pointer is tainted (user-controlled)
        is_tainted = self._is_tainted(Object)

        if is_tainted:
            # Create symbolic handle to track it
            handle_val = claripy.BVS(f"ob_handle_{id(self.state)}", self.state.arch.bits)
            self.state.memory.store(Handle, handle_val, self.state.arch.bytes, disable_actions=True, inspect=False)

            if context:
                # Track in detector for future operations
                for detector in context.detectors:
                    if hasattr(detector, "name") and detector.name == "process_termination":
                        if hasattr(detector, "tainted_handles"):
                            detector.tainted_handles.add(handle_val)
                        if hasattr(detector, "tainted_objects"):
                            detector.tainted_objects.add(Object)

                # Get IOCTL code if available
                ioctl_code = "N/A"
                if hasattr(self.state, "globals") and "IoControlCode" in self.state.globals:
                    try:
                        ioctl_code = hex(self.state.globals["IoControlCode"])
                    except:
                        pass

                # Check desired access for severity
                severity = "HIGH"
                exploitation = "Open handle to privileged object"
                try:
                    if hasattr(DesiredAccess, "concrete"):
                        access = self.state.solver.eval_one(DesiredAccess)
                    else:
                        access = DesiredAccess

                    # PROCESS_ALL_ACCESS = 0x1FFFFF
                    if access == 0x1FFFFF or access == 0xFFFFFFFF:
                        severity = "CRITICAL"
                        exploitation = "Open SYSTEM process handle for token stealing"
                except:
                    pass

                # Report vulnerability
                vuln = {
                    "title": "Controllable Process Handle - ObOpenObjectByPointer",
                    "description": "User controls Object parameter in ObOpenObjectByPointer",
                    "state": str(self.state),
                    "eval": {
                        "Object": str(Object)[:100],
                        "DesiredAccess": hex(access) if "access" in locals() else str(DesiredAccess)[:100],
                        "IoControlCode": ioctl_code,
                    },
                    "parameters": {
                        "tainted": True,
                        "object_ptr": str(Object)[:100],
                    },
                    "others": {
                        "severity": severity,
                        "exploitation": exploitation,
                        "technique": "Pass EPROCESS pointer of SYSTEM process to escalate privileges",
                    },
                }
                context.add_vulnerability(vuln)
                logger.debug(f"[VULN] ObOpenObjectByPointer with tainted Object pointer - {exploitation}")

        return 0  # STATUS_SUCCESS

    def _is_tainted(self, value):
        """Check if a value is tainted (user-controlled)."""
        if value is None:
            return False
        if hasattr(value, "symbolic"):
            return value.symbolic
        if hasattr(value, "variables"):
            # Check if any variable comes from user input
            for var in value.variables:
                if any(
                    target in str(var) for target in ["SystemBuffer", "Type3InputBuffer", "UserBuffer", "InputBuffer"]
                ):
                    return True
        return False


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
        "ObOpenObjectByPointer": HookObOpenObjectByPointer,
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
    "HookObOpenObjectByPointer",
]
