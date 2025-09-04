"""Object manipulation vulnerability detector for kernel objects.

Detects vulnerabilities related to Windows kernel object manipulation:
- Tainted ObReferenceObject/ObDereferenceObject
- Reference count mismatches
- Invalid object pointer operations
- Type confusion with kernel objects
"""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class ObjectManipulationDetector(VulnerabilityDetector):
    """Detects vulnerabilities in kernel object manipulation.

    This detector identifies issues with:
    - ObReferenceObject/ObDereferenceObject with tainted pointers
    - Reference counting errors
    - Invalid object operations
    - Type confusion attacks
    """

    name = "object_manipulation"

    # Common Windows kernel object types
    KERNEL_OBJECT_TYPES = {
        "FILE_OBJECT",
        "DEVICE_OBJECT",
        "DRIVER_OBJECT",
        "ETHREAD",
        "EPROCESS",
        "KEVENT",
        "KMUTEX",
        "KSEMAPHORE",
        "TOKEN",
        "SECTION_OBJECT",
        "KEY_OBJECT",
        "DESKTOP_OBJECT",
    }

    # Functions that manipulate object references (direct reference only)
    REFERENCE_FUNCTIONS = {
        "ObReferenceObject",
        "ObReferenceObjectByName",
        "ObReferenceObjectWithTag",
        "ObfReferenceObject",
    }

    DEREFERENCE_FUNCTIONS = {
        "ObDereferenceObject",
        "ObDereferenceObjectDeferDelete",
        "ObDereferenceObjectWithTag",
        "ObfDereferenceObject",
        "ObDereferenceObjectDeferDeleteWithTag",
    }

    # Functions that get object pointers
    OBJECT_GETTER_FUNCTIONS = {
        "ObReferenceObjectByHandle",
        "ObReferenceObjectByPointer",
        "IoGetDeviceObjectPointer",
        "IoGetAttachedDevice",
        "PsLookupProcessByProcessId",
        "PsLookupThreadByThreadId",
        "ZwOpenFile",
        "ZwOpenProcess",
        "ZwOpenThread",
    }

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects kernel object manipulation vulnerabilities"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the object manipulation detector."""
        super().__init__(context)

        # Track object references per state
        self.object_refs: dict[int, dict[int, int]] = {}  # state_id -> {object_addr -> ref_count}
        self.tainted_objects: set[int] = set()  # Track tainted object addresses
        self.detected_vulns: set[tuple[int, str, str]] = set()  # Deduplication

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check state for object manipulation vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event (call, ret, etc.)
            **kwargs: Event-specific arguments

        Returns:
            Vulnerability info if detected, None otherwise
        """
        if event_type != "call":
            return None

        func_name = kwargs.get("function_name", "")

        # Check for reference operations
        if func_name in self.REFERENCE_FUNCTIONS:
            return self._check_reference(state, func_name, **kwargs)
        elif func_name in self.DEREFERENCE_FUNCTIONS:
            return self._check_dereference(state, func_name, **kwargs)
        elif func_name in self.OBJECT_GETTER_FUNCTIONS:
            return self._check_object_getter(state, func_name, **kwargs)

        return None

    def _check_reference(self, state: SimState, func_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check ObReferenceObject operations for vulnerabilities.

        Args:
            state: Current simulation state
            func_name: Name of the reference function
            **kwargs: Function arguments

        Returns:
            Vulnerability info if detected
        """
        # Get the object pointer argument (usually first argument)
        object_ptr = kwargs.get("args", [None])[0]
        if object_ptr is None:
            object_ptr = kwargs.get("object_ptr")

        if object_ptr is None:
            return None

        # Check if object pointer is tainted (user-controlled)
        if self._is_tainted(object_ptr):
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "tainted_reference", str(object_ptr)[:30])
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Tainted Object Reference",
                description=f"User-controlled object passed to {func_name}",
                state=state,
                parameters={
                    "function": func_name,
                    "object_ptr": str(object_ptr)[:100],
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "HIGH",
                    "exploitation": "Arbitrary kernel object manipulation",
                    "confidence": "HIGH",
                    "mitigation": "Validate object pointer before reference",
                    "windows_specific": "Can lead to privilege escalation via object type confusion",
                },
            )

        # Track reference count
        state_id = id(state)
        if state_id not in self.object_refs:
            self.object_refs[state_id] = {}

        # Try to get concrete address for tracking
        try:
            if hasattr(object_ptr, "concrete"):
                concrete_addr = state.solver.eval_one(object_ptr)
            else:
                concrete_addr = int(object_ptr)

            # Increment reference count
            if concrete_addr not in self.object_refs[state_id]:
                self.object_refs[state_id][concrete_addr] = 0
            self.object_refs[state_id][concrete_addr] += 1

            # Check for excessive references (potential reference count overflow)
            if self.object_refs[state_id][concrete_addr] > 100:
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "ref_overflow", hex(concrete_addr))
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Reference Count Overflow",
                    description=f"Excessive references to object at {hex(concrete_addr)}",
                    state=state,
                    parameters={
                        "function": func_name,
                        "object_addr": hex(concrete_addr),
                        "ref_count": self.object_refs[state_id][concrete_addr],
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "MEDIUM",
                        "exploitation": "Reference count overflow can lead to use-after-free",
                        "confidence": "MEDIUM",
                        "mitigation": "Limit reference operations per IOCTL",
                    },
                )
        except:
            # Can't get concrete address, skip tracking
            pass

        return None

    def _check_dereference(self, state: SimState, func_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check ObDereferenceObject operations for vulnerabilities.

        Args:
            state: Current simulation state
            func_name: Name of the dereference function
            **kwargs: Function arguments

        Returns:
            Vulnerability info if detected
        """
        # Get the object pointer argument
        object_ptr = kwargs.get("args", [None])[0]
        if object_ptr is None:
            object_ptr = kwargs.get("object_ptr")

        if object_ptr is None:
            return None

        # Check if object pointer is tainted
        if self._is_tainted(object_ptr):
            vuln_key = (state.addr if hasattr(state, "addr") else 0, "tainted_dereference", str(object_ptr)[:30])
            if vuln_key in self.detected_vulns:
                return None
            self.detected_vulns.add(vuln_key)

            return self.create_vulnerability_info(
                title="Tainted Object Dereference",
                description=f"User-controlled object passed to {func_name}",
                state=state,
                parameters={
                    "function": func_name,
                    "object_ptr": str(object_ptr)[:100],
                    "ioctl_code": self._get_ioctl_code(state),
                },
                others={
                    "severity": "HIGH",
                    "exploitation": "Can cause arbitrary object destruction",
                    "confidence": "HIGH",
                    "mitigation": "Validate object pointer before dereference",
                    "windows_specific": "Can trigger use-after-free or double-free",
                },
            )

        # Track dereference for reference counting
        state_id = id(state)
        if state_id in self.object_refs:
            try:
                if hasattr(object_ptr, "concrete"):
                    concrete_addr = state.solver.eval_one(object_ptr)
                else:
                    concrete_addr = int(object_ptr)

                # Decrement reference count
                if concrete_addr in self.object_refs[state_id]:
                    self.object_refs[state_id][concrete_addr] -= 1

                    # Check for negative reference count (over-dereference)
                    if self.object_refs[state_id][concrete_addr] < 0:
                        vuln_key = (state.addr if hasattr(state, "addr") else 0, "over_deref", hex(concrete_addr))
                        if vuln_key in self.detected_vulns:
                            return None
                        self.detected_vulns.add(vuln_key)

                        return self.create_vulnerability_info(
                            title="Object Over-Dereference",
                            description=f"Object at {hex(concrete_addr)} dereferenced more than referenced",
                            state=state,
                            parameters={
                                "function": func_name,
                                "object_addr": hex(concrete_addr),
                                "ref_count": self.object_refs[state_id][concrete_addr],
                                "ioctl_code": self._get_ioctl_code(state),
                            },
                            others={
                                "severity": "HIGH",
                                "exploitation": "Can lead to use-after-free",
                                "confidence": "HIGH",
                                "mitigation": "Ensure balanced reference/dereference",
                                "windows_specific": "May trigger BAD_REFERENCE_COUNT bugcheck",
                            },
                        )
            except:
                pass

        return None

    def _check_object_getter(self, state: SimState, func_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check functions that retrieve object pointers.

        Args:
            state: Current simulation state
            func_name: Name of the getter function
            **kwargs: Function arguments

        Returns:
            Vulnerability info if detected
        """
        # Check if handle/ID parameter is tainted
        if "Handle" in func_name or "ByProcessId" in func_name or "ByThreadId" in func_name:
            # First argument is usually the handle/ID
            handle_arg = kwargs.get("args", [None])[0]
            if handle_arg is None:
                handle_arg = kwargs.get("handle") or kwargs.get("process_id") or kwargs.get("thread_id")

            if handle_arg and self._is_tainted(handle_arg):
                vuln_key = (state.addr if hasattr(state, "addr") else 0, "tainted_handle", str(handle_arg)[:30])
                if vuln_key in self.detected_vulns:
                    return None
                self.detected_vulns.add(vuln_key)

                return self.create_vulnerability_info(
                    title="Tainted Handle/ID Access",
                    description=f"User-controlled handle/ID passed to {func_name}",
                    state=state,
                    parameters={
                        "function": func_name,
                        "handle_value": str(handle_arg)[:100],
                        "ioctl_code": self._get_ioctl_code(state),
                    },
                    others={
                        "severity": "MEDIUM",
                        "exploitation": "Can access arbitrary kernel objects",
                        "confidence": "HIGH",
                        "mitigation": "Validate handles before use",
                        "windows_specific": "May allow cross-process object access",
                    },
                )

        # Check for type confusion possibilities
        if func_name == "ObReferenceObjectByPointer":
            # Check the ObjectType parameter (usually 3rd argument)
            args = kwargs.get("args", [])
            if len(args) >= 3:
                object_type = args[2]
                if self._is_tainted(object_type):
                    vuln_key = (state.addr if hasattr(state, "addr") else 0, "type_confusion", func_name)
                    if vuln_key in self.detected_vulns:
                        return None
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title="Object Type Confusion",
                        description="User-controlled object type parameter",
                        state=state,
                        parameters={
                            "function": func_name,
                            "ioctl_code": self._get_ioctl_code(state),
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "Type confusion can bypass security checks",
                            "confidence": "HIGH",
                            "mitigation": "Validate object types",
                            "windows_specific": "Can cast objects to incorrect types",
                        },
                    )

        return None

    def get_statistics(self) -> dict[str, Any]:
        """Get detector statistics.

        Returns:
            Statistics dictionary
        """
        total_refs = sum(len(refs) for refs in self.object_refs.values())
        return {
            "tracked_states": len(self.object_refs),
            "total_object_refs": total_refs,
            "tainted_objects": len(self.tainted_objects),
            "detected_vulnerabilities": len(self.detected_vulns),
        }


# Register the detector
detector_registry.register(ObjectManipulationDetector)
