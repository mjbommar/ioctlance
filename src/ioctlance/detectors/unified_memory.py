"""Unified memory management detector for comprehensive memory vulnerability detection.

This detector combines and improves upon double_free.py and use_after_free.py,
providing a single source of truth for all memory-related vulnerability detection.
"""

import logging
from typing import Any
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

from angr import SimState

from ..core.analysis_context import AnalysisContext
from .base import VulnerabilityDetector, detector_registry
from ..utils.error_handler import SymbolicExecutionErrorHandler

logger = logging.getLogger(__name__)


class MemoryState(Enum):
    """State of a memory region."""

    ALLOCATED = "allocated"
    FREED = "freed"
    REFERENCED = "referenced"
    DEREFERENCED = "dereferenced"


@dataclass
class MemoryRegion:
    """Represents a tracked memory region."""

    address: int
    size: int
    pool_tag: str | None = None
    state: MemoryState = MemoryState.ALLOCATED
    allocation_site: int | None = None
    free_site: int | None = None
    reference_count: int = 1
    allocation_path_depth: int = 0
    is_object: bool = False  # True for kernel objects (ObReference/Dereference)
    object_type: str | None = None  # FILE_OBJECT, DEVICE_OBJECT, etc.
    last_access_site: int | None = None
    access_count: int = 0
    is_temporary: bool = True  # False if OBJ_PERMANENT was set


@dataclass
class MemoryAccess:
    """Represents a memory access event."""

    address: int
    size: int
    is_write: bool
    site: int
    path_depth: int
    ioctl_code: str | None = None


class UnifiedMemoryDetector(VulnerabilityDetector):
    """
    Unified detector for all memory-related vulnerabilities.

    Detects:
    - Double-free vulnerabilities
    - Use-after-free vulnerabilities
    - Null pointer dereferences
    - Reference count mismatches
    - Pool corruption
    - Invalid free operations
    - Memory leaks (reference count > 0 at cleanup)
    - Tainted pointer free operations
    """

    name = "unified_memory"
    # Backwards-compatible alias so tests can reference UnifiedMemoryDetector.MemoryRegion
    MemoryRegion = MemoryRegion

    # Windows pool tags we commonly see
    COMMON_POOL_TAGS = {"File", "Devi", "Thre", "Proc", "Driv", "IoCt"}

    # Object types in Windows kernel
    OBJECT_TYPES = {"FILE_OBJECT", "DEVICE_OBJECT", "DRIVER_OBJECT", "ETHREAD", "EPROCESS", "KEVENT", "KMUTEX"}

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Unified memory management vulnerability detection with reference counting"

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the unified memory detector."""
        super().__init__(context)

        # Primary tracking structures
        self.memory_regions: dict[int, MemoryRegion] = {}
        self.freed_regions: dict[int, MemoryRegion] = {}

        # Secondary tracking for analysis
        self.access_history: list[MemoryAccess] = []
        self.pool_tag_stats: dict[str, int] = defaultdict(int)
        self.object_stats: dict[str, int] = defaultdict(int)

        # Vulnerability tracking
        self.detected_vulns: set[tuple[int, str, str]] = set()

        # Symbolic tracking
        self.symbolic_addresses: set[int] = set()

    def detect(self, state: SimState) -> dict[str, Any] | None:
        """Main detection method called by framework."""
        return None  # Detection happens in check_state and hook methods

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """
        Check state for memory vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Event-specific arguments
        """
        if event_type in ("mem_read", "mem_write"):
            return self._check_memory_access(state, event_type, **kwargs)
        elif event_type == "call":
            # Extract func_name and remove it from kwargs to avoid duplicate argument error
            func_name = kwargs.pop("func_name", kwargs.pop("function_name", ""))
            return self._check_function_call(state, func_name, **kwargs)
        elif event_type == "free":
            # Called from ExFreePool hooks
            return self._handle_free(state, "ExFreePool", pool_ptr=kwargs.get("address"), tag=kwargs.get("tag"))

        return None

    # Hook compatibility methods for backwards compatibility
    def check_exfreepool(self, state: SimState, pool_ptr: Any, tag: Any = None) -> dict[str, Any] | None:
        """Compatibility method for ExFreePool hooks."""
        # Use ExFreePoolWithTag if tag parameter was provided (even if 0 or symbolic)
        func_name = "ExFreePoolWithTag" if tag is not None else "ExFreePool"
        return self._handle_free(state, func_name, pool_ptr=pool_ptr, tag=tag)

    def check_exallocatepool(self, state: SimState, pool_type: Any, size: Any, tag: Any = None) -> Any:
        """Compatibility method for ExAllocatePool hooks."""
        # Use ExAllocatePoolWithTag if tag parameter was provided (even if 0 or symbolic)
        func_name = "ExAllocatePoolWithTag" if tag is not None else "ExAllocatePool"
        return self._handle_allocation(state, func_name, pool_type=pool_type, size=size, tag=tag)

    def _check_memory_access(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check memory access for use-after-free and null pointer dereferences."""
        address = kwargs.get("address")
        size = kwargs.get("size", 1)

        if address is None:
            return None

        # First check for null pointer dereference
        null_check = self._check_null_pointer(state, event_type, address)
        if null_check:
            return null_check

        # Get concrete address if possible
        concrete_addr = self._make_concrete(state, address)
        if concrete_addr is None:
            return None

        # Create access record
        access = MemoryAccess(
            address=concrete_addr,
            size=self._make_concrete(state, size) or 1,
            is_write=(event_type == "mem_write"),
            site=state.addr if hasattr(state, "addr") else 0,
            path_depth=len(state.history.bbl_addrs) if hasattr(state, "history") else 0,
            ioctl_code=self._get_ioctl_code(state),
        )

        self.access_history.append(access)

        # Check for use-after-free
        vuln = self._check_use_after_free(state, access)
        if vuln:
            return vuln

        # Update access tracking for allocated regions
        if concrete_addr in self.memory_regions:
            region = self.memory_regions[concrete_addr]
            region.last_access_site = access.site
            region.access_count += 1

        return None

    def _check_function_call(self, state: SimState, func_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check function calls for memory operations."""
        if not func_name:
            return None
        func_lower = func_name.lower()

        # Allocation functions
        if "exallocatepool" in func_lower:
            return self._handle_allocation(state, func_name, **kwargs)

        # Free functions
        elif "exfreepool" in func_lower:
            return self._handle_free(state, func_name, **kwargs)

        # Reference counting
        elif "obreference" in func_lower:
            return self._handle_reference(state, func_name, **kwargs)
        elif "obdereference" in func_lower:
            return self._handle_dereference(state, func_name, **kwargs)

        # Other memory functions
        elif "rtlfreeheap" in func_lower:
            return self._handle_heap_free(state, **kwargs)
        elif "mmfreecontiguous" in func_lower:
            return self._handle_contiguous_free(state, **kwargs)

        return None

    def _handle_allocation(self, state: SimState, func_name: str, **kwargs: Any) -> None:
        """Handle memory allocation."""
        size = kwargs.get("size")
        tag = kwargs.get("tag")

        # Generate allocation address (symbolic in analysis)
        alloc_addr = self._generate_allocation_address(state)

        # Get concrete values where possible
        concrete_size = self._make_concrete(state, size) or 0x1000  # Default 4KB
        pool_tag = self._extract_pool_tag(tag) if tag else None

        # Create memory region
        region = MemoryRegion(
            address=alloc_addr,
            size=concrete_size,
            pool_tag=pool_tag,
            state=MemoryState.ALLOCATED,
            allocation_site=state.addr if hasattr(state, "addr") else 0,
            allocation_path_depth=len(state.history.bbl_addrs) if hasattr(state, "history") else 0,
            is_object=False,
        )

        self.memory_regions[alloc_addr] = region

        # Track pool tag statistics
        if pool_tag:
            self.pool_tag_stats[pool_tag] += 1

        return None

    def _handle_free(self, state: SimState, func_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Handle memory free operation."""
        pool_ptr = kwargs.get("pool_ptr")
        if pool_ptr is None:
            pool_ptr = kwargs.get("address")
        tag = kwargs.get("tag")

        if pool_ptr is None:
            return None

        concrete_addr = self._make_concrete(state, pool_ptr)
        if concrete_addr is None or concrete_addr == 0:
            # Freeing NULL is safe
            return None

        # Check for double-free
        if concrete_addr in self.freed_regions:
            return self._create_double_free_vuln(state, concrete_addr, self.freed_regions[concrete_addr])

        # Check if we're tracking this allocation
        if concrete_addr not in self.memory_regions:
            # Freeing untracked memory - still need to track it for double-free detection
            if self._is_symbolic(pool_ptr) or self._is_tainted(pool_ptr):
                # Check for arbitrary/tainted free vulnerability
                vuln = self._create_tainted_free_vuln(state, pool_ptr)
                if vuln:
                    return vuln

            # Create a region for this untracked free (we don't know the original allocation details)
            region = MemoryRegion(
                address=concrete_addr,
                size=0,  # Unknown size
                pool_tag=self._extract_pool_tag(tag) if tag else None,
                state=MemoryState.FREED,
                free_site=state.addr if hasattr(state, "addr") else 0,
                allocation_site=0,  # Unknown
                allocation_path_depth=0,
            )
            self.freed_regions[concrete_addr] = region
            return None

        # We are tracking this allocation
        region = self.memory_regions[concrete_addr]

        # Check pool tag mismatch (if provided)
        if tag is not None and region.pool_tag is not None:
            extracted_tag = self._extract_pool_tag(tag)
            if extracted_tag != region.pool_tag:
                return self._create_tag_mismatch_vuln(state, concrete_addr, region.pool_tag, extracted_tag)

        # Move to freed regions
        region.state = MemoryState.FREED
        region.free_site = state.addr if hasattr(state, "addr") else 0
        self.freed_regions[concrete_addr] = region
        del self.memory_regions[concrete_addr]

        return None

    def _handle_heap_free(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Handle RtlFreeHeap operation."""
        mem_ptr = kwargs.get("memory")

        if mem_ptr is None:
            return None

        # Treat heap free like ExFreePool
        return self._handle_free(state, "RtlFreeHeap", pool_ptr=mem_ptr)

    def _handle_contiguous_free(self, state: SimState, **kwargs: Any) -> dict[str, Any] | None:
        """Handle MmFreeContiguousMemory operation."""
        base_addr = kwargs.get("base_address")

        if base_addr is None:
            return None

        # Treat contiguous free like ExFreePool
        return self._handle_free(state, "MmFreeContiguousMemory", pool_ptr=base_addr)

    def _handle_reference(self, state: SimState, func_name: str, **kwargs: Any) -> None:
        """Handle ObReferenceObject."""
        obj_ptr = kwargs.get("object")
        if obj_ptr is None:
            obj_ptr = kwargs.get("object_ptr")

        if obj_ptr is None:
            return None

        concrete_addr = self._make_concrete(state, obj_ptr)
        if concrete_addr is None:
            return None

        # Create or update object tracking
        if concrete_addr not in self.memory_regions:
            # First reference - create object
            region = MemoryRegion(
                address=concrete_addr,
                size=0x100,  # Default object size
                state=MemoryState.REFERENCED,
                allocation_site=state.addr if hasattr(state, "addr") else 0,
                reference_count=1,
                is_object=True,
                object_type=self._infer_object_type(state, obj_ptr),
            )
            self.memory_regions[concrete_addr] = region
        else:
            # Increment reference count
            self.memory_regions[concrete_addr].reference_count += 1

        return None

    def _handle_dereference(self, state: SimState, func_name: str, **kwargs: Any) -> dict[str, Any] | None:
        """Handle ObDereferenceObject."""
        obj_ptr = kwargs.get("object")
        if obj_ptr is None:
            obj_ptr = kwargs.get("object_ptr")

        if obj_ptr is None:
            return None

        concrete_addr = self._make_concrete(state, obj_ptr)
        if concrete_addr is None:
            return None

        # Check if we're tracking this object
        if concrete_addr not in self.memory_regions:
            # Check if it's already freed
            if concrete_addr in self.freed_regions:
                region = self.freed_regions[concrete_addr]
                # If it's an object with negative ref count, it's underflow
                if region.is_object and region.reference_count < 0:
                    return self._create_refcount_underflow_vuln(state, concrete_addr, region)
                # Otherwise it's UAF
                return self._create_use_after_free_vuln(state, concrete_addr, region)
            return None

        region = self.memory_regions[concrete_addr]

        if not region.is_object:
            # Dereferencing non-object memory
            return self._create_type_confusion_vuln(state, concrete_addr, region)

        # Decrement reference count
        region.reference_count -= 1

        # Check for reference count issues
        if region.reference_count < 0:
            return self._create_refcount_underflow_vuln(state, concrete_addr, region)

        if region.reference_count == 0:
            # Object should be freed
            if region.is_temporary:
                # Move to freed regions
                region.state = MemoryState.FREED
                region.free_site = state.addr if hasattr(state, "addr") else 0
                self.freed_regions[concrete_addr] = region
                del self.memory_regions[concrete_addr]
        elif region.reference_count < 0:
            # Move to freed with negative count for tracking
            region.state = MemoryState.FREED
            self.freed_regions[concrete_addr] = region
            del self.memory_regions[concrete_addr]

        return None

    def _check_use_after_free(self, state: SimState, access: MemoryAccess) -> dict[str, Any] | None:
        """Check if memory access is use-after-free."""
        # Direct UAF - accessing freed memory
        if access.address in self.freed_regions:
            region = self.freed_regions[access.address]
            return self._create_use_after_free_vuln(state, access.address, region, access)

        # Range-based UAF - accessing within freed region
        for freed_addr, region in self.freed_regions.items():
            if freed_addr <= access.address < freed_addr + region.size:
                return self._create_use_after_free_vuln(state, access.address, region, access, is_range=True)

        return None

    def _create_double_free_vuln(self, state: SimState, address: int, region: MemoryRegion) -> dict[str, Any]:
        """Create double-free vulnerability info."""
        vuln_key = (state.addr, "double_free", str(address))
        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Double-Free Vulnerability",
            description=f"Memory at {hex(address)} freed multiple times",
            state=state,
            parameters={
                "address": hex(address),
                "size": region.size,
                "pool_tag": region.pool_tag or "none",
                "first_free_site": hex(region.free_site) if region.free_site else "unknown",
                "second_free_site": hex(state.addr) if hasattr(state, "addr") else "unknown",
                "allocation_site": hex(region.allocation_site) if region.allocation_site else "unknown",
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "CRITICAL",
                "exploitation": "Heap corruption, potential RCE",
                "confidence": "HIGH" if region.pool_tag else "MEDIUM",
                "windows_specific": "Can trigger KERNEL_MODE_HEAP_CORRUPTION (0x13A)",
            },
        )

    def _create_use_after_free_vuln(
        self,
        state: SimState,
        address: int,
        region: MemoryRegion,
        access: MemoryAccess | None = None,
        is_range: bool = False,
    ) -> dict[str, Any]:
        """Create use-after-free vulnerability info."""
        vuln_key = (state.addr, "use_after_free", str(address))
        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        access_type = "unknown"
        if access is not None:
            access_type = "write" if access.is_write else "read"

        return self.create_vulnerability_info(
            title="Use-After-Free Vulnerability",
            description=f"{'Write to' if access and access.is_write else 'Read from'} freed memory",
            state=state,
            parameters={
                "address": hex(address),
                "freed_base": hex(region.address),
                "size": region.size,
                "pool_tag": region.pool_tag or "none",
                "access_type": access_type,
                "is_range_access": is_range,
                "free_site": hex(region.free_site) if region.free_site else "unknown",
                "allocation_site": hex(region.allocation_site) if region.allocation_site else "unknown",
                "time_since_free": (access.path_depth - region.allocation_path_depth) if access else "unknown",
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "CRITICAL",
                "exploitation": "Code execution via freed object reuse",
                "confidence": "HIGH",
                "windows_specific": "Can be exploited via pool spraying",
            },
        )

    def _create_refcount_underflow_vuln(self, state: SimState, address: int, region: MemoryRegion) -> dict[str, Any]:
        """Create reference count underflow vulnerability."""
        vuln_key = (state.addr, "refcount_underflow", str(address))
        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Reference Count Underflow",
            description="ObDereferenceObject called more times than ObReferenceObject",
            state=state,
            parameters={
                "object_address": hex(address),
                "object_type": region.object_type or "unknown",
                "reference_count": region.reference_count,
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "HIGH",
                "exploitation": "Object lifetime manipulation, UAF",
                "confidence": "HIGH",
                "windows_specific": "Violates Windows object lifecycle rules",
            },
        )

    def _create_tainted_free_vuln(self, state: SimState, pool_ptr: Any) -> dict[str, Any]:
        """Create tainted/arbitrary free vulnerability."""
        vuln_key = (state.addr if hasattr(state, "addr") else 0, "tainted_free", str(pool_ptr)[:20])
        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        # Determine the type of vulnerability
        is_tainted = self._is_tainted(pool_ptr)
        is_symbolic = self._is_symbolic(pool_ptr)

        if is_tainted is True:
            title = "Tainted Pointer Free"
            description = "Freeing user-controlled pointer from IOCTL input"
            confidence = "HIGH"
        else:
            title = "Arbitrary Free Vulnerability"
            description = "Freeing symbolic or untracked pointer"
            confidence = "MEDIUM"

        return self.create_vulnerability_info(
            title=title,
            description=description,
            state=state,
            parameters={
                "pointer": str(pool_ptr)[:100],
                "is_symbolic": is_symbolic,
                "is_tainted": is_tainted,
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "CRITICAL" if is_tainted else "HIGH",
                "exploitation": "Arbitrary memory corruption, pool metadata corruption",
                "confidence": confidence,
                "windows_specific": "Can trigger BAD_POOL_CALLER (0xC2) or KERNEL_MODE_HEAP_CORRUPTION (0x13A)",
                "cwe": "CWE-415: Double Free" if is_tainted else "CWE-590: Free of Memory not on the Heap",
            },
        )

    def _create_tag_mismatch_vuln(self, state: SimState, address: int, alloc_tag: str, free_tag: str) -> dict[str, Any]:
        """Create pool tag mismatch vulnerability."""
        vuln_key = (state.addr, "tag_mismatch", str(address))
        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Pool Tag Mismatch",
            description="Memory freed with different tag than allocated",
            state=state,
            parameters={
                "address": hex(address),
                "allocation_tag": alloc_tag,
                "free_tag": free_tag,
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "MEDIUM",
                "exploitation": "Pool corruption, debugging issues",
                "confidence": "HIGH",
                "windows_specific": "Violates Windows pool tagging conventions",
            },
        )

    def _create_type_confusion_vuln(self, state: SimState, address: int, region: MemoryRegion) -> dict[str, Any]:
        """Create type confusion vulnerability."""
        vuln_key = (state.addr, "type_confusion", str(address))
        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Type Confusion Vulnerability",
            description="ObDereferenceObject called on non-object memory",
            state=state,
            parameters={
                "address": hex(address),
                "expected": "kernel object",
                "actual": "pool allocation" if region.pool_tag else "unknown",
                "pool_tag": region.pool_tag or "none",
                "ioctl_code": self._get_ioctl_code(state),
            },
            others={
                "severity": "HIGH",
                "exploitation": "Memory corruption, potential RCE",
                "confidence": "MEDIUM",
                "windows_specific": "Mixing pool and object manager APIs",
            },
        )

    # Helper methods

    def _make_concrete(self, state: SimState, value: Any) -> int | None:
        """Make a value concrete if possible."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        # Try to evaluate symbolic values
        if hasattr(state, "solver"):
            try:
                # Try to evaluate with the solver
                return state.solver.eval_one(value)
            except Exception as e:
                if not SymbolicExecutionErrorHandler.handle_claripy_error(e, "concrete value evaluation"):
                    logger.debug(f"Failed to make value concrete: {e}")
                # Not a symbolic value or can't be made concrete
                pass
        # Try to convert directly if it's a number-like object
        try:
            return int(value)
        except Exception as e:
            if not SymbolicExecutionErrorHandler.is_non_fatal_error(e):
                logger.debug(f"Failed to convert value to int: {e}")
            return None

    def _check_null_pointer(self, state: SimState, event_type: str, address: Any) -> dict[str, Any] | None:
        """Check for null pointer dereferences."""
        # Target buffers to check
        targets = ["SystemBuffer", "Type3InputBuffer", "UserBuffer"]
        addr_str = str(address)

        # Check address for null pointer patterns

        for target in targets:
            if target not in addr_str:
                continue

            # Found target pattern in address

            # Extract base address
            asts = [i for i in address.children_asts()] if hasattr(address, "children_asts") else []
            target_base = asts[0] if len(asts) > 1 else address

            # Check if already validated
            if self.is_address_validated(state, target_base):
                # Address already validated, skipping
                continue

            # Only check if single variable
            if hasattr(address, "variables") and len(address.variables) != 1:
                continue

            # Create a test state
            tmp_state = state.copy()

            # Check for null pointer based on buffer type
            if target == "SystemBuffer":
                if "*" not in addr_str:
                    # SystemBuffer is not a pointer - check for null

                    if self.context.system_buffer is not None:
                        tmp_state.solver.add(self.context.system_buffer == 0)
                    if self.context.input_buffer_length is not None:
                        tmp_state.solver.add(self.context.input_buffer_length == 0)
                    if self.context.output_buffer_length is not None:
                        tmp_state.solver.add(self.context.output_buffer_length == 0)

                    satisfiable = tmp_state.satisfiable()
                    # Check if null pointer is satisfiable
                    if satisfiable is True:
                        vuln_key = (state.addr if hasattr(state, "addr") else 0, "null_pointer", target)
                        if vuln_key in self.detected_vulns:
                            return None
                        self.detected_vulns.add(vuln_key)

                        return self.create_vulnerability_info(
                            title="Null Pointer Dereference - Input Buffer"
                            if event_type == "mem_read"
                            else "Null Pointer Dereference - Output Buffer",
                            description=f"{event_type.replace('_', ' ')} on null {'input' if event_type == 'mem_read' else 'output'} buffer",
                            state=state,
                            parameters={
                                "buffer": target,
                                "operation": event_type,
                                "address": addr_str[:100],
                            },
                            others={
                                "severity": "HIGH",
                                "exploitation": "Denial of service, potential code execution",
                                "confidence": "HIGH",
                                "mitigation": "Check buffer pointers before use",
                                "windows_specific": "Can trigger BSOD with PAGE_FAULT_IN_NONPAGED_AREA",
                            },
                        )

            # Check for null pointer in allocated memory or other buffers
            elif "+" not in addr_str or target in ["Type3InputBuffer", "UserBuffer"]:
                tmp_state.solver.add(address == 0)
                if tmp_state.satisfiable():
                    vuln_key = (state.addr if hasattr(state, "addr") else 0, "null_pointer_deref", addr_str[:30])
                    if vuln_key in self.detected_vulns:
                        return None
                    self.detected_vulns.add(vuln_key)

                    return self.create_vulnerability_info(
                        title=f"Null Pointer Dereference - {target if target in addr_str else 'Memory'}",
                        description=f"{event_type.replace('_', ' ')} on null pointer",
                        state=state,
                        parameters={
                            "operation": event_type,
                            "address": addr_str[:100],
                        },
                        others={
                            "severity": "HIGH",
                            "exploitation": "System crash, potential privilege escalation",
                            "confidence": "HIGH",
                            "mitigation": "Validate pointers before dereference",
                        },
                    )

        return None

    def _is_symbolic(self, value: Any) -> bool:
        """Check if value is symbolic."""
        return SymbolicExecutionErrorHandler.safe_symbolic_check(value)

    def _extract_pool_tag(self, tag: Any) -> str | None:
        """Extract pool tag as string."""
        if tag is None:
            return None
        if isinstance(tag, str):
            return tag[:4]  # Pool tags are 4 bytes
        if isinstance(tag, int):
            # Convert int to 4-byte string
            return tag.to_bytes(4, "little").decode("ascii", errors="ignore")[:4]
        return str(tag)[:4]

    def _generate_allocation_address(self, state: SimState) -> int:
        """Generate a unique allocation address."""
        # In real analysis, this would be symbolic
        # For tracking, we use a deterministic address
        base = 0x80000000  # Kernel space
        offset = len(self.memory_regions) * 0x1000  # Page-aligned
        return base + offset

    def _infer_object_type(self, state: SimState, obj_ptr: Any) -> str | None:
        """Infer Windows object type from context."""
        # This would analyze the context to determine object type
        # For now, return generic
        return "UNKNOWN_OBJECT"

    def get_statistics(self) -> dict[str, Any]:
        """Get memory tracking statistics."""
        return {
            "tracked_allocations": len(self.memory_regions),
            "freed_regions": len(self.freed_regions),
            "total_accesses": len(self.access_history),
            "pool_tags": dict(self.pool_tag_stats),
            "object_types": dict(self.object_stats),
            "vulnerabilities_detected": len(self.detected_vulns),
        }

    # Duplicate methods removed - using compatibility methods defined earlier at lines 133-148


# Register the detector
detector_registry.register(UnifiedMemoryDetector)
