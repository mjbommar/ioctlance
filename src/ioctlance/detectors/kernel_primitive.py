"""Kernel primitive detector for IOCTLance."""

import logging
from typing import Any
from angr import SimState

from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class KernelPrimitiveDetector(VulnerabilityDetector):
    """Detects kernel exploitation primitives like arbitrary increment/decrement."""

    def __init__(self, context):
        """Initialize kernel primitive detector."""
        super().__init__(context)
        self.detected_vulns = set()
        self.tracked_operations = {}  # Track increment/decrement operations

    @property
    def name(self) -> str:
        """Get detector name."""
        return "kernel_primitive"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects kernel exploitation primitives including arbitrary increment, decrement, and bit operations"

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for kernel exploitation primitives.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Event-specific data

        Returns:
            Vulnerability info if found, None otherwise
        """
        if event_type == "mem_write":
            address = kwargs.get("address")
            value = kwargs.get("value")
            size = kwargs.get("size", 0)
            if address is not None and value is not None:
                # Remove address, value, size from kwargs to avoid duplicate argument error
                filtered_kwargs = {k: v for k, v in kwargs.items() if k not in ['address', 'value', 'size']}
                return self._check_arbitrary_primitive(state, address, value, size, **filtered_kwargs)
        elif event_type == "function_call":
            return self._check_interlocked_operations(state, **kwargs)

        return None

    def _check_arbitrary_primitive(self, state: SimState, address: Any, value: Any,
                                  size: int, **kwargs: Any) -> dict[str, Any] | None:
        """Check for arbitrary increment/decrement primitives.

        Args:
            state: Current simulation state
            address: Memory address being written
            value: Value being written
            size: Size of write

        Returns:
            Vulnerability info if found, None otherwise
        """
        # Check if we're modifying memory at a user-controlled address
        if not self._is_tainted(address):
            return None

        try:
            # Check if this is an increment/decrement operation
            primitive_type = self._detect_primitive_type(state, address, value)

            if primitive_type:
                # Check if the operation gives useful primitive
                if self._is_exploitable_primitive(state, address, value, primitive_type):
                    return self._create_primitive_vuln(state, address, value, primitive_type)

            # Check for arbitrary OR/AND/XOR operations
            bitop_type = self._detect_bitop_primitive(state, address, value)
            if bitop_type:
                return self._create_primitive_vuln(state, address, value, bitop_type)

        except Exception as e:
            logger.debug(f"Error checking kernel primitive: {e}")

        return None

    def _check_interlocked_operations(self, state: SimState, function_name: str,
                                     **kwargs: Any) -> dict[str, Any] | None:
        """Check for vulnerable interlocked operations.

        Args:
            state: Current simulation state
            function_name: Name of function being called

        Returns:
            Vulnerability info if found, None otherwise
        """
        interlocked_functions = {
            "InterlockedIncrement", "InterlockedDecrement",
            "InterlockedAdd", "InterlockedExchange",
            "InterlockedCompareExchange", "InterlockedOr",
            "InterlockedAnd", "InterlockedXor",
            "_InterlockedIncrement", "_InterlockedDecrement",
            "_InterlockedAdd", "_InterlockedExchange"
        }

        if function_name not in interlocked_functions:
            return None

        try:
            # Check if target address is user-controlled
            if hasattr(state.regs, 'rcx'):
                target_addr = state.regs.rcx  # First argument in x64
            elif hasattr(state.regs, 'rdi'):
                target_addr = state.regs.rdi  # First argument in System V
            else:
                return None

            if self._is_tainted(target_addr):
                operation = function_name.replace("Interlocked", "").replace("_", "").lower()
                return self._create_interlocked_vuln(state, function_name, target_addr, operation)

        except Exception as e:
            logger.debug(f"Error checking interlocked operation: {e}")

        return None

    def _detect_primitive_type(self, state: SimState, address: Any, value: Any) -> str | None:
        """Detect if this is an increment/decrement primitive.

        Args:
            state: Current simulation state
            address: Target address
            value: New value being written

        Returns:
            Type of primitive or None
        """
        try:
            # Try to get previous value at this address
            if address in self.tracked_operations:
                prev_value = self.tracked_operations[address]

                # Check for increment
                if self._is_increment(prev_value, value):
                    return "increment"
                # Check for decrement
                elif self._is_decrement(prev_value, value):
                    return "decrement"

            # Track this operation for future comparison
            if hasattr(address, 'concrete'):
                concrete_addr = state.solver.eval(address)
                self.tracked_operations[concrete_addr] = value

        except:
            pass

        return None

    def _detect_bitop_primitive(self, state: SimState, address: Any, value: Any) -> str | None:
        """Detect bitwise operation primitives.

        Args:
            state: Current simulation state
            address: Target address
            value: New value being written

        Returns:
            Type of bit operation or None
        """
        try:
            if hasattr(value, 'op'):
                # Check for OR operation
                if value.op == 'Or':
                    return "arbitrary_or"
                # Check for AND operation
                elif value.op == 'And':
                    return "arbitrary_and"
                # Check for XOR operation
                elif value.op == 'Xor':
                    return "arbitrary_xor"
        except:
            pass

        return None

    def _is_increment(self, prev_value: Any, new_value: Any) -> bool:
        """Check if this is an increment operation.

        Args:
            prev_value: Previous value
            new_value: New value

        Returns:
            True if increment detected
        """
        try:
            # Check symbolic expressions
            if hasattr(new_value, 'op') and new_value.op == 'Add':
                # Check if it's prev + 1 or prev + small_value
                if len(new_value.args) == 2:
                    arg1, arg2 = new_value.args
                    if arg1 == prev_value or arg2 == prev_value:
                        return True
        except:
            pass

        return False

    def _is_decrement(self, prev_value: Any, new_value: Any) -> bool:
        """Check if this is a decrement operation.

        Args:
            prev_value: Previous value
            new_value: New value

        Returns:
            True if decrement detected
        """
        try:
            # Check symbolic expressions
            if hasattr(new_value, 'op') and new_value.op == 'Sub':
                # Check if it's prev - 1 or prev - small_value
                if len(new_value.args) == 2:
                    arg1, arg2 = new_value.args
                    if arg1 == prev_value:
                        return True
        except:
            pass

        return False

    def _is_exploitable_primitive(self, state: SimState, address: Any,
                                 value: Any, primitive_type: str) -> bool:
        """Check if the primitive is exploitable.

        Args:
            state: Current simulation state
            address: Target address
            value: Value being written
            primitive_type: Type of primitive

        Returns:
            True if exploitable
        """
        # Check if we can control:
        # 1. The target address (already checked via _is_tainted)
        # 2. The increment/decrement amount (for advanced primitives)

        # Check if this could target critical structures
        critical_targets = self._check_critical_targets(state, address)
        if critical_targets:
            return True

        # Check if we can chain multiple primitives
        if self._can_chain_primitives(state, address):
            return True

        return False

    def _check_critical_targets(self, state: SimState, address: Any) -> bool:
        """Check if address could target critical kernel structures.

        Args:
            state: Current simulation state
            address: Target address

        Returns:
            True if critical target possible
        """
        # Check if address could point to:
        # - Reference counts (could cause UAF)
        # - Privilege/security tokens
        # - Lock counts
        # - Size fields (could cause overflows)

        # This is a heuristic - in practice would need more analysis
        return True  # Conservative: assume any controlled write is critical

    def _can_chain_primitives(self, state: SimState, address: Any) -> bool:
        """Check if multiple primitives can be chained.

        Args:
            state: Current simulation state
            address: Target address

        Returns:
            True if chaining possible
        """
        # Check if we've seen multiple primitive operations
        # that could be combined for exploitation
        return len(self.tracked_operations) > 1

    def _is_tainted(self, value: Any) -> bool:
        """Check if value is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if tainted
        """
        if value is None:
            return False

        # Check for symbolic variables from user input
        if hasattr(value, 'symbolic') and value.symbolic:
            for var in value.variables:
                var_name = str(var).lower()
                if 'input' in var_name or 'buffer' in var_name or 'ioctl' in var_name:
                    return True

        return False

    def _create_primitive_vuln(self, state: SimState, address: Any,
                              value: Any, primitive_type: str) -> dict[str, Any]:
        """Create kernel primitive vulnerability info.

        Args:
            state: Current simulation state
            address: Target address
            value: Value being written
            primitive_type: Type of primitive

        Returns:
            Vulnerability information
        """
        vuln_key = (
            state.addr if hasattr(state, 'addr') else 0,
            primitive_type,
            str(address)[:30]
        )

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        severity_map = {
            "increment": "HIGH",
            "decrement": "HIGH",
            "arbitrary_or": "MEDIUM",
            "arbitrary_and": "MEDIUM",
            "arbitrary_xor": "HIGH",
        }

        return self.create_vulnerability_info(
            title=f"Kernel Primitive - Arbitrary {primitive_type.replace('_', ' ').title()}",
            description=f"Arbitrary {primitive_type} primitive at user-controlled address",
            state=state,
            severity=severity_map.get(primitive_type, "MEDIUM"),
            parameters={
                "type": primitive_type,
                "address": str(address)[:100],
                "value": str(value)[:100],
                "exploitable": "YES"
            }
        )

    def _create_interlocked_vuln(self, state: SimState, function_name: str,
                                target_addr: Any, operation: str) -> dict[str, Any]:
        """Create interlocked operation vulnerability info.

        Args:
            state: Current simulation state
            function_name: Interlocked function name
            target_addr: Target address
            operation: Type of operation

        Returns:
            Vulnerability information
        """
        vuln_key = (
            state.addr if hasattr(state, 'addr') else 0,
            "interlocked_" + operation,
            function_name
        )

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title=f"Kernel Primitive - Arbitrary Interlocked {operation.title()}",
            description=f"User-controlled address passed to {function_name}",
            state=state,
            severity="HIGH",
            parameters={
                "function": function_name,
                "operation": operation,
                "target_address": str(target_addr)[:100],
                "exploitable": "YES"
            }
        )


# Register detector
detector_registry.register(KernelPrimitiveDetector)
