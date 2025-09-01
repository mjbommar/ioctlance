"""Validation context tracker to reduce false positives by tracking defensive checks."""

import logging
from typing import Any
from angr import SimState

logger = logging.getLogger(__name__)


class ValidationTracker:
    """
    Track validation operations and defensive checks to reduce false positives.

    This tracker monitors:
    - ProbeForRead/ProbeForWrite validations
    - Null pointer checks
    - Bounds checking
    - MmIsAddressValid calls
    - Safe string operations
    """

    def __init__(self):
        """Initialize validation tracking state."""
        # Track validated memory regions: addr -> (size, validation_type, state_addr)
        self.probe_validated: dict[int, tuple[int, str, int]] = {}

        # Track null-checked pointers: ptr_id -> state_addr where checked
        self.null_checked_ptrs: set[int] = set()

        # Track bounds-checked variables: var_id -> (min, max, state_addr)
        self.bounds_checked: dict[int, tuple[int, int, int]] = {}

        # Track MmIsAddressValid validated addresses
        self.mm_validated_addrs: set[int] = set()

        # Track safe string operations
        self.safe_string_ops: dict[int, str] = {}  # addr -> operation_type

        # Track reference counting
        self.ref_counted_objects: dict[int, int] = {}  # addr -> ref_count

    def track_probe_validation(self, state: SimState, addr: Any, size: Any, probe_type: str = "read"):
        """
        Track ProbeForRead/ProbeForWrite validation.

        Args:
            state: Current simulation state
            addr: Address being validated
            size: Size being validated
            probe_type: Type of probe ("read" or "write")
        """
        try:
            # Get concrete values if possible
            concrete_addr = self._make_concrete(state, addr)
            concrete_size = self._make_concrete(state, size)

            if concrete_addr is not None and concrete_size is not None:
                state_addr = state.addr if hasattr(state, "addr") else 0
                self.probe_validated[concrete_addr] = (concrete_size, probe_type, state_addr)
        except Exception as e:
            logger.debug(f"Failed to track probe validation: {e}")

    def track_null_check(self, state: SimState, ptr: Any) -> bool:
        """
        Track null pointer checks.

        Args:
            state: Current simulation state
            ptr: Pointer being checked

        Returns:
            True if pointer was checked for null
        """
        try:
            # Check if there's a constraint that ptr != 0
            for constraint in state.solver.constraints:
                if self._is_null_check_constraint(constraint, ptr):
                    ptr_id = self._get_pointer_id(ptr)
                    if ptr_id is not None:
                        self.null_checked_ptrs.add(ptr_id)
                        return True
        except Exception as e:
            logger.debug(f"Failed to track null check: {e}")
        return False

    def track_bounds_check(self, state: SimState, var: Any, min_val: Any, max_val: Any):
        """
        Track bounds checking on variables.

        Args:
            state: Current simulation state
            var: Variable being bounds-checked
            min_val: Minimum allowed value
            max_val: Maximum allowed value
        """
        try:
            var_id = self._get_variable_id(var)
            concrete_min = self._make_concrete(state, min_val)
            concrete_max = self._make_concrete(state, max_val)

            if var_id is not None and concrete_min is not None and concrete_max is not None:
                state_addr = state.addr if hasattr(state, "addr") else 0
                self.bounds_checked[var_id] = (concrete_min, concrete_max, state_addr)
        except Exception as e:
            logger.debug(f"Failed to track bounds check: {e}")

    def track_mm_validation(self, state: SimState, addr: Any):
        """
        Track MmIsAddressValid validation.

        Args:
            state: Current simulation state
            addr: Address being validated
        """
        try:
            concrete_addr = self._make_concrete(state, addr)
            if concrete_addr is not None:
                self.mm_validated_addrs.add(concrete_addr)
        except Exception as e:
            logger.debug(f"Failed to track MmIsAddressValid: {e}")

    def track_reference_count(self, state: SimState, obj_addr: Any, delta: int):
        """
        Track reference counting operations.

        Args:
            state: Current simulation state
            obj_addr: Object address
            delta: Change in reference count (+1 for increment, -1 for decrement)
        """
        try:
            concrete_addr = self._make_concrete(state, obj_addr)
            if concrete_addr is not None:
                current = self.ref_counted_objects.get(concrete_addr, 0)
                self.ref_counted_objects[concrete_addr] = current + delta
        except Exception as e:
            logger.debug(f"Failed to track reference count: {e}")

    def is_validated_access(self, state: SimState, addr: Any, size: Any, access_type: str = "read") -> bool:
        """
        Check if a memory access has been validated.

        Args:
            state: Current simulation state
            addr: Address being accessed
            size: Size of access
            access_type: Type of access ("read" or "write")

        Returns:
            True if access has been properly validated
        """
        try:
            concrete_addr = self._make_concrete(state, addr)
            concrete_size = self._make_concrete(state, size) or 1

            if concrete_addr is None:
                return False

            # Check ProbeForRead/Write validation
            for validated_addr, (validated_size, validated_type, _) in self.probe_validated.items():
                if validated_type in (access_type, "readwrite"):
                    # Check if our access is within validated range
                    if validated_addr <= concrete_addr < validated_addr + validated_size:
                        if concrete_addr + concrete_size <= validated_addr + validated_size:
                            return True

            # Check MmIsAddressValid
            if concrete_addr in self.mm_validated_addrs:
                return True

        except Exception as e:
            logger.debug(f"Failed to check validation: {e}")

        return False

    def is_null_checked(self, ptr: Any) -> bool:
        """
        Check if a pointer has been null-checked.

        Args:
            ptr: Pointer to check

        Returns:
            True if pointer was null-checked
        """
        ptr_id = self._get_pointer_id(ptr)
        return ptr_id in self.null_checked_ptrs if ptr_id is not None else False

    def is_bounds_checked(self, var: Any) -> tuple[int, int] | None:
        """
        Check if a variable has been bounds-checked.

        Args:
            var: Variable to check

        Returns:
            (min, max) tuple if bounds-checked, None otherwise
        """
        var_id = self._get_variable_id(var)
        if var_id is not None and var_id in self.bounds_checked:
            min_val, max_val, _ = self.bounds_checked[var_id]
            return (min_val, max_val)
        return None

    def is_properly_freed(self, state: SimState, addr: Any) -> bool:
        """
        Check if a free operation is legitimate (not a double-free).

        Args:
            state: Current simulation state
            addr: Address being freed

        Returns:
            True if this is a legitimate free (e.g., ref count reached 0)
        """
        try:
            concrete_addr = self._make_concrete(state, addr)
            if concrete_addr is not None:
                # Check reference counting
                ref_count = self.ref_counted_objects.get(concrete_addr, 0)
                if ref_count > 0:
                    # Still has references, this would be a bad free
                    return False

            # Check for NULL (freeing NULL is safe)
            if concrete_addr == 0:
                return True

        except Exception as e:
            logger.debug(f"Failed to check free legitimacy: {e}")

        return True  # Default to allowing the free

    def get_validation_score(self, state: SimState, vuln_type: str) -> float:
        """
        Calculate a validation score for the current state.

        Higher scores indicate more defensive checks are in place.

        Args:
            state: Current simulation state
            vuln_type: Type of vulnerability being evaluated

        Returns:
            Score from 0.0 (no validation) to 1.0 (fully validated)
        """
        score = 0.0
        factors = 0

        # Check for ProbeForRead/Write validations
        if self.probe_validated:
            score += 0.3
            factors += 1

        # Check for null checks
        if self.null_checked_ptrs:
            score += 0.2
            factors += 1

        # Check for bounds checks
        if self.bounds_checked:
            score += 0.2
            factors += 1

        # Check for MmIsAddressValid
        if self.mm_validated_addrs:
            score += 0.15
            factors += 1

        # Check for reference counting
        if self.ref_counted_objects:
            score += 0.15
            factors += 1

        # Normalize score
        if factors > 0:
            score = score / (factors * 0.2)  # Normalize to 0-1 range

        return min(1.0, score)

    def _make_concrete(self, state: SimState, value: Any) -> int | None:
        """Helper to make a value concrete if possible."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if hasattr(value, "concrete") and hasattr(state, "solver"):
            try:
                return state.solver.eval_one(value)
            except:
                return None
        return None

    def _get_pointer_id(self, ptr: Any) -> int | None:
        """Get a unique ID for a pointer."""
        if hasattr(ptr, "__hash__"):
            try:
                return hash(ptr)
            except:
                pass
        return id(ptr) if ptr is not None else None

    def _get_variable_id(self, var: Any) -> int | None:
        """Get a unique ID for a variable."""
        return self._get_pointer_id(var)

    def _is_null_check_constraint(self, constraint: Any, ptr: Any) -> bool:
        """Check if a constraint represents a null check."""
        # This would need to analyze the constraint AST
        # For now, simplified check
        try:
            if hasattr(constraint, "op") and constraint.op == "__ne__":
                if hasattr(constraint, "args"):
                    # Check if one arg is our pointer and other is 0
                    args = constraint.args
                    if len(args) == 2:
                        if (args[0] == ptr and args[1] == 0) or (args[1] == ptr and args[0] == 0):
                            return True
        except:
            pass
        return False


# Global instance for use across detectors
validation_tracker = ValidationTracker()
