"""Vulnerability detectors for IOCTLance."""

from .base import VulnerabilityDetector, detector_registry

# Import all detector modules to trigger their self-registration
# Each detector module registers itself with detector_registry at module load time
from . import (
    file_operations,
    format_string,
    heap_buffer_overflow,
    information_disclosure,
    integer_overflow,
    ioctl_validation,
    kernel_primitive,
    object_manipulation,
    race_condition,
    stack_buffer_overflow,
    symlink_attack,
    unified_input_validation,
    unified_memory,
    unified_privilege_escalation,
)

# Re-export detector classes for backward compatibility
from .file_operations import FileOperationDetector
from .format_string import FormatStringDetector
from .heap_buffer_overflow import HeapBufferOverflowDetector
from .information_disclosure import InformationDisclosureDetector
from .integer_overflow import IntegerOverflowDetector
from .ioctl_validation import IOCTLValidationDetector
from .kernel_primitive import KernelPrimitiveDetector
from .object_manipulation import ObjectManipulationDetector
from .race_condition import RaceConditionDetector
from .stack_buffer_overflow import StackBufferOverflowDetector
from .symlink_attack import SymlinkAttackDetector
from .unified_input_validation import UnifiedInputValidationDetector
from .unified_memory import UnifiedMemoryDetector
from .unified_privilege_escalation import UnifiedPrivilegeEscalationDetector

__all__ = [
    "VulnerabilityDetector",
    "detector_registry",
    "FileOperationDetector",
    "FormatStringDetector",
    "HeapBufferOverflowDetector",
    "InformationDisclosureDetector",
    "IntegerOverflowDetector",
    "IOCTLValidationDetector",
    "KernelPrimitiveDetector",
    "ObjectManipulationDetector",
    "RaceConditionDetector",
    "StackBufferOverflowDetector",
    "SymlinkAttackDetector",
    "UnifiedInputValidationDetector",
    "UnifiedMemoryDetector",
    "UnifiedPrivilegeEscalationDetector",
]
