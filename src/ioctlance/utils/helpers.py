"""Helper utilities for IOCTLance analysis."""

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

import angr
from angr import SimState

from ..core.analysis_context import AnalysisContext


def get_state_globals(state: SimState) -> dict[str, Any]:
    """Get state globals as a dict for type checking compatibility.

    Args:
        state: The simulation state

    Returns:
        State globals as a dictionary-like object
    """
    return cast(dict[str, Any], state.globals)


def safe_hex(value: Any) -> str:
    """Safely convert a value to hex string.

    Handles symbolic values, integers, and strings.

    Args:
        value: Value to convert to hex

    Returns:
        Hex string representation
    """
    try:
        # If it's already a string starting with 0x, return it
        if isinstance(value, str) and value.startswith("0x"):
            return value
        # If it's an integer, convert to hex
        elif isinstance(value, int):
            return hex(value)
        # If it's a symbolic value, try to evaluate it
        elif hasattr(value, "concrete") or hasattr(value, "symbolic"):
            # Try to get a concrete value
            if hasattr(value, "solver"):
                return hex(value.solver.eval(value))
            # Might be from a state context
            else:
                return str(value)  # Return string representation
        else:
            # Try direct conversion as last resort
            return hex(int(value))
    except (ValueError, TypeError, AttributeError):
        return "0x0"


# Pre-defined set of tainted buffer names for fast lookup
TAINTED_BUFFER_NAMES = frozenset(
    [
        "SystemBuffer",
        "Type3InputBuffer",
        "UserBuffer",
        "InputBufferLength",
        "OutputBufferLength",
    ]
)


def is_tainted_buffer(symbolic_var: Any) -> str:
    """Check if a symbolic variable represents a tainted buffer.

    Args:
        symbolic_var: Symbolic variable to check

    Returns:
        Name of the tainted buffer if found, empty string otherwise
    """
    # The tainted buffer contains only one symbolic variable
    if not hasattr(symbolic_var, "variables") or len(symbolic_var.variables) != 1:
        return ""

    # Check the tainted symbolic variable
    var_str = str(symbolic_var)

    # Use set intersection for efficient lookup
    for buffer_name in TAINTED_BUFFER_NAMES:
        if buffer_name in var_str:
            return buffer_name

    return ""


@lru_cache(maxsize=128)
def _find_device_names_cached(driver_path_str: str, file_size: int, file_mtime: float) -> tuple[str, ...]:
    """Internal cached implementation of device name extraction.

    Args:
        driver_path_str: String path to the driver file
        file_size: Size of the file (for cache key)
        file_mtime: Modification time of the file (for cache key)

    Returns:
        Tuple of device names found (tuple for hashability)
    """
    path = Path(driver_path_str)
    device_names = []

    # Read the driver file
    with open(path, "rb") as f:
        data = f.read()

    # Common Windows device name patterns
    patterns = [
        rb"\\Device\\[A-Za-z0-9_]+",
        rb"\\DosDevices\\[A-Za-z0-9_]+",
        rb"\\??\\[A-Za-z0-9_]+",
    ]

    for pattern in patterns:
        matches = re.findall(pattern, data)
        for match in matches:
            try:
                device_name = match.decode("utf-8", errors="ignore")
                if device_name not in device_names:
                    device_names.append(device_name)
            except:
                pass

    # Note: UTF-16LE encoded names checking was removed as part of cleanup

    return tuple(device_names)  # Return tuple for hashability


def find_device_names(driver_path: Path | str) -> list[str]:
    """Extract device names from a driver file.

    Args:
        driver_path: Path to the driver file

    Returns:
        List of device names found
    """
    path = Path(driver_path) if isinstance(driver_path, str) else driver_path

    if not path.exists():
        return []

    # Get file stats for cache key
    stat = path.stat()

    # Call cached implementation
    device_names_tuple = _find_device_names_cached(str(path), stat.st_size, stat.st_mtime)

    return list(device_names_tuple)


def find_driver_type(project: angr.Project) -> str:
    """Determine the type of Windows driver.

    Args:
        project: angr project for the driver

    Returns:
        Driver type: 'wdm', 'wdf', 'kmdf', 'umdf', or 'unknown'
    """
    pe = project.loader.main_object

    # Helper to check if symbol exists
    def has_symbol(name: str) -> bool:
        """Check if a symbol exists in the PE file."""
        try:
            # Check in symbols list
            if hasattr(pe, "symbols"):
                for symbol in pe.symbols:
                    if symbol.name == name:
                        return True

            # Try get_symbol
            if hasattr(pe, "get_symbol"):
                sym = pe.get_symbol(name)
                if sym is not None:
                    return True
        except:
            pass
        return False

    # For Windows kernel drivers, check if it has an entry point
    # All kernel drivers have an entry point (DriverEntry)
    if project.entry != 0:
        # Check for KMDF/WDF symbols
        if has_symbol("WdfDriverCreate") or has_symbol("WdfVersionBind"):
            return "kmdf"

        if has_symbol("WdfControlDeviceInitAllocate") or has_symbol("WdfDeviceCreate"):
            return "wdf"

        # Default to WDM for kernel drivers
        return "wdm"

    # Check for UMDF driver
    if has_symbol("DllMain"):
        if has_symbol("IDriverEntry") or has_symbol("IUnknown"):
            return "umdf"

    return "unknown"
