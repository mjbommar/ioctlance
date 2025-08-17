"""Helper utilities for IOCTLance analysis."""

import json
import re
import subprocess
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


def analyze_object_attributes(
    context: AnalysisContext, func_name: str, state: SimState, object_attributes_addr: int
) -> None:
    """Analyze ObjectAttributes structure for vulnerabilities.

    Args:
        context: Analysis context
        func_name: Name of the function being analyzed
        state: Current simulation state
        object_attributes_addr: Address of ObjectAttributes structure
    """
    # Access ObjectAttributes structure
    object_name = state.mem[object_attributes_addr].struct._OBJECT_ATTRIBUTES.ObjectName.resolved
    attributes = state.mem[object_attributes_addr].struct._OBJECT_ATTRIBUTES.Attributes.resolved
    buffer = state.mem[object_name].struct._UNICODE_STRING.Buffer.resolved

    tmp_state = state.copy()

    # Attributes is not OBJ_FORCE_ACCESS_CHECK (0x400)
    tmp_state.solver.add(attributes & 0x400 == 0)

    # Check if the ObjectName is controllable
    buffer_content = state.memory.load(buffer, 0x80)

    if tmp_state.satisfiable() and (
        str(state.mem[object_name].struct._UNICODE_STRING.Buffer.resolved)
        in state.globals.get("tainted_unicode_strings", ())
        or is_tainted_buffer(buffer_content)
    ):
        ret_addr = hex(state.callstack.ret_addr) if state.callstack else "0x0"

        vuln_info = {
            "title": "ObjectName in ObjectAttributes controllable",
            "description": func_name,
            "state": str(state),
            "parameters": {
                "ObjectAttributes": {
                    "ObjectName": str(object_name),
                    "ObjectName.Buffer": str(buffer_content.reversed),
                    "Attributes": str(attributes),
                }
            },
            "others": {"return_address": ret_addr},
        }

        context.add_vulnerability(vuln_info)
        context.print_info(f"Vulnerability found: {vuln_info['title']}")


def find_utf16le_string(data: bytes, search_string: str) -> int:
    """Find UTF-16LE encoded string in binary data.

    Args:
        data: Binary data to search
        search_string: String to find (will be encoded as UTF-16LE)

    Returns:
        Position of the string if found, -1 otherwise
    """
    try:
        encoded = search_string.encode("utf-16le")
        return data.find(encoded)
    except UnicodeEncodeError:
        return -1


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

    # Also check for UTF-16LE encoded names
    common_prefixes = ["\\Device\\", "\\DosDevices\\", "\\??\\"]
    for prefix in common_prefixes:
        pos = find_utf16le_string(data, prefix)
        if pos >= 0:
            # Try to extract the full device name
            # This is simplified - real implementation would be more robust
            pass

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


def print_eval_buffers(context: AnalysisContext, state: SimState, max_solutions: int = 5) -> dict[str, list[str]]:
    """Evaluate and print symbolic buffer values.

    Args:
        context: Analysis context
        state: Current simulation state
        max_solutions: Maximum number of solutions to evaluate

    Returns:
        Dictionary mapping buffer names to possible values
    """
    results = {}

    buffers = {
        "SystemBuffer": context.system_buffer,
        "Type3InputBuffer": context.type3_input_buffer,
        "UserBuffer": context.user_buffer,
        "InputBufferLength": context.input_buffer_length,
        "OutputBufferLength": context.output_buffer_length,
        "IoControlCode": context.io_control_code,
    }

    for name, buffer in buffers.items():
        if buffer is not None:
            try:
                values = state.solver.eval_upto(buffer, max_solutions)
                results[name] = [hex(v) for v in values]
                context.print_debug(f"{name}: {results[name]}")
            except angr.errors.SimError:
                results[name] = ["<unsolvable>"]

    return results


def save_analysis_result(result: dict[str, Any], output_path: Path | str) -> None:
    """Save analysis result to JSON file.

    Args:
        result: Analysis result dictionary
        output_path: Path to save the JSON file
    """
    path = Path(output_path) if isinstance(output_path, str) else output_path

    with open(path, "w") as f:
        json.dump(result, f, indent=4)


def run_objdump(driver_path: Path | str) -> list[str]:
    """Run objdump on a driver file to get disassembly.

    Args:
        driver_path: Path to the driver file

    Returns:
        List of disassembly lines
    """
    path = Path(driver_path) if isinstance(driver_path, str) else driver_path

    if not path.exists():
        return []

    command = ["objdump", "--insn-width=16", "-d", str(path)]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return []
