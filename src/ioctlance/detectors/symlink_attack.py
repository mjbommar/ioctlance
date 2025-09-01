"""Symbolic link attack detector for IOCTLance."""

import logging
from typing import Any
from angr import SimState

from .base import VulnerabilityDetector, detector_registry

logger = logging.getLogger(__name__)


class SymlinkAttackDetector(VulnerabilityDetector):
    """Detects symbolic link race condition vulnerabilities."""

    # File operations that are vulnerable to symlink attacks
    VULNERABLE_FUNCTIONS = {
        # File creation/opening
        "ZwCreateFile", "NtCreateFile", "IoCreateFile", "IoCreateFileEx",
        "ZwOpenFile", "NtOpenFile", "IoOpenFile",

        # File operations
        "ZwWriteFile", "NtWriteFile", "ZwReadFile", "NtReadFile",
        "ZwDeleteFile", "NtDeleteFile", "ZwSetInformationFile", "NtSetInformationFile",

        # Directory operations
        "ZwCreateDirectoryObject", "NtCreateDirectoryObject",

        # Registry operations (can also be vulnerable)
        "ZwCreateKey", "NtCreateKey", "ZwOpenKey", "NtOpenKey",
        "ZwSetValueKey", "NtSetValueKey",
    }

    def __init__(self, context):
        """Initialize symlink attack detector."""
        super().__init__(context)
        self.detected_vulns = set()
        self.file_operations = {}  # Track file operations for TOCTOU detection
        self.checked_paths = {}  # Track paths that were checked/validated

    @property
    def name(self) -> str:
        """Get detector name."""
        return "symlink_attack"

    @property
    def description(self) -> str:
        """Get detector description."""
        return "Detects symbolic link race conditions and TOCTOU vulnerabilities in file operations"

    def check_state(self, state: SimState, event_type: str, **kwargs: Any) -> dict[str, Any] | None:
        """Check for symlink attack vulnerabilities.

        Args:
            state: Current simulation state
            event_type: Type of event
            **kwargs: Event-specific data

        Returns:
            Vulnerability info if found, None otherwise
        """
        if event_type == "function_call":
            function_name = kwargs.get("function_name", "")

            # Check for vulnerable file operations
            if function_name in self.VULNERABLE_FUNCTIONS:
                return self._check_file_operation(state, function_name, **kwargs)

            # Track path validation functions
            elif function_name in ["GetFileAttributes", "GetFileAttributesEx",
                                 "RtlDoesFileExists", "IoCheckShareAccess"]:
                self._track_path_check(state, function_name, **kwargs)

        return None

    def _check_file_operation(self, state: SimState, function_name: str,
                             **kwargs: Any) -> dict[str, Any] | None:
        """Check file operation for symlink vulnerabilities.

        Args:
            state: Current simulation state
            function_name: Name of file operation function

        Returns:
            Vulnerability info if found, None otherwise
        """
        try:
            # Get file path parameter
            file_path = self._get_file_path_parameter(state, function_name)
            if file_path is None:
                return None

            # Check for various symlink attack patterns

            # 1. TOCTOU: Path was checked earlier but now being used
            if self._is_toctou_vulnerable(state, file_path, function_name):
                return self._create_toctou_vuln(state, function_name, file_path)

            # 2. Unvalidated symbolic link following
            if self._follows_symlinks_unsafely(state, function_name, file_path):
                return self._create_symlink_vuln(state, function_name, file_path)

            # 3. Predictable temporary file creation
            if self._is_predictable_temp_file(state, file_path):
                return self._create_temp_file_vuln(state, function_name, file_path)

            # 4. Race condition in file creation
            if self._has_creation_race(state, function_name, file_path):
                return self._create_race_vuln(state, function_name, file_path)

            # Track this operation for future TOCTOU detection
            self._track_file_operation(state, file_path, function_name)

        except Exception as e:
            logger.debug(f"Error checking symlink attack: {e}")

        return None

    def _track_path_check(self, state: SimState, function_name: str, **kwargs: Any) -> None:
        """Track when a path is checked/validated.

        Args:
            state: Current simulation state
            function_name: Validation function name
        """
        try:
            file_path = self._get_file_path_parameter(state, function_name)
            if file_path is not None and hasattr(file_path, 'concrete'):
                path_id = self._get_path_id(file_path)
                self.checked_paths[path_id] = {
                    'check_addr': state.addr,
                    'function': function_name,
                    'state': state
                }
        except:
            pass

    def _track_file_operation(self, state: SimState, file_path: Any,
                             function_name: str) -> None:
        """Track file operation for TOCTOU detection.

        Args:
            state: Current simulation state
            file_path: Path being operated on
            function_name: Operation function name
        """
        try:
            if hasattr(file_path, 'concrete'):
                path_id = self._get_path_id(file_path)
                if path_id not in self.file_operations:
                    self.file_operations[path_id] = []
                self.file_operations[path_id].append({
                    'addr': state.addr,
                    'function': function_name,
                    'state': state
                })
        except:
            pass

    def _get_file_path_parameter(self, state: SimState, function_name: str) -> Any:
        """Extract file path parameter from function call.

        Args:
            state: Current simulation state
            function_name: Function being called

        Returns:
            File path parameter or None
        """
        try:
            # For most NT/Zw functions, OBJECT_ATTRIBUTES is in RDX (2nd param)
            if function_name.startswith(("Zw", "Nt")):
                if hasattr(state.regs, 'rdx'):
                    obj_attr_ptr = state.regs.rdx
                    # OBJECT_ATTRIBUTES has ObjectName (UNICODE_STRING*) at offset 0x10
                    unicode_str_ptr = state.memory.load(obj_attr_ptr + 0x10, 8)
                    # UNICODE_STRING has Buffer at offset 0x8
                    path_buffer = state.memory.load(unicode_str_ptr + 0x8, 8)
                    return path_buffer

            # For Io functions, path may be in RCX or RDX
            elif function_name.startswith("Io"):
                if hasattr(state.regs, 'rcx'):
                    return state.regs.rcx

        except:
            pass

        return None

    def _get_path_id(self, file_path: Any) -> str:
        """Get unique identifier for a file path.

        Args:
            file_path: File path value

        Returns:
            String identifier for the path
        """
        # Use string representation for comparison
        return str(file_path)[:100]

    def _is_toctou_vulnerable(self, state: SimState, file_path: Any,
                             function_name: str) -> bool:
        """Check for Time-of-Check-Time-of-Use vulnerability.

        Args:
            state: Current simulation state
            file_path: File path being accessed
            function_name: Current operation

        Returns:
            True if TOCTOU vulnerable
        """
        path_id = self._get_path_id(file_path)

        # Check if this path was previously checked
        if path_id in self.checked_paths:
            check_info = self.checked_paths[path_id]

            # TOCTOU if:
            # 1. Path was checked (validation function called)
            # 2. Now being used for privileged operation
            # 3. Sufficient instructions between check and use

            if function_name in ["ZwCreateFile", "ZwOpenFile", "ZwWriteFile", "ZwDeleteFile"]:
                # Check instruction distance
                check_addr = check_info['check_addr']
                current_addr = state.addr if hasattr(state, 'addr') else 0

                # If there's distance between check and use, it's TOCTOU
                if abs(current_addr - check_addr) > 0x10:  # More than a few instructions
                    return True

        return False

    def _follows_symlinks_unsafely(self, state: SimState, function_name: str,
                                  file_path: Any) -> bool:
        """Check if operation follows symlinks unsafely.

        Args:
            state: Current simulation state
            function_name: Function being called
            file_path: File path

        Returns:
            True if follows symlinks unsafely
        """
        # Check if FILE_FLAG_OPEN_REPARSE_POINT is NOT set
        # This flag prevents following symlinks

        if function_name in ["ZwCreateFile", "NtCreateFile"]:
            try:
                # CreateOptions is typically in stack (5th parameter)
                if hasattr(state.regs, 'rsp'):
                    create_options = state.memory.load(state.regs.rsp + 0x28, 4)
                    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

                    # If flag is not set and path is tainted, it's vulnerable
                    if self._is_tainted(file_path):
                        options_val = state.solver.eval(create_options) if hasattr(create_options, 'concrete') else 0
                        if not (options_val & FILE_FLAG_OPEN_REPARSE_POINT):
                            return True
            except:
                pass

        return False

    def _is_predictable_temp_file(self, state: SimState, file_path: Any) -> bool:
        """Check if creating predictable temporary file.

        Args:
            state: Current simulation state
            file_path: File path

        Returns:
            True if predictable temp file
        """
        try:
            # Check if path contains temp directory indicators
            if hasattr(file_path, 'symbolic'):
                path_str = str(file_path)
                temp_indicators = ["\\temp\\", "\\tmp\\", "%temp%", "%tmp%", "\\local\\temp"]

                for indicator in temp_indicators:
                    if indicator.lower() in path_str.lower():
                        # Check if filename is predictable (not random)
                        if not self._has_random_component(file_path):
                            return True
        except:
            pass

        return False

    def _has_creation_race(self, state: SimState, function_name: str,
                          file_path: Any) -> bool:
        """Check for race condition in file creation.

        Args:
            state: Current simulation state
            function_name: Function being called
            file_path: File path

        Returns:
            True if race condition exists
        """
        if function_name in ["ZwCreateFile", "NtCreateFile"]:
            try:
                # Check if using CREATE_NEW disposition without proper locking
                if hasattr(state.regs, 'rsp'):
                    # Disposition is typically 6th parameter
                    disposition = state.memory.load(state.regs.rsp + 0x30, 4)
                    FILE_OPEN_IF = 3  # Opens if exists, creates if not

                    disp_val = state.solver.eval(disposition) if hasattr(disposition, 'concrete') else 0

                    # FILE_OPEN_IF without exclusive access is vulnerable
                    if disp_val == FILE_OPEN_IF:
                        # Check if exclusive access is requested
                        desired_access = state.regs.rcx if hasattr(state.regs, 'rcx') else None
                        if desired_access is not None:
                            GENERIC_WRITE = 0x40000000
                            FILE_WRITE_DATA = 0x00000002

                            access_val = state.solver.eval(desired_access) if hasattr(desired_access, 'concrete') else 0
                            # If writing without exclusive lock, vulnerable
                            if (access_val & (GENERIC_WRITE | FILE_WRITE_DATA)):
                                return True
            except:
                pass

        return False

    def _has_random_component(self, file_path: Any) -> bool:
        """Check if file path has random component.

        Args:
            file_path: File path to check

        Returns:
            True if has random component
        """
        # Check if path contains random-looking components
        # (GUIDs, timestamps, random numbers)
        try:
            path_str = str(file_path)
            # Simple heuristic: paths with long hex strings or GUIDs
            import re
            if re.search(r'[0-9a-f]{8,}', path_str, re.IGNORECASE):
                return True
        except:
            pass

        return False

    def _is_tainted(self, value: Any) -> bool:
        """Check if value is tainted (user-controlled).

        Args:
            value: Value to check

        Returns:
            True if tainted
        """
        if value is None:
            return False

        if hasattr(value, 'symbolic') and value.symbolic:
            for var in value.variables:
                var_name = str(var).lower()
                if 'input' in var_name or 'buffer' in var_name or 'user' in var_name:
                    return True

        return False

    def _create_toctou_vuln(self, state: SimState, function_name: str,
                           file_path: Any) -> dict[str, Any]:
        """Create TOCTOU vulnerability info."""
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, "toctou", function_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Symlink Attack - TOCTOU Race Condition",
            description=f"Time-of-Check-Time-of-Use vulnerability in {function_name}: "
                       "File path checked earlier but used without re-validation",
            state=state,
            severity="HIGH",
            parameters={
                "function": function_name,
                "file_path": str(file_path)[:100],
                "type": "toctou"
            }
        )

    def _create_symlink_vuln(self, state: SimState, function_name: str,
                           file_path: Any) -> dict[str, Any]:
        """Create symlink following vulnerability info."""
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, "symlink_follow", function_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Symlink Attack - Unsafe Symlink Following",
            description=f"{function_name} follows symbolic links without FILE_FLAG_OPEN_REPARSE_POINT",
            state=state,
            severity="HIGH",
            parameters={
                "function": function_name,
                "file_path": str(file_path)[:100],
                "type": "symlink_following"
            }
        )

    def _create_temp_file_vuln(self, state: SimState, function_name: str,
                              file_path: Any) -> dict[str, Any]:
        """Create predictable temp file vulnerability info."""
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, "predictable_temp", function_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Symlink Attack - Predictable Temporary File",
            description=f"Predictable temporary file creation in {function_name} allows symlink attacks",
            state=state,
            severity="MEDIUM",
            parameters={
                "function": function_name,
                "file_path": str(file_path)[:100],
                "type": "predictable_temp_file"
            }
        )

    def _create_race_vuln(self, state: SimState, function_name: str,
                        file_path: Any) -> dict[str, Any]:
        """Create file creation race vulnerability info."""
        vuln_key = (state.addr if hasattr(state, 'addr') else 0, "creation_race", function_name)

        if vuln_key in self.detected_vulns:
            return None
        self.detected_vulns.add(vuln_key)

        return self.create_vulnerability_info(
            title="Symlink Attack - File Creation Race",
            description=f"Race condition in {function_name} with FILE_OPEN_IF allows symlink attacks",
            state=state,
            severity="MEDIUM",
            parameters={
                "function": function_name,
                "file_path": str(file_path)[:100],
                "type": "creation_race"
            }
        )


# Register detector
detector_registry.register(SymlinkAttackDetector)
