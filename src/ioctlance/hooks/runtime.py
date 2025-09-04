"""Runtime library (Rtl*) hooks for Windows kernel API simulation."""

from typing import Any

import claripy

from .base import BaseHook


class HookRtlGetVersion(BaseHook):
    """Hook for RtlGetVersion - gets OS version."""

    def run(self, lpVersionInformation) -> int:
        """Get OS version with symbolic values."""
        ret_addr = hex(self.state.callstack.ret_addr)
        VersionInformation = self.state.mem[lpVersionInformation].struct._OSVERSIONINFOW

        # Create symbolic version values
        dwMajorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}_major", self.state.arch.bits // 2)
        VersionInformation.dwMajorVersion = dwMajorVersion

        dwMinorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}_minor", self.state.arch.bits // 2)
        VersionInformation.dwMinorVersion = dwMinorVersion

        dwBuildNumber = claripy.BVS(f"RtlGetVersion_{ret_addr}_build", self.state.arch.bits // 2)
        VersionInformation.dwBuildNumber = dwBuildNumber

        return 0


class HookRtlInitUnicodeString(BaseHook):
    """Hook for RtlInitUnicodeString."""

    def run(self, DestinationString, SourceString) -> None:
        """Initialize Unicode string and track if tainted."""
        self.get_context()

        # Track tainted unicode strings
        if "tainted_unicode_strings" not in self.state.globals:
            self.state.globals["tainted_unicode_strings"] = ()

        # Check if source is tainted and track it
        from ..utils.helpers import is_tainted_buffer

        if is_tainted_buffer(SourceString):
            self.state.globals["tainted_unicode_strings"] = self.state.globals["tainted_unicode_strings"] + (
                str(SourceString),
            )

        return None


class HookRtlIsNtDdiVersionAvailable(BaseHook):
    """Hook for RtlIsNtDdiVersionAvailable."""

    def run(self, Version) -> int:
        """Check if DDI version is available."""
        # Return True (1) to indicate version is available
        return 1


class HookSprintf(BaseHook):
    """Hook for sprintf family functions to detect format string vulnerabilities."""

    def run(self, buffer, format_str, *args) -> Any:
        """Check for format string vulnerabilities in sprintf."""
        context = self.get_context()
        if context:
            # Notify detectors about the sprintf call
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="sprintf",
                        buffer=buffer,
                        format_str=format_str,
                        args=args,
                    )
                    if result:
                        context.vulnerabilities.append(result)

        # Return success (number of chars written, we'll use a symbolic value)
        return claripy.BVS("sprintf_ret", 32)


class HookSwprintf(BaseHook):
    """Hook for swprintf family functions to detect format string vulnerabilities."""

    def run(self, buffer, size, format_str, *args) -> Any:
        """Check for format string vulnerabilities in swprintf."""
        context = self.get_context()
        if context:
            # Notify detectors about the swprintf call
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="swprintf",
                        buffer=buffer,
                        size=size,
                        format_str=format_str,
                        args=args,
                    )
                    if result:
                        context.vulnerabilities.append(result)

        # Return success (number of chars written, we'll use a symbolic value)
        return claripy.BVS("swprintf_ret", 32)


class HookDbgPrint(BaseHook):
    """Hook for DbgPrint to detect format string vulnerabilities."""

    def run(self, format_str, *args):
        context = self.get_context()
        if context:
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="DbgPrint",
                        format_str=format_str,
                        args=args,
                    )
                    if result:
                        context.add_vulnerability(result)
        return 0


class HookDbgPrintEx(BaseHook):
    """Hook for DbgPrintEx to detect format string vulnerabilities."""

    def run(self, component_id, level, format_str, *args):
        context = self.get_context()
        if context:
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="DbgPrintEx",
                        component_id=component_id,
                        level=level,
                        format_str=format_str,
                        args=args,
                    )
                    if result:
                        context.add_vulnerability(result)
        return 0


class HookKdPrint(BaseHook):
    """Hook for KdPrint to detect format string vulnerabilities (alias of DbgPrint)."""

    def run(self, format_str, *args):
        context = self.get_context()
        if context:
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="KdPrint",
                        format_str=format_str,
                        args=args,
                    )
                    if result:
                        context.add_vulnerability(result)
        return 0


class HookKdPrintEx(BaseHook):
    """Hook for KdPrintEx to detect format string vulnerabilities (alias of DbgPrintEx)."""

    def run(self, component_id, level, format_str, *args):
        context = self.get_context()
        if context:
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="KdPrintEx",
                        component_id=component_id,
                        level=level,
                        format_str=format_str,
                        args=args,
                    )
                    if result:
                        context.add_vulnerability(result)
        return 0


class HookRtlStringCbPrintfW(BaseHook):
    """Hook for RtlStringCbPrintfW to detect format string vulnerabilities."""

    def run(self, pszDest, cbDest, pszFormat, *args) -> int:
        """Check for format string vulnerabilities in RtlStringCbPrintfW."""
        context = self.get_context()
        if context:
            # Notify detectors about the RtlStringCbPrintfW call
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="RtlStringCbPrintfW",
                        buffer=pszDest,
                        size=cbDest,
                        format_str=pszFormat,
                        args=args,
                    )
                    if result:
                        context.vulnerabilities.append(result)

        # Return STATUS_SUCCESS
        return 0


class HookPrintf(BaseHook):
    """Hook for printf to detect format string vulnerabilities."""

    def run(self, format_str, *args):
        context = self.get_context()
        if context:
            for detector in context.detectors:
                if hasattr(detector, "check_state"):
                    result = detector.check_state(
                        self.state,
                        "call",
                        func_name="printf",
                        format_str=format_str,
                        args=args,
                    )
                    if result:
                        context.add_vulnerability(result)
        return 0


def register_hooks(project) -> None:
    """Register hooks with the project.

    Args:
        project: angr project to register hooks with
    """
    # Get calling convention
    cc = BaseHook.get_calling_convention(project)

    hooks = {
        "RtlGetVersion": HookRtlGetVersion,
        "RtlInitUnicodeString": HookRtlInitUnicodeString,
        "RtlIsNtDdiVersionAvailable": HookRtlIsNtDdiVersionAvailable,
        # Format string functions
        "DbgPrint": HookDbgPrint,
        "DbgPrintEx": HookDbgPrintEx,
        "KdPrint": HookKdPrint,
        "KdPrintEx": HookKdPrintEx,
        "printf": HookPrintf,
        "sprintf": HookSprintf,
        "swprintf": HookSwprintf,
        "snprintf": HookSprintf,  # Same signature as sprintf
        "snwprintf": HookSwprintf,  # Same signature as swprintf
        "RtlStringCbPrintfW": HookRtlStringCbPrintfW,
        "RtlStringCbPrintfA": HookRtlStringCbPrintfW,  # Same signature
        "RtlStringCchPrintfW": HookRtlStringCbPrintfW,  # Similar enough
        "RtlStringCchPrintfA": HookRtlStringCbPrintfW,  # Similar enough
    }

    for name, hook_class in hooks.items():
        try:
            project.hook_symbol(name, hook_class(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol might not exist in this driver
            pass


__all__ = [
    "HookRtlGetVersion",
    "HookRtlInitUnicodeString",
    "HookRtlIsNtDdiVersionAvailable",
    "HookPrintf",
    "HookDbgPrint",
    "HookDbgPrintEx",
    "HookKdPrint",
    "HookKdPrintEx",
    "HookSprintf",
    "HookSwprintf",
    "HookRtlStringCbPrintfW",
]
