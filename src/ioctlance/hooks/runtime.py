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
        "RtlGetVersion": HookRtlGetVersion,
        "RtlInitUnicodeString": HookRtlInitUnicodeString,
        "RtlIsNtDdiVersionAvailable": HookRtlIsNtDdiVersionAvailable,
        # Format string functions
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
    "HookSprintf",
    "HookSwprintf",
    "HookRtlStringCbPrintfW",
]
