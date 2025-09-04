"""Memory copy hooks for vulnerability detection."""

import logging
from typing import Any

import angr

from ..utils.error_handler import SymbolicExecutionErrorHandler

logger = logging.getLogger(__name__)


class MemcpyHook(angr.SimProcedure):
    """Hook for memcpy/memmove/RtlCopyMemory functions."""

    def run(self, dst: Any, src: Any, size: Any) -> Any:
        """Execute memcpy with vulnerability detection.

        Args:
            dst: Destination address
            src: Source address
            size: Number of bytes to copy

        Returns:
            Destination address
        """
        # Get the analysis context from state globals
        context = self.state.globals.get("analysis_context")

        # Only log in debug mode to reduce overhead
        if context and context.config.debug:
            logger.debug(f"memcpy hook: dst={dst}, src={src}, size={size}")

        # FIRST: Check for controllable addresses (arbitrary read/write)
        # This is different from buffer overflow - it's about WHERE, not HOW MUCH
        dst_tainted = self._is_tainted_safe(dst)
        src_tainted = self._is_tainted_safe(src)

        if (dst_tainted or src_tainted) and context:
            # Get IOCTL code if available
            ioctl_code = "N/A"
            if hasattr(self.state, "globals") and "IoControlCode" in self.state.globals:
                try:
                    ioctl_code = hex(self.state.globals["IoControlCode"])
                except:
                    pass

            # This is a potential arbitrary read/write primitive
            vuln_info = {
                "title": f"{'Destination' if dst_tainted else 'Source'} Controllable - memcpy",
                "description": f"User controls {'destination' if dst_tainted else 'source'} address in memcpy",
                "state": self.state,  # Pass the actual state object
                "state_str": str(self.state),  # Keep string version for backward compatibility
                "eval": {
                    "dst": str(dst)[:100],
                    "src": str(src)[:100],
                    "size": str(size)[:100],
                    "dst_tainted": dst_tainted,
                    "src_tainted": src_tainted,
                    "IoControlCode": ioctl_code,
                },
                "parameters": {
                    "controllable": "destination" if dst_tainted else "source",
                },
                "others": {
                    "severity": "HIGH",
                    "exploitation": "Arbitrary write" if dst_tainted else "Arbitrary read",
                    "primitive_type": "write" if dst_tainted else "read",
                    "technique": "Control memory address to read/write arbitrary kernel memory",
                },
            }

            context.add_vulnerability(vuln_info)
            # Log at debug level, vulnerability is already tracked
            logger.debug(
                f"[VULN] {'Dest' if dst_tainted else 'Src'} controllable in memcpy - "
                f"{'Arbitrary write' if dst_tainted else 'Arbitrary read'} primitive"
            )

        # Check if size is symbolic (tainted) - use safe check to avoid ClaripyOperationError
        is_symbolic_size = SymbolicExecutionErrorHandler.safe_symbolic_check(size)

        # Get concrete or max size for the actual copy - use safe evaluation
        try:
            if is_symbolic_size:
                # For symbolic size, get the maximum possible value (capped at reasonable limit)
                max_size = self.state.solver.max(size)
                if max_size > 0x10000:  # Cap at 64KB to avoid state explosion
                    max_size = 0x10000
                concrete_size = max_size

                # Log potential overflow at debug level
                if context and context.config.debug:
                    logger.debug(f"memcpy with symbolic size (max={max_size})")
            else:
                concrete_size = SymbolicExecutionErrorHandler.safe_eval(self.state, size, 0x100)
        except Exception as e:
            logger.debug(f"Error evaluating memcpy size: {e}")
            concrete_size = 0x100  # Default fallback

        # Trigger memory write breakpoint with size information
        # This will be caught by our stack overflow detector
        if context:
            # Temporarily store the size in inspect for breakpoints to see
            self.state.inspect.mem_write_length = size
            self.state.inspect.mem_write_address = dst
            self.state.inspect.mem_write_expr = src

            # For symbolic size or large copies, explicitly check for stack overflow
            if is_symbolic_size or concrete_size > 256:
                # Check if destination is on stack - use safe evaluation
                stack_pointer = self.state.regs.rsp if hasattr(self.state.regs, "rsp") else self.state.regs.sp
                try:
                    dst_concrete = SymbolicExecutionErrorHandler.safe_eval(self.state, dst, 0)
                    sp_concrete = SymbolicExecutionErrorHandler.safe_eval(self.state, stack_pointer, 0)

                    # Check if destination is in stack range
                    max_stack_size = 1024 * 1024  # 1MB
                    max_frame_size = 8192  # 8KB

                    is_stack = (sp_concrete - max_stack_size) <= dst_concrete <= (sp_concrete + max_frame_size)

                    if is_stack and (is_symbolic_size or concrete_size > 256):
                        # Potential stack buffer overflow!
                        vuln_info = {
                            "title": "Stack Buffer Overflow - memcpy",
                            "description": f"memcpy to stack with {'symbolic' if is_symbolic_size else 'large'} size",
                            "state": self.state,  # Pass the actual state object
                            "state_str": str(self.state),  # Keep string version for backward compatibility
                            "eval": {
                                "dst": hex(dst_concrete),
                                "size": str(size),
                                "max_size": concrete_size,
                                "symbolic": is_symbolic_size,
                            },
                            "others": {
                                "severity": "CRITICAL" if is_symbolic_size else "HIGH",
                                "type": "stack_overflow",
                            },
                        }
                        context.add_vulnerability(vuln_info)
                        logger.debug(f"[VULN] Stack overflow in memcpy: size={size}")

                except Exception as e:
                    if context and context.config.debug:
                        logger.error(f"Error checking memcpy overflow: {e}")

        # Perform the actual memory copy
        if concrete_size > 0 and concrete_size <= 0x10000:
            # Use angr's built-in memcpy for the actual operation
            self.state.memory.store(dst, self.state.memory.load(src, concrete_size), size=concrete_size)

        return dst

    def _is_tainted_safe(self, value):
        """Check if a value is tainted (user-controlled) using centralized safe checks.

        Args:
            value: Value to check for taint

        Returns:
            True if value is tainted/user-controlled
        """
        if value is None:
            return False

        # Use the centralized safe symbolic check first
        if not SymbolicExecutionErrorHandler.safe_symbolic_check(value):
            return False

        # If it's symbolic, check if any variable comes from user input
        if hasattr(value, "variables"):
            try:
                for var in value.variables:
                    if any(
                        target in str(var)
                        for target in ["SystemBuffer", "Type3InputBuffer", "UserBuffer", "InputBuffer"]
                    ):
                        return True
            except Exception as e:
                logger.debug(f"Error checking variable taint: {e}")
                # If we can't check variables safely, assume it might be tainted if it's symbolic
                return True

        return False


class RtlCopyMemoryHook(MemcpyHook):
    """Alias for RtlCopyMemory which is the same as memcpy."""

    pass


class MemmoveHook(MemcpyHook):
    """Alias for memmove which is similar to memcpy."""

    pass


def register_hooks(project: angr.Project) -> None:
    """Register memory copy hooks.

    Args:
        project: angr project to hook
    """
    logger.debug("Registering memcpy hooks...")
    hooked_addrs = set()

    # Hook various memory copy functions
    for func_name in ["memcpy", "memmove", "RtlCopyMemory"]:
        # Try to find the function in the binary
        symbol = project.loader.find_symbol(func_name)
        if symbol and symbol.rebased_addr not in hooked_addrs:
            hook_addr = symbol.rebased_addr
            if func_name == "RtlCopyMemory":
                project.hook(hook_addr, RtlCopyMemoryHook(), replace=True)
            elif func_name == "memmove":
                project.hook(hook_addr, MemmoveHook(), replace=True)
            else:
                project.hook(hook_addr, MemcpyHook(), replace=True)
            logger.debug(f"Hooked {func_name} at {hex(hook_addr)}")
            hooked_addrs.add(hook_addr)

    # Also hook by common import addresses if available
    # These are commonly imported from ntoskrnl.exe
    try:
        if hasattr(project.loader, "main_object"):
            imports = project.loader.main_object.imports
            # Handle both Import objects and plain strings
            for imp in imports:
                # Check if it's an Import object with name attribute or just a string
                if hasattr(imp, "name"):
                    imp_name = imp.name
                    imp_addr = imp.rebased_addr if hasattr(imp, "rebased_addr") else None
                elif isinstance(imp, str):
                    imp_name = imp
                    # For string imports, we can't get the address directly
                    imp_addr = None
                else:
                    continue

                if imp_name in ["memcpy", "memmove", "RtlCopyMemory"] and imp_addr:
                    hook_addr = imp_addr
                    if hook_addr and hook_addr not in hooked_addrs:
                        assert isinstance(hook_addr, int), "hook_addr must be int at this point"
                        if imp_name == "RtlCopyMemory":
                            project.hook(hook_addr, RtlCopyMemoryHook(), replace=True)
                        elif imp_name == "memmove":
                            project.hook(hook_addr, MemmoveHook(), replace=True)
                        else:
                            project.hook(hook_addr, MemcpyHook(), replace=True)
                        logger.debug(f"Hooked import {imp_name} at {hex(hook_addr)}")
                        hooked_addrs.add(hook_addr)

            # For PE files, also look for PLT stubs (jump thunks)
            if hasattr(project.loader.main_object, "plt"):
                for func_name in ["memcpy", "memmove", "RtlCopyMemory"]:
                    if func_name in project.loader.main_object.plt:
                        plt_addr = project.loader.main_object.plt[func_name]
                        if plt_addr not in hooked_addrs:
                            if func_name == "RtlCopyMemory":
                                project.hook(plt_addr, RtlCopyMemoryHook(), replace=True)
                            elif func_name == "memmove":
                                project.hook(plt_addr, MemmoveHook(), replace=True)
                            else:
                                project.hook(plt_addr, MemcpyHook(), replace=True)
                            logger.debug(f"Hooked PLT {func_name} at {hex(plt_addr)}")
                            hooked_addrs.add(plt_addr)

    except Exception as e:
        if not SymbolicExecutionErrorHandler.is_non_fatal_error(e):
            logger.warning(f"Failed to hook imports: {e}")
        else:
            logger.debug(f"Non-fatal error hooking imports: {e}")
