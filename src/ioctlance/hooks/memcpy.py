"""Memory copy hooks for vulnerability detection."""

import logging
from typing import Any

import angr

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

        if context and context.config.debug:
            logger.info(f"memcpy hook: dst={dst}, src={src}, size={size}")

        # Check if size is symbolic (tainted)
        is_symbolic_size = False
        if hasattr(size, "symbolic"):
            is_symbolic_size = size.symbolic
        elif hasattr(size, "variables"):
            is_symbolic_size = len(size.variables) > 0

        # Get concrete or max size for the actual copy
        try:
            if is_symbolic_size:
                # For symbolic size, get the maximum possible value (capped at reasonable limit)
                max_size = self.state.solver.max(size)
                if max_size > 0x10000:  # Cap at 64KB to avoid state explosion
                    max_size = 0x10000
                concrete_size = max_size

                # Log potential overflow
                if context and context.config.debug:
                    logger.warning(f"memcpy with symbolic size (max={max_size})")
            else:
                concrete_size = self.state.solver.eval_one(size)
        except:
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
                # Check if destination is on stack
                stack_pointer = self.state.regs.rsp if hasattr(self.state.regs, "rsp") else self.state.regs.sp
                try:
                    if hasattr(dst, "concrete"):
                        dst_concrete = self.state.solver.eval_one(dst)
                    else:
                        dst_concrete = dst

                    if hasattr(stack_pointer, "concrete"):
                        sp_concrete = self.state.solver.eval_one(stack_pointer)
                    else:
                        sp_concrete = stack_pointer

                    # Check if destination is in stack range
                    max_stack_size = 1024 * 1024  # 1MB
                    max_frame_size = 8192  # 8KB

                    is_stack = (sp_concrete - max_stack_size) <= dst_concrete <= (sp_concrete + max_frame_size)

                    if is_stack and (is_symbolic_size or concrete_size > 256):
                        # Potential stack buffer overflow!
                        vuln_info = {
                            "title": "Stack Buffer Overflow - memcpy",
                            "description": f"memcpy to stack with {'symbolic' if is_symbolic_size else 'large'} size",
                            "state": str(self.state),
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
                        context.print_info(f"[VULN] Stack overflow in memcpy: size={size}")

                except Exception as e:
                    if context and context.config.debug:
                        logger.error(f"Error checking memcpy overflow: {e}")

        # Perform the actual memory copy
        if concrete_size > 0 and concrete_size <= 0x10000:
            # Use angr's built-in memcpy for the actual operation
            self.state.memory.store(dst, self.state.memory.load(src, concrete_size), size=concrete_size)

        return dst


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
    logger.info("Registering memcpy hooks...")
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
            logger.info(f"Hooked {func_name} at {hex(hook_addr)}")
            hooked_addrs.add(hook_addr)

    # Also hook by common import addresses if available
    # These are commonly imported from ntoskrnl.exe
    try:
        if hasattr(project.loader, "main_object"):
            imports = project.loader.main_object.imports
            # Handle both Import objects and plain strings
            for imp in imports:
                # Check if it's an Import object with name attribute or just a string
                if hasattr(imp, 'name'):
                    imp_name = imp.name
                    imp_addr = imp.rebased_addr if hasattr(imp, 'rebased_addr') else None
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
                        logger.info(f"Hooked import {imp_name} at {hex(hook_addr)}")
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
                            logger.info(f"Hooked PLT {func_name} at {hex(plt_addr)}")
                            hooked_addrs.add(plt_addr)

    except Exception as e:
        logger.warning(f"Failed to hook imports: {e}")
