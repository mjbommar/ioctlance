"""Utility functions for capturing raw state data from SimState."""

import logging
from typing import Any

from angr import SimState

from ..core.analysis_context import AnalysisContext
from ..models.raw_state import (
    RawCallStack,
    RawConcreteInputs,
    RawConstraints,
    RawExecutionTrace,
    RawInstructionContext,
    RawMemorySnapshot,
    RawRegisters,
    RawStateGlobals,
    RawSymbolicState,
    RawVulnerabilityData,
)

logger = logging.getLogger(__name__)


def capture_raw_state(state: SimState, context: AnalysisContext | None = None) -> RawVulnerabilityData:
    """Capture all raw state data for vulnerability analysis.

    Args:
        state: The SimState at the vulnerability point
        context: Optional analysis context for additional info

    Returns:
        Complete raw vulnerability data
    """
    raw_data = RawVulnerabilityData()

    try:
        # Capture SMT constraints
        raw_data.constraints = capture_constraints(state)
    except Exception as e:
        logger.debug(f"Failed to capture constraints: {e}")

    try:
        # Capture execution trace
        raw_data.execution_trace = capture_execution_trace(state)
    except Exception as e:
        logger.debug(f"Failed to capture execution trace: {e}")

    try:
        # Capture register state
        raw_data.registers = capture_registers(state)
    except Exception as e:
        logger.debug(f"Failed to capture registers: {e}")

    try:
        # Capture symbolic state
        raw_data.symbolic_state = capture_symbolic_state(state)
    except Exception as e:
        logger.debug(f"Failed to capture symbolic state: {e}")

    try:
        # Capture call stack
        raw_data.call_stack = capture_call_stack(state)
    except Exception as e:
        logger.debug(f"Failed to capture call stack: {e}")

    try:
        # Capture instruction context
        raw_data.instruction_context = capture_instruction_context(state)
    except Exception as e:
        logger.debug(f"Failed to capture instruction context: {e}")

    try:
        # Capture concrete inputs
        raw_data.concrete_inputs = capture_concrete_inputs(state, context)
    except Exception as e:
        logger.debug(f"Failed to capture concrete inputs: {e}")

    try:
        # Capture state globals
        raw_data.state_globals = capture_state_globals(state)
    except Exception as e:
        logger.debug(f"Failed to capture state globals: {e}")

    # Capture memory snapshots (limited to avoid huge output)
    # This is intentionally last as it might be expensive
    try:
        raw_data.memory = capture_memory_snapshots(state, context)
    except Exception as e:
        logger.debug(f"Failed to capture memory: {e}")

    return raw_data


def capture_constraints(state: SimState) -> RawConstraints:
    """Capture all SMT constraints."""
    constraints = []

    # Get all constraints as strings
    for constraint in state.solver.constraints:
        try:
            constraints.append(str(constraint))
        except:
            constraints.append("<unprintable constraint>")

    return RawConstraints(constraints=constraints, satisfiable=state.satisfiable())


def capture_execution_trace(state: SimState) -> RawExecutionTrace:
    """Capture execution trace information."""
    # Get basic block addresses
    bbl_addrs = []
    if hasattr(state.history, "bbl_addrs"):
        try:
            bbl_addrs = list(state.history.bbl_addrs.hardcopy)
        except:
            pass

    # Count unique addresses
    unique_addrs = len(set(bbl_addrs)) if bbl_addrs else 0

    # Get call depth from history
    call_depth = 0
    if hasattr(state, "callstack") and state.callstack:
        try:
            call_depth = len(state.callstack)
        except:
            pass

    return RawExecutionTrace(
        basic_blocks=bbl_addrs,
        instructions_executed=len(bbl_addrs),
        call_depth=call_depth,
        unique_addresses=unique_addrs,
    )


def capture_registers(state: SimState) -> RawRegisters:
    """Capture register values."""
    registers = {}
    symbolic_regs = []

    # Get all register names for this architecture
    reg_names = []
    if hasattr(state.arch, "register_names"):
        reg_names = list(state.arch.register_names.values())
    else:
        # Common x64 registers as fallback
        reg_names = [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rip",
        ]

    for reg_name in reg_names:
        try:
            reg_val = state.registers.load(reg_name)
            if hasattr(reg_val, "symbolic") and reg_val.symbolic:
                symbolic_regs.append(reg_name)
                registers[reg_name] = str(reg_val)
            else:
                # Try to get concrete value
                concrete_val = state.solver.eval(reg_val)
                registers[reg_name] = hex(concrete_val) if isinstance(concrete_val, int) else str(concrete_val)
        except:
            pass

    return RawRegisters(registers=registers, symbolic_registers=symbolic_regs)


def capture_symbolic_state(state: SimState) -> RawSymbolicState:
    """Capture symbolic variable information."""
    symbolic_vars = {}
    symbolic_exprs = {}
    taint_sources = []

    # Get all symbolic variables
    try:
        for var in state.solver.all_variables:
            var_name = str(var)
            # Get possible values (limit to 10)
            try:
                possible_values = state.solver.eval_upto(var, 10)
                symbolic_vars[var_name] = [hex(v) if isinstance(v, int) else str(v) for v in possible_values]
            except:
                symbolic_vars[var_name] = ["<unable to evaluate>"]
    except:
        pass

    # Capture key symbolic expressions from inspect
    if hasattr(state, "inspect"):
        try:
            if hasattr(state.inspect, "mem_read_address") and state.inspect.mem_read_address:
                symbolic_exprs["mem_read_address"] = str(state.inspect.mem_read_address)
            if hasattr(state.inspect, "mem_write_address") and state.inspect.mem_write_address:
                symbolic_exprs["mem_write_address"] = str(state.inspect.mem_write_address)
            if hasattr(state.inspect, "mem_write_expr") and state.inspect.mem_write_expr:
                symbolic_exprs["mem_write_expr"] = str(state.inspect.mem_write_expr)
        except:
            pass

    # Get taint sources from common names
    taint_keywords = [
        "SystemBuffer",
        "UserBuffer",
        "Type3InputBuffer",
        "IoControlCode",
        "InputBufferLength",
        "OutputBufferLength",
    ]
    for var_name in symbolic_vars:
        for keyword in taint_keywords:
            if keyword in var_name:
                taint_sources.append(var_name)
                break

    return RawSymbolicState(
        symbolic_vars=symbolic_vars, symbolic_expressions=symbolic_exprs, taint_sources=taint_sources
    )


def capture_call_stack(state: SimState) -> RawCallStack:
    """Capture call stack information."""
    return_addrs = []
    func_names = []

    # Try to get return addresses from stack
    try:
        if hasattr(state.regs, "rsp"):
            stack_ptr = state.solver.eval(state.regs.rsp)
        elif hasattr(state.regs, "sp"):
            stack_ptr = state.solver.eval(state.regs.sp)
        else:
            stack_ptr = None

        if stack_ptr:
            # Read up to 20 potential return addresses
            for i in range(20):
                try:
                    addr = state.solver.eval(
                        state.memory.load(
                            stack_ptr + (i * state.arch.bytes), state.arch.bytes, endness=state.arch.memory_endness
                        )
                    )
                    # Basic heuristic: kernel addresses on x64 start high
                    if addr > 0x10000:
                        return_addrs.append(addr)
                except:
                    break
    except:
        pass

    # Try to get function names from CFG if available
    # This would require access to the CFG which we might not have here

    return RawCallStack(return_addresses=return_addrs, function_names=func_names, stack_depth=len(return_addrs))


def capture_instruction_context(state: SimState) -> RawInstructionContext:
    """Capture instruction context at vulnerability."""
    addr = state.addr if hasattr(state, "addr") else 0
    instr_bytes = ""
    disasm = ""
    bb_start = addr

    # Try to get instruction bytes
    try:
        block = state.block()
        if block:
            instr_bytes = block.bytes.hex()
            # Try to get disassembly
            try:
                disasm = str(block.capstone)
            except:
                pass
    except:
        pass

    return RawInstructionContext(address=addr, bytes=instr_bytes, disassembly=disasm, basic_block_start=bb_start)


def capture_concrete_inputs(state: SimState, context: AnalysisContext | None) -> RawConcreteInputs:
    """Capture concrete input values that trigger the vulnerability."""
    inputs = RawConcreteInputs()

    if not context:
        return inputs

    # Get concrete IOCTL code
    if context.io_control_code is not None:
        try:
            inputs.ioctl_code = state.solver.eval(context.io_control_code)
        except:
            pass

    # Get buffer lengths
    if context.input_buffer_length is not None:
        try:
            inputs.input_buffer_length = state.solver.eval(context.input_buffer_length)
        except:
            pass

    if context.output_buffer_length is not None:
        try:
            inputs.output_buffer_length = state.solver.eval(context.output_buffer_length)
        except:
            pass

    # Get buffer addresses
    if context.system_buffer is not None:
        try:
            inputs.system_buffer_addr = state.solver.eval(context.system_buffer)
        except:
            pass

    if context.type3_input_buffer is not None:
        try:
            inputs.type3_input_buffer_addr = state.solver.eval(context.type3_input_buffer)
        except:
            pass

    if context.user_buffer is not None:
        try:
            inputs.user_buffer_addr = state.solver.eval(context.user_buffer)
        except:
            pass

    # Try to get actual buffer content (limited)
    if inputs.system_buffer_addr:
        try:
            # Read first 64 bytes of system buffer
            buf_content = state.solver.eval(state.memory.load(inputs.system_buffer_addr, 64))
            if isinstance(buf_content, int):
                inputs.input_buffer = hex(buf_content)
            else:
                inputs.input_buffer = str(buf_content)
        except:
            pass

    return inputs


def capture_state_globals(state: SimState) -> RawStateGlobals:
    """Capture state globals dictionary."""
    globals_data = RawStateGlobals()

    if not hasattr(state, "globals"):
        return globals_data

    try:
        state_globals = dict(state.globals)

        # Extract known fields
        globals_data.device_object_addr = state_globals.get("device_object_addr")
        globals_data.ioctl_handler = state_globals.get("ioctl_handler")

        # Extract tainted lists
        globals_data.tainted_probe_read = list(state_globals.get("tainted_ProbeForRead", []))
        globals_data.tainted_probe_write = list(state_globals.get("tainted_ProbeForWrite", []))
        globals_data.tainted_mmisvalid = list(state_globals.get("tainted_MmIsAddressValid", []))
        globals_data.tainted_handles = list(state_globals.get("tainted_handles", []))
        globals_data.tainted_eprocess = list(state_globals.get("tainted_eprocess", []))

        # Store any other globals
        skip_keys = {
            "device_object_addr",
            "ioctl_handler",
            "tainted_ProbeForRead",
            "tainted_ProbeForWrite",
            "tainted_MmIsAddressValid",
            "tainted_handles",
            "tainted_eprocess",
            "analysis_context",
        }

        for key, value in state_globals.items():
            if key not in skip_keys:
                try:
                    # Try to serialize the value
                    if isinstance(value, int | str | bool | list | dict):
                        globals_data.custom_globals[key] = value
                    else:
                        globals_data.custom_globals[key] = str(value)
                except:
                    pass
    except:
        pass

    return globals_data


def capture_memory_snapshots(
    state: SimState, context: AnalysisContext | None, max_regions: int = 5
) -> RawMemorySnapshot:
    """Capture memory snapshots at key addresses.

    This is limited to avoid huge output files.
    """
    snapshots = {}
    symbolic_regions = []

    # Key addresses to snapshot (if they exist and are concrete)
    key_addrs = []

    if context:
        # Add buffer addresses if available
        for buf_name, buf_var in [
            ("SystemBuffer", context.system_buffer),
            ("Type3InputBuffer", context.type3_input_buffer),
            ("UserBuffer", context.user_buffer),
        ]:
            if buf_var is not None:
                try:
                    addr = state.solver.eval(buf_var)
                    if addr and addr > 0x1000:  # Skip null/low addresses
                        key_addrs.append((buf_name, addr))
                except:
                    # Buffer is symbolic - note it
                    symbolic_regions.append({"name": buf_name, "expression": str(buf_var)})

    # Add current instruction address region
    if hasattr(state, "addr"):
        key_addrs.append(("instruction_region", state.addr & ~0xFFF))  # Page-align

    # Capture memory at key addresses (limit regions and size)
    for i, (name, addr) in enumerate(key_addrs[:max_regions]):
        try:
            # Read 256 bytes max per region
            mem_content = state.memory.load(addr, 256)
            if hasattr(mem_content, "symbolic") and mem_content.symbolic:
                symbolic_regions.append(
                    {
                        "name": name,
                        "address": hex(addr),
                        "expression": str(mem_content)[:200],  # Limit expression length
                    }
                )
            else:
                # Get concrete bytes
                concrete_bytes = state.solver.eval(mem_content, cast_to=bytes)
                snapshots[hex(addr)] = concrete_bytes.hex()[:512]  # Limit to 256 bytes (512 hex chars)
        except:
            pass

    return RawMemorySnapshot(snapshots=snapshots, symbolic_regions=symbolic_regions)
