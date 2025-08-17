"""Breakpoint handlers for vulnerability detection during symbolic execution."""

import logging
from typing import Any, cast

import claripy
from angr import SimState

logger = logging.getLogger(__name__)

from ..core.analysis_context import AnalysisContext
from ..utils.helpers import get_state_globals
from ..utils.state_capture import capture_raw_state

# Target buffers for null pointer dereference detection
NPD_TARGETS = ["SystemBuffer", "Type3InputBuffer", "UserBuffer"]


def b_mem_write_ioctl_handler(state: SimState, context: AnalysisContext) -> None:
    """Store the address of IOCTL handler when written to driver object.

    Args:
        state: Current simulation state
        context: Analysis context
    """
    ioctl_handler_addr = state.solver.eval(state.inspect.mem_write_expr)
    context.ioctl_handler = int(ioctl_handler_addr)
    globals_dict = get_state_globals(state)
    globals_dict["ioctl_handler"] = context.ioctl_handler
    # Move deadended states to drop after finding handler
    if context.simulation_manager:
        context.simulation_manager.move(from_stash="deadended", to_stash="_Drop")


def b_mem_write_DriverStartIo(state: SimState, context: AnalysisContext) -> None:
    """Store the address of DriverStartIo when written to driver object.

    Args:
        state: Current simulation state
        context: Analysis context
    """
    driver_startio_addr = state.solver.eval(state.inspect.mem_write_expr)
    # Store in context if we add a DriverStartIo field
    logger.debug(f"DriverStartIo: {hex(int(driver_startio_addr))}")


def b_mem_read(state: SimState, context: AnalysisContext) -> None:
    """Check memory reads for vulnerability patterns.

    This is a critical function that detects:
    - Null pointer dereferences
    - Arbitrary read/write vulnerabilities
    - Unvalidated pointer usage

    Args:
        state: Current simulation state
        context: Analysis context
    """
    context.print_debug(
        f"mem_read {state}, addr={state.inspect.mem_read_address}, "
        f"expr={state.inspect.mem_read_expr}, len={state.inspect.mem_read_length}"
    )

    # Use detectors if available
    if hasattr(context, "detectors") and context.detectors:
        for detector in context.detectors:
            if detector.enabled:
                vuln_info = detector.check_state(state, "mem_read", address=state.inspect.mem_read_address)
                if vuln_info:
                    context.add_vulnerability(vuln_info)
                    logger.debug(f"[VULN] {vuln_info['title']}: {vuln_info['description']}")
                    return  # Stop after first detection to avoid duplicates

    # Check each target buffer for vulnerabilities
    for target in NPD_TARGETS:
        if target in str(state.inspect.mem_read_address):
            asts = [i for i in state.inspect.mem_read_address.children_asts()]
            target_base = asts[0] if len(asts) > 1 else state.inspect.mem_read_address
            vars = state.inspect.mem_read_address.variables

            # Check if not already validated by ProbeForRead/Write
            tainted_probe_read = state.globals.get("tainted_ProbeForRead", ())
            tainted_probe_write = state.globals.get("tainted_ProbeForWrite", ())
            tainted_mmisvalid = state.globals.get("tainted_MmIsAddressValid", ())

            if (
                str(target_base) not in tainted_probe_read
                and str(target_base) not in tainted_probe_write
                and len(vars) == 1
            ):
                tmp_state = state.copy()

                if target == "SystemBuffer":
                    if "*" in str(state.inspect.mem_read_address):
                        # SystemBuffer is a pointer - check if controllable
                        tmp_state.solver.add(tmp_state.inspect.mem_read_address == 0x87)
                        if tmp_state.satisfiable() and str(target_base) not in tainted_mmisvalid:
                            _record_vulnerability(
                                context,
                                state,
                                title="read/write controllable address",
                                description="read",
                                others={"read from": str(state.inspect.mem_read_address)},
                            )
                    else:
                        # SystemBuffer is not a pointer - check for null
                        tmp_state.solver.add(context.system_buffer == 0)
                        tmp_state.solver.add(context.input_buffer_length == 0)
                        tmp_state.solver.add(context.output_buffer_length == 0)
                        if tmp_state.satisfiable() and str(target_base) not in tainted_mmisvalid:
                            _record_vulnerability(
                                context,
                                state,
                                title="null pointer dereference - input buffer",
                                description="read input buffer",
                                others={"read from": str(state.inspect.mem_read_address)},
                            )

                elif target in ("Type3InputBuffer", "UserBuffer"):
                    # Check if Type3InputBuffer or UserBuffer is controllable
                    if target == "Type3InputBuffer":
                        tmp_state.solver.add(context.type3_input_buffer == 0x87)
                    else:
                        tmp_state.solver.add(context.user_buffer == 0x87)

                    if tmp_state.satisfiable() and str(target_base) not in tainted_mmisvalid:
                        _record_vulnerability(
                            context,
                            state,
                            title=f"read/write controllable address - {target}",
                            description="read",
                            others={"read from": str(state.inspect.mem_read_address)},
                        )
                else:
                    # Detect null pointer in allocated memory
                    if "+" not in str(state.inspect.mem_read_address):
                        tmp_state.solver.add(state.inspect.mem_read_address == 0)
                        if tmp_state.satisfiable():
                            _record_vulnerability(
                                context,
                                state,
                                title="null pointer dereference - allocated memory",
                                description="read allocated memory",
                                others={"read from": str(state.inspect.mem_read_address)},
                            )

            # Symbolize tainted buffer addresses for vulnerability detection
            from ..utils.helpers import is_tainted_buffer

            if is_tainted_buffer(target_base) and str(target_base) not in state.globals:
                tmp_state = state.copy()
                tmp_state.solver.add(target_base == context.next_base_addr())
                if tmp_state.satisfiable():
                    globals_dict = get_state_globals(state)
                    globals_dict[str(target_base)] = True
                    mem = claripy.BVS(f"*{str(target_base)}", 8 * 0x200).reversed
                    addr = context.next_base_addr()
                    state.solver.add(target_base == addr)
                    state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)


def b_mem_write(state: SimState, context: AnalysisContext) -> None:
    """Check memory writes for vulnerability patterns.

    Detects:
    - Arbitrary write vulnerabilities
    - Buffer overflows
    - Unvalidated write operations

    Args:
        state: Current simulation state
        context: Analysis context
    """
    context.print_debug(
        f"mem_write {state}, addr={state.inspect.mem_write_address}, "
        f"expr={state.inspect.mem_write_expr}, len={state.inspect.mem_write_length}"
    )

    # Use detectors if available
    if hasattr(context, "detectors") and context.detectors:
        for detector in context.detectors:
            if detector.enabled:
                vuln_info = detector.check_state(
                    state,
                    "mem_write",
                    address=state.inspect.mem_write_address,
                    size=state.inspect.mem_write_length,
                    value=state.inspect.mem_write_expr,
                )
                if vuln_info:
                    context.add_vulnerability(vuln_info)
                    logger.debug(f"[VULN] {vuln_info['title']}: {vuln_info['description']}")
                    return  # Stop after first detection to avoid duplicates

    # Check each target buffer
    for target in NPD_TARGETS:
        if target in str(state.inspect.mem_write_address):
            asts = [i for i in state.inspect.mem_write_address.children_asts()]
            target_base = asts[0] if len(asts) > 1 else state.inspect.mem_write_address
            vars = state.inspect.mem_write_address.variables

            tainted_probe_read = state.globals.get("tainted_ProbeForRead", ())
            tainted_probe_write = state.globals.get("tainted_ProbeForWrite", ())
            tainted_mmisvalid = state.globals.get("tainted_MmIsAddressValid", ())

            if (
                str(target_base) not in tainted_probe_read
                and str(target_base) not in tainted_probe_write
                and len(vars) == 1
            ):
                tmp_state = state.copy()

                if target == "SystemBuffer":
                    if "*" in str(state.inspect.mem_write_address):
                        # Arbitrary write through SystemBuffer pointer
                        tmp_state.solver.add(tmp_state.inspect.mem_write_address == 0x87)
                        if tmp_state.satisfiable() and str(target_base) not in tainted_mmisvalid:
                            _record_vulnerability(
                                context,
                                state,
                                title="arbitrary write",
                                description="write through controllable pointer",
                                others={"write to": str(state.inspect.mem_write_address)},
                            )
                    else:
                        # Null pointer write
                        tmp_state.solver.add(context.system_buffer == 0)
                        tmp_state.solver.add(context.input_buffer_length == 0)
                        tmp_state.solver.add(context.output_buffer_length == 0)
                        if tmp_state.satisfiable() and str(target_base) not in tainted_mmisvalid:
                            _record_vulnerability(
                                context,
                                state,
                                title="null pointer dereference - output buffer",
                                description="write to output buffer",
                                others={"write to": str(state.inspect.mem_write_address)},
                            )

                elif target in ("Type3InputBuffer", "UserBuffer"):
                    # Arbitrary write through Type3InputBuffer/UserBuffer
                    if target == "Type3InputBuffer":
                        tmp_state.solver.add(context.type3_input_buffer == 0x87)
                    else:
                        tmp_state.solver.add(context.user_buffer == 0x87)

                    if tmp_state.satisfiable() and str(target_base) not in tainted_mmisvalid:
                        _record_vulnerability(
                            context,
                            state,
                            title=f"arbitrary write - {target}",
                            description="write through controllable pointer",
                            others={"write to": str(state.inspect.mem_write_address)},
                        )
                else:
                    # Detect null pointer in allocated memory
                    if "+" not in str(state.inspect.mem_write_address):
                        tmp_state.solver.add(state.inspect.mem_write_address == 0)
                        if tmp_state.satisfiable():
                            _record_vulnerability(
                                context,
                                state,
                                title="null pointer dereference - allocated memory",
                                description="write allocated memory",
                                others={"write to": str(state.inspect.mem_write_address)},
                            )

            # Symbolize tainted buffer addresses for vulnerability detection
            from ..utils.helpers import is_tainted_buffer

            if is_tainted_buffer(target_base) and str(target_base) not in state.globals:
                tmp_state = state.copy()
                tmp_state.solver.add(target_base == context.next_base_addr())
                if tmp_state.satisfiable():
                    globals_dict = get_state_globals(state)
                    globals_dict[str(target_base)] = True
                    mem = claripy.BVS(f"*{str(target_base)}", 8 * 0x200).reversed
                    addr = context.next_base_addr()
                    state.solver.add(target_base == addr)
                    state.memory.store(addr, mem, 0x200, disable_actions=True, inspect=False)


def b_call(state: SimState, context: AnalysisContext) -> None:
    """Monitor function calls during execution.

    Detects:
    - Arbitrary shellcode execution
    - Indirect calls to tainted addresses

    Args:
        state: Current simulation state
        context: Analysis context
    """
    # Get return address for logging
    ret_addr = 0
    try:
        ret_addr = state.solver.eval(
            state.memory.load(
                state.regs.rsp if hasattr(state.regs, "rsp") else state.regs.sp,
                state.arch.bytes,
                endness=state.arch.memory_endness,
            )
        )
    except:
        pass

    context.print_debug(
        f"call: state={state}, ret_addr={hex(ret_addr)}, function_addr={state.inspect.function_address}"
    )

    # Use detectors if available
    if hasattr(context, "detectors") and context.detectors:
        for detector in context.detectors:
            if detector.enabled:
                vuln_info = detector.check_state(
                    state,
                    "call",
                    function_address=state.inspect.function_address,
                    return_address=ret_addr,
                )
                if vuln_info:
                    # Set RIP to marker value
                    if hasattr(state.regs, "rip"):
                        state.regs.rip = 0x1337
                    else:
                        state.regs.ip = 0x1337
                    context.add_vulnerability(vuln_info)
                    logger.debug(f"[VULN] {vuln_info['title']}: {vuln_info['description']}")
                    return  # Stop after first detection

    # Check if the function address to call is tainted (arbitrary shellcode execution)
    from ..utils.helpers import is_tainted_buffer

    if is_tainted_buffer(state.inspect.function_address):
        # Set RIP to a marker value to indicate exploitation
        if hasattr(state.regs, "rip"):
            state.regs.rip = 0x1337
        else:
            state.regs.ip = 0x1337

        _record_vulnerability(
            context,
            state,
            title="arbitrary shellcode execution",
            description="call to tainted function address",
            others={
                "function_address": str(state.inspect.function_address),
                "return_address": hex(ret_addr),
            },
        )

    # If function address has multiple solutions, skip the call to avoid path explosion
    try:
        possible_addrs = state.solver.eval_upto(state.inspect.function_address, 2)
        if len(possible_addrs) > 1:
            # Create a deferred state to explore later
            tmp_state = state.copy()
            if hasattr(tmp_state.regs, "rip"):
                tmp_state.regs.rip = context.do_nothing_addr
            else:
                tmp_state.regs.ip = context.do_nothing_addr

            if context.simulation_manager:
                context.simulation_manager.deferred.append(tmp_state)

            # Return unconstrained to skip this path
            import angr

            return angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]().execute(state)
    except:
        pass


def b_address_concretization_before(state: SimState, context: AnalysisContext) -> None:
    """Handle address concretization before it happens.

    Args:
        state: Current simulation state
        context: Analysis context
    """
    context.print_debug(f"address_concretization_before: {state.inspect.address_concretization_expr}")


def b_address_concretization_after(state: SimState, context: AnalysisContext) -> None:
    """Handle address concretization after it happens.

    Args:
        state: Current simulation state
        context: Analysis context
    """
    context.print_debug(f"address_concretization_after: {state.inspect.address_concretization_result}")


def b_dirty(state: SimState, context: AnalysisContext) -> None:
    """Handle VEX dirty calls (special IR operations).

    Args:
        state: Current simulation state
        context: Analysis context
    """
    # Dirty calls are used for complex x86 instructions
    pass


def _record_vulnerability(
    context: AnalysisContext,
    state: SimState,
    title: str,
    description: str,
    parameters: dict | None = None,
    others: dict | None = None,
) -> None:
    """Record a discovered vulnerability.

    Args:
        context: Analysis context
        state: Current simulation state
        title: Vulnerability title
        description: Vulnerability description
        parameters: Evaluation parameters
        others: Additional information
    """
    # Get evaluation values
    eval_params = {}
    if context.io_control_code:
        try:
            ioctl = state.solver.eval_one(context.io_control_code)
            eval_params["IoControlCode"] = hex(ioctl)
        except:
            eval_params["IoControlCode"] = str(context.io_control_code)

    # Add buffer values
    for name, buf in [
        ("SystemBuffer", context.system_buffer),
        ("Type3InputBuffer", context.type3_input_buffer),
        ("UserBuffer", context.user_buffer),
        ("InputBufferLength", context.input_buffer_length),
        ("OutputBufferLength", context.output_buffer_length),
    ]:
        if buf is not None:
            try:
                val = state.solver.eval_one(buf)
                eval_params[name] = hex(val) if isinstance(val, int) else str(val)
            except:
                eval_params[name] = str(buf)

    # Capture raw state data for enhanced analysis
    raw_data = None
    try:
        raw_data = capture_raw_state(state, context)
    except Exception as e:
        # Don't fail vulnerability recording if raw capture fails
        context.print_debug(f"Failed to capture raw state data: {e}")

    vuln_info = {
        "title": title,
        "description": description,
        "state": str(state),
        "eval": eval_params,
        "parameters": parameters or {},
        "others": others or {},
        "raw_data": raw_data,  # Include raw state data
    }

    context.add_vulnerability(vuln_info)
    logger.debug(f"[VULN] {title}: {description}")


def b_vex_expr(state: SimState, context: AnalysisContext) -> None:
    """Breakpoint for VEX IR expressions to detect arithmetic operations.

    This is called during VEX IR translation to catch arithmetic operations
    that might cause integer overflow/underflow.

    Args:
        state: Current simulation state
        context: Analysis context
    """
    if not state.inspect.expr:
        return

    expr = state.inspect.expr

    # Check if this is an arithmetic operation
    if hasattr(expr, "op"):
        op = expr.op

        # Map VEX operations to our detector operations
        arithmetic_ops = {
            "Iop_Add8": "ADD",
            "Iop_Add16": "ADD",
            "Iop_Add32": "ADD",
            "Iop_Add64": "ADD",
            "Iop_Sub8": "SUB",
            "Iop_Sub16": "SUB",
            "Iop_Sub32": "SUB",
            "Iop_Sub64": "SUB",
            "Iop_Mul8": "MUL",
            "Iop_Mul16": "MUL",
            "Iop_Mul32": "MUL",
            "Iop_Mul64": "MUL",
            "Iop_MullS8": "MUL",
            "Iop_MullS16": "MUL",
            "Iop_MullS32": "MUL",
            "Iop_MullS64": "MUL",
            "Iop_MullU8": "MUL",
            "Iop_MullU16": "MUL",
            "Iop_MullU32": "MUL",
            "Iop_MullU64": "MUL",
        }

        if op in arithmetic_ops:
            op_type = arithmetic_ops[op]

            # Get operands
            operands = expr.args if hasattr(expr, "args") else []

            # Check with integer overflow detector if available
            if hasattr(context, "detectors"):
                for detector in context.detectors:
                    if hasattr(detector, "check_arithmetic_operation"):
                        # Get the operands
                        op1 = operands[0] if len(operands) > 0 else None
                        op2 = operands[1] if len(operands) > 1 else None

                        # Check for overflow/underflow
                        vuln = detector.check_arithmetic_operation(state, op_type, expr, op1, op2)

                        if vuln:
                            context.add_vulnerability(vuln)
