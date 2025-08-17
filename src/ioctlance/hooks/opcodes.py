"""Low-level CPU instruction hooks for vulnerability detection."""

import claripy
from angr import SimState


def is_tainted(value) -> bool:
    """Check if a value is tainted (user-controlled).

    Args:
        value: Value to check (register, memory, etc.)

    Returns:
        True if the value is symbolic (user-controlled)
    """
    if hasattr(value, "symbolic"):
        return value.symbolic
    return isinstance(value, claripy.ast.Base) and value.symbolic


def wrmsr_hook(state: SimState) -> None:
    """Hook for wrmsr instruction - Write Model Specific Register.

    Checks if user can control MSR writes which could lead to privilege escalation.

    Args:
        state: Current simulation state
    """
    # Get the context from state globals
    context = state.globals.get("analysis_context")
    if not context:
        return

    # Check if we can control the parameters of wrmsr
    # ECX = MSR address, EDX:EAX = value to write
    if is_tainted(state.regs.eax) and is_tainted(state.regs.ecx) and is_tainted(state.regs.edx):
        # Check if the register can be set to critical MSRs
        tmp_state = state.copy()

        # Critical MSRs that could lead to privilege escalation
        critical_msrs = [
            0x174,  # IA32_SYSENTER_CS
            0x175,  # IA32_SYSENTER_ESP
            0x176,  # IA32_SYSENTER_EIP
            0xC0000081,  # MSR_STAR
            0xC0000082,  # MSR_LSTAR
            0xC0000083,  # MSR_CSTAR
        ]

        # Build constraint for critical MSRs
        constraints = []
        for msr in critical_msrs:
            constraints.append(tmp_state.regs.ecx == msr)

        tmp_state.solver.add(claripy.Or(*constraints))

        if tmp_state.satisfiable():
            # Create vulnerability report
            vuln = {
                "title": "arbitrary wrmsr",
                "description": "User can control Model Specific Register writes",
                "state": repr(state),
                "eval": {
                    "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                    "MSR": str(state.regs.ecx),
                    "Value_EDX": str(state.regs.edx),
                    "Value_EAX": str(state.regs.eax),
                },
                "parameters": {},
                "others": {"critical_msrs": [hex(msr) for msr in critical_msrs]},
            }

            if hasattr(context, "vulnerabilities"):
                context.vulnerabilities.append(vuln)
                context.print_info(f"Found arbitrary wrmsr vulnerability at {state.addr:#x}")


def out_hook(state: SimState) -> None:
    """Hook for out instruction - Output to I/O port.

    Checks if user can control I/O port writes which could lead to system compromise.

    Args:
        state: Current simulation state
    """
    context = state.globals.get("analysis_context")
    if not context:
        return

    # Check if we can control the parameters of out
    # DX = port, AL/AX/EAX = data
    if is_tainted(state.regs.eax) and is_tainted(state.regs.edx):
        # Check if port 0xCF9 (system reset) is reachable
        tmp_state = state.copy()
        tmp_state.solver.add(tmp_state.regs.dx == 0xCF9)
        tmp_state.solver.add(tmp_state.regs.ax == 0xE)  # Reset command

        if tmp_state.satisfiable():
            vuln = {
                "title": "arbitrary out",
                "description": "User can control I/O port writes (potential system reset)",
                "state": repr(state),
                "eval": {
                    "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                    "Port": str(state.regs.dx),
                    "Data": str(state.regs.al),
                },
                "parameters": {},
                "others": {"critical_port": "0xCF9 (system reset)"},
            }

            if hasattr(context, "vulnerabilities"):
                context.vulnerabilities.append(vuln)
                context.print_info(f"Found arbitrary I/O port write at {state.addr:#x}")


def rep_movsb_hook(state: SimState) -> None:
    """Hook for rep movsb - Repeat move string byte.

    Checks for buffer overflow via string operations.

    Args:
        state: Current simulation state
    """
    context = state.globals.get("analysis_context")
    if not context:
        return

    dst = state.regs.rdi
    src = state.regs.rsi
    count = state.regs.ecx

    # Check if count is tainted and can be large
    if is_tainted(count):
        tmp_state = state.copy()
        # Check if count can be > 0x1000 (potential overflow)
        tmp_state.solver.add(count > 0x1000)

        if tmp_state.satisfiable():
            max_count = tmp_state.solver.max(count)

            vuln = {
                "title": "potential buffer overflow (rep movsb)",
                "description": f"User-controlled string copy length (max: {max_count:#x})",
                "state": repr(state),
                "eval": {
                    "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                    "Destination": str(dst),
                    "Source": str(src),
                    "Count": str(count),
                },
                "parameters": {},
                "others": {"max_count": hex(max_count) if isinstance(max_count, int) else str(max_count)},
            }

            if hasattr(context, "vulnerabilities"):
                context.vulnerabilities.append(vuln)
                context.print_info(f"Found potential buffer overflow (rep movsb) at {state.addr:#x}")

    # Perform the actual string copy (limited for performance)
    try:
        concrete_count = state.solver.eval(count)
        if concrete_count <= 0:
            concrete_count = 1
        elif concrete_count > 0x1000:
            concrete_count = 0x1000

        val = state.memory.load(src, concrete_count)
        state.memory.store(dst, val)
    except:
        # If we can't evaluate, just do a small symbolic copy
        val = state.memory.load(src, 1)
        state.memory.store(dst, val)


def rep_movsw_hook(state: SimState) -> None:
    """Hook for rep movsw - Repeat move string word."""
    _rep_movs_generic(state, 2, "rep movsw")


def rep_movsd_hook(state: SimState) -> None:
    """Hook for rep movsd - Repeat move string dword."""
    _rep_movs_generic(state, 4, "rep movsd")


def _rep_movs_generic(state: SimState, element_size: int, insn_name: str) -> None:
    """Generic handler for rep movs* instructions.

    Args:
        state: Current simulation state
        element_size: Size of each element (2 for word, 4 for dword)
        insn_name: Name of the instruction for reporting
    """
    context = state.globals.get("analysis_context")
    if not context:
        return

    dst = state.regs.rdi
    src = state.regs.rsi
    count = state.regs.ecx

    # Check if count is tainted and can be large
    if is_tainted(count):
        tmp_state = state.copy()
        # Check if byte count can be > 0x1000
        tmp_state.solver.add(count * element_size > 0x1000)

        if tmp_state.satisfiable():
            max_count = tmp_state.solver.max(count)

            vuln = {
                "title": f"potential buffer overflow ({insn_name})",
                "description": f"User-controlled string copy length (max: {max_count:#x} elements)",
                "state": repr(state),
                "eval": {
                    "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                    "Destination": str(dst),
                    "Source": str(src),
                    "Count": str(count),
                },
                "parameters": {},
                "others": {
                    "max_bytes": hex(max_count * element_size) if isinstance(max_count, int) else str(max_count)
                },
            }

            if hasattr(context, "vulnerabilities"):
                context.vulnerabilities.append(vuln)
                context.print_info(f"Found potential buffer overflow ({insn_name}) at {state.addr:#x}")

    # Perform limited copy
    try:
        concrete_count = state.solver.eval(count)
        if concrete_count <= 0:
            concrete_count = 1
        elif concrete_count > 0x400:  # Limit to 1024 elements
            concrete_count = 0x400

        val = state.memory.load(src, concrete_count * element_size)
        state.memory.store(dst, val)
    except:
        pass


def rep_stosb_hook(state: SimState) -> None:
    """Hook for rep stosb - Repeat store string byte."""
    _rep_stos_generic(state, 1, "al", "rep stosb")


def rep_stosw_hook(state: SimState) -> None:
    """Hook for rep stosw - Repeat store string word."""
    _rep_stos_generic(state, 2, "ax", "rep stosw")


def rep_stosd_hook(state: SimState) -> None:
    """Hook for rep stosd - Repeat store string dword."""
    _rep_stos_generic(state, 4, "eax", "rep stosd")


def rep_stosq_hook(state: SimState) -> None:
    """Hook for rep stosq - Repeat store string qword."""
    _rep_stos_generic(state, 8, "rax", "rep stosq")


def _rep_stos_generic(state: SimState, element_size: int, reg_name: str, insn_name: str) -> None:
    """Generic handler for rep stos* instructions.

    Args:
        state: Current simulation state
        element_size: Size of each element
        reg_name: Name of the source register
        insn_name: Name of the instruction
    """
    context = state.globals.get("analysis_context")
    if not context:
        return

    dst = state.regs.rdi
    value = getattr(state.regs, reg_name)
    count = state.regs.ecx

    # Check if count is tainted and can be large
    if is_tainted(count):
        tmp_state = state.copy()
        # Check if byte count can be > 0x1000
        tmp_state.solver.add(count * element_size > 0x1000)

        if tmp_state.satisfiable():
            max_count = tmp_state.solver.max(count)

            vuln = {
                "title": f"potential buffer overflow ({insn_name})",
                "description": f"User-controlled memory fill length (max: {max_count:#x} elements)",
                "state": repr(state),
                "eval": {
                    "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                    "Destination": str(dst),
                    "Value": str(value),
                    "Count": str(count),
                },
                "parameters": {},
                "others": {
                    "max_bytes": hex(max_count * element_size) if isinstance(max_count, int) else str(max_count)
                },
            }

            if hasattr(context, "vulnerabilities"):
                context.vulnerabilities.append(vuln)
                context.print_info(f"Found potential buffer overflow ({insn_name}) at {state.addr:#x}")


def int_hook(state: SimState) -> None:
    """Hook for int instruction - Software interrupt.

    Checks if user can trigger arbitrary interrupts.
    """
    context = state.globals.get("analysis_context")
    if not context:
        return

    # For int instruction, the interrupt number is usually immediate
    # But check if any registers that might affect it are tainted
    if is_tainted(state.regs.rax) or is_tainted(state.regs.rcx):
        vuln = {
            "title": "software interrupt with tainted context",
            "description": "User-controlled registers during interrupt",
            "state": repr(state),
            "eval": {
                "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                "RAX": str(state.regs.rax),
                "RCX": str(state.regs.rcx),
            },
            "parameters": {},
            "others": {},
        }

        if hasattr(context, "vulnerabilities"):
            context.vulnerabilities.append(vuln)


def lock_hook(state: SimState) -> None:
    """Hook for lock prefix - Atomic operation.

    Checks for potential race conditions or deadlocks.
    """
    # Lock prefix itself isn't a vulnerability, but track it for analysis
    pass


def rdpmc_hook(state: SimState) -> None:
    """Hook for rdpmc - Read Performance Monitoring Counter."""
    context = state.globals.get("analysis_context")
    if not context:
        return

    # Check if ECX (counter selection) is tainted
    if is_tainted(state.regs.ecx):
        vuln = {
            "title": "performance counter read with tainted selector",
            "description": "User can control which performance counter to read",
            "state": repr(state),
            "eval": {
                "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                "Counter": str(state.regs.ecx),
            },
            "parameters": {},
            "others": {},
        }

        if hasattr(context, "vulnerabilities"):
            context.vulnerabilities.append(vuln)


def outs_hook(state: SimState) -> None:
    """Hook for outs* instructions - Output string to port."""
    context = state.globals.get("analysis_context")
    if not context:
        return

    # Check if port (DX) or source (RSI) is tainted
    if is_tainted(state.regs.dx) or is_tainted(state.regs.rsi):
        vuln = {
            "title": "string output to I/O port",
            "description": "User-controlled I/O port string write",
            "state": repr(state),
            "eval": {
                "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                "Port": str(state.regs.dx),
                "Source": str(state.regs.rsi),
            },
            "parameters": {},
            "others": {},
        }

        if hasattr(context, "vulnerabilities"):
            context.vulnerabilities.append(vuln)


def ins_hook(state: SimState) -> None:
    """Hook for ins* instructions - Input string from port."""
    context = state.globals.get("analysis_context")
    if not context:
        return

    # Check if port (DX) or destination (RDI) is tainted
    if is_tainted(state.regs.dx) or is_tainted(state.regs.rdi):
        vuln = {
            "title": "string input from I/O port",
            "description": "User-controlled I/O port string read",
            "state": repr(state),
            "eval": {
                "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                "Port": str(state.regs.dx),
                "Destination": str(state.regs.rdi),
            },
            "parameters": {},
            "others": {},
        }

        if hasattr(context, "vulnerabilities"):
            context.vulnerabilities.append(vuln)


def lfence_hook(state: SimState) -> None:
    """Hook for lfence - Load fence (memory barrier)."""
    # Track for side-channel analysis but not a direct vulnerability
    pass


def pushfw_hook(state: SimState) -> None:
    """Hook for pushfw - Push FLAGS register."""
    # Track for analysis
    pass


def popfw_hook(state: SimState) -> None:
    """Hook for popfw - Pop FLAGS register."""
    context = state.globals.get("analysis_context")
    if not context:
        return

    # Check if stack value that will be popped is tainted
    sp = state.regs.rsp
    try:
        flags_value = state.memory.load(sp, 2)
        if is_tainted(flags_value):
            vuln = {
                "title": "FLAGS register control",
                "description": "User can control processor FLAGS",
                "state": repr(state),
                "eval": {
                    "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
                    "Stack_Value": str(flags_value),
                },
                "parameters": {},
                "others": {},
            }

            if hasattr(context, "vulnerabilities"):
                context.vulnerabilities.append(vuln)
    except:
        pass


def sidt_hook(state: SimState) -> None:
    """Hook for sidt - Store Interrupt Descriptor Table."""
    # Information disclosure - reveals IDT location
    context = state.globals.get("analysis_context")
    if not context:
        return

    vuln = {
        "title": "IDT location disclosure",
        "description": "Reveals Interrupt Descriptor Table address",
        "state": repr(state),
        "eval": {
            "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
        },
        "parameters": {},
        "others": {},
    }

    if hasattr(context, "vulnerabilities"):
        context.vulnerabilities.append(vuln)


def lidt_hook(state: SimState) -> None:
    """Hook for lidt - Load Interrupt Descriptor Table."""
    context = state.globals.get("analysis_context")
    if not context:
        return

    # This is extremely dangerous if reachable from user mode
    vuln = {
        "title": "CRITICAL: IDT modification",
        "description": "Can modify Interrupt Descriptor Table",
        "state": repr(state),
        "eval": {
            "IoControlCode": hex(context.io_control_code) if hasattr(context, "io_control_code") else "N/A",
        },
        "parameters": {},
        "others": {"severity": "CRITICAL"},
    }

    if hasattr(context, "vulnerabilities"):
        context.vulnerabilities.append(vuln)
        context.print_error(f"CRITICAL: Found IDT modification capability at {state.addr:#x}")
