"""Raw state data models for capturing complete vulnerability context."""

from typing import Any
from pydantic import BaseModel, Field


class RawConstraints(BaseModel):
    """Raw SMT constraints from the solver."""

    constraints: list[str] = Field(default_factory=list, description="String representation of all SMT constraints")
    satisfiable: bool = Field(default=True, description="Whether the constraints are satisfiable")


class RawExecutionTrace(BaseModel):
    """Raw execution trace information."""

    basic_blocks: list[int] = Field(default_factory=list, description="Basic block addresses visited in order")
    instructions_executed: int = Field(default=0, description="Total instructions executed")
    call_depth: int = Field(default=0, description="Maximum call stack depth reached")
    unique_addresses: int = Field(default=0, description="Number of unique addresses visited")


class RawRegisters(BaseModel):
    """Raw register values at vulnerability point."""

    registers: dict[str, int | str] = Field(
        default_factory=dict, description="Register name to value mapping (hex strings or ints)"
    )
    symbolic_registers: list[str] = Field(default_factory=list, description="Names of registers that are symbolic")


class RawMemorySnapshot(BaseModel):
    """Raw memory content at key addresses."""

    snapshots: dict[str, str] = Field(default_factory=dict, description="Address (hex) to memory content (hex) mapping")
    symbolic_regions: list[dict[str, Any]] = Field(default_factory=list, description="Memory regions that are symbolic")


class RawSymbolicState(BaseModel):
    """Raw symbolic variable information."""

    symbolic_vars: dict[str, Any] = Field(
        default_factory=dict, description="Symbolic variable names and their possible values"
    )
    symbolic_expressions: dict[str, str] = Field(
        default_factory=dict, description="Key symbolic expressions (AST string representations)"
    )
    taint_sources: list[str] = Field(default_factory=list, description="Tainted input sources")


class RawCallStack(BaseModel):
    """Raw call stack information."""

    return_addresses: list[int] = Field(default_factory=list, description="Return addresses on the stack")
    function_names: list[str] = Field(default_factory=list, description="Function names if available")
    stack_depth: int = Field(default=0, description="Current stack depth")


class RawInstructionContext(BaseModel):
    """Raw instruction context at vulnerability."""

    address: int = Field(..., description="Instruction address")
    bytes: str = Field(default="", description="Hex string of instruction bytes")
    disassembly: str = Field(default="", description="Disassembled instruction if available")
    basic_block_start: int = Field(default=0, description="Start address of containing basic block")


class RawConcreteInputs(BaseModel):
    """Concrete input values that trigger the vulnerability."""

    ioctl_code: int | None = Field(None, description="Concrete IOCTL code value")
    input_buffer: str | None = Field(None, description="Hex string of input buffer content")
    input_buffer_length: int | None = Field(None, description="Input buffer length")
    output_buffer_length: int | None = Field(None, description="Output buffer length")
    system_buffer_addr: int | None = Field(None, description="System buffer address")
    type3_input_buffer_addr: int | None = Field(None, description="Type3 input buffer address")
    user_buffer_addr: int | None = Field(None, description="User buffer address")
    additional_inputs: dict[str, Any] = Field(default_factory=dict, description="Any additional concrete inputs")


class RawStateGlobals(BaseModel):
    """Raw state globals dictionary."""

    device_object_addr: int | None = Field(None, description="Device object address")
    ioctl_handler: int | None = Field(None, description="IOCTL handler address")
    tainted_probe_read: list[str] = Field(default_factory=list, description="Addresses validated by ProbeForRead")
    tainted_probe_write: list[str] = Field(default_factory=list, description="Addresses validated by ProbeForWrite")
    tainted_mmisvalid: list[str] = Field(default_factory=list, description="Addresses validated by MmIsAddressValid")
    tainted_handles: list[int] = Field(default_factory=list, description="Tainted handle values")
    tainted_eprocess: list[str] = Field(default_factory=list, description="Tainted EPROCESS pointers")
    custom_globals: dict[str, Any] = Field(default_factory=dict, description="Any other custom globals")


class RawVulnerabilityData(BaseModel):
    """Complete raw data for a vulnerability."""

    constraints: RawConstraints | None = Field(None, description="SMT constraints")
    execution_trace: RawExecutionTrace | None = Field(None, description="Execution trace")
    registers: RawRegisters | None = Field(None, description="Register state")
    memory: RawMemorySnapshot | None = Field(None, description="Memory snapshots")
    symbolic_state: RawSymbolicState | None = Field(None, description="Symbolic state information")
    call_stack: RawCallStack | None = Field(None, description="Call stack")
    instruction_context: RawInstructionContext | None = Field(None, description="Instruction context")
    concrete_inputs: RawConcreteInputs | None = Field(None, description="Concrete input values")
    state_globals: RawStateGlobals | None = Field(None, description="State globals")
