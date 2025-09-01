"""Analysis context for managing state during driver analysis."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

import angr
from angr.calling_conventions import SimCC

# Import kernel types to ensure they're registered with angr
from ..symbolic import kernel_types  # noqa: F401

if TYPE_CHECKING:
    from angr import SimState
    from ..output.manager import OutputManager


@dataclass
class AnalysisConfig:
    """Configuration for driver analysis."""

    timeout: int = 120
    ioctl_timeout: int = 60  # Increased for accuracy
    bound: int = 0  # Loop bound, 0 for unlimited
    length: int = 0  # Instruction length limit, 0 for unlimited
    global_var_size: int = 0  # Bytes of .data section to symbolize
    complete_mode: bool = False
    debug: bool = False
    verbose: bool = False  # Verbose output mode
    recursion_kill: bool = True

    # Additional tuning parameters for symbolic execution
    max_steps: int = 100000  # Maximum symbolic execution steps (reduced from 500000)
    max_states: int = 200  # Maximum concurrent states (reduced from 500)
    handler_max_steps: int = 0x10000  # Max steps for handler discovery (reduced from 0x100000)
    explosion_threshold: int = 2000  # State explosion threshold (reduced from 10000)

    # Memory optimization settings
    cfg_simple: bool = False  # Use simplified CFG (less memory)
    max_symbolic_buffers: int = 50  # Limit symbolic buffer count
    max_buffer_size: int = 0x100  # Max size per buffer (256 bytes)

    # Specific IOCTL to analyze (hex string like "0x22201c")
    target_ioctl: str | None = None

    # IOCTL handler address to skip discovery (hex string like "0x140007080")
    ioctl_handler_addr: str | None = None

    # Functions to exclude (list of hex addresses)
    exclude_functions: list[str] = field(default_factory=list)


@dataclass
class AnalysisContext:
    """Context object to replace global state during analysis."""

    # Core angr objects
    project: angr.Project
    cfg: Any  # angr.analyses.cfg.CFGFast
    calling_convention: SimCC

    # Configuration
    config: AnalysisConfig

    # Analysis phase (1 = finding handler, 2 = hunting vulns)
    phase: int = 1

    # Driver information
    driver_path: Path = field(default_factory=Path)
    driver_type: str = "unknown"  # wdm, wdf, etc.
    device_names: list[str] = field(default_factory=list)

    # IOCTL handler discovery
    ioctl_handler: int = 0
    ioctl_codes: list[str] = field(default_factory=list)

    # Vulnerability tracking
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)
    vuln_buffer: list[str] = field(default_factory=list)  # Buffer for reduced output

    # Symbolic execution state
    simulation_manager: Any | None = None  # angr.SimulationManager

    # Memory addresses for special structures
    irp_addr: int = 0x41410000  # IRP structure address
    irsp_addr: int = 0x41420000  # IO_STACK_LOCATION address
    do_nothing_addr: int = 0x42420000  # Address for no-op hook

    # Symbolic variables (replacing globals)
    system_buffer: Any | None = None  # claripy.BVS
    type3_input_buffer: Any | None = None  # claripy.BVS
    user_buffer: Any | None = None  # claripy.BVS
    output_buffer_length: Any | None = None  # claripy.BVS
    input_buffer_length: Any | None = None  # claripy.BVS
    io_control_code: Any | None = None  # claripy.BVS

    # Performance metrics
    unique_addresses: set[int] = field(default_factory=set)

    # Vulnerability detectors
    detectors: list[Any] = field(default_factory=list)

    # Unified output manager (optional, for enhanced output)
    output_manager: Any | None = None  # OutputManager

    @classmethod
    def create_for_driver(
        cls, driver_path: Path | str, config: AnalysisConfig | None = None, output_manager: Any | None = None
    ) -> "AnalysisContext":
        """Create analysis context for a driver file.

        Args:
            driver_path: Path to the driver file
            config: Analysis configuration (uses defaults if None)
            output_manager: Output manager for enhanced output (optional)

        Returns:
            Configured analysis context
        """
        import archinfo
        from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCStdcall

        path = Path(driver_path) if isinstance(driver_path, str) else driver_path
        config = config or AnalysisConfig()

        # Load the driver with angr
        project = angr.Project(str(path), auto_load_libs=False)

        # Get control flow graph with memory optimizations
        if config.cfg_simple:
            # Use simplified CFG for memory-constrained environments
            cfg = project.analyses.CFGFast(
                symbols=False,  # Don't resolve symbols
                function_prologues=False,  # Skip prologue analysis
                force_complete_scan=False,  # Don't scan everything
                force_smart_scan=False,  # Disable smart scan to avoid warnings
                data_references=False,  # Skip data refs (new parameter name)
                normalize=False,  # Skip normalization
            )
        else:
            # Full CFG for thorough analysis
            cfg = project.analyses.CFGFast()

        # Set calling convention based on architecture
        if project.arch.name == archinfo.ArchX86.name:
            calling_convention = SimCCStdcall(project.arch)
        else:
            calling_convention = SimCCMicrosoftAMD64(project.arch)

        # Create context instance
        context = cls(
            project=project,
            cfg=cfg,
            calling_convention=calling_convention,
            config=config,
            driver_path=path,
            output_manager=output_manager,
        )

        # Initialize output manager if provided
        if output_manager:
            output_manager.initialize(path, config.__dict__)

        # Register all kernel API hooks
        from ..hooks import register_all_hooks

        register_all_hooks(project)

        # Initialize detectors
        from ..detectors import detector_registry

        context.detectors = detector_registry.create_instances(context)

        return context

    def next_base_addr(self) -> int:
        """Get next available base address for allocation.

        Returns:
            Next available address
        """
        if not hasattr(self, "_next_addr"):
            self._next_addr = 0x50000000
        self._next_addr += 0x10000
        return self._next_addr

    def add_vulnerability(self, vuln_info: dict[str, Any]) -> None:
        """Add a discovered vulnerability.

        Args:
            vuln_info: Vulnerability information dictionary
        """
        # Use enhanced reporting if output manager is available
        if self.output_manager:
            state = vuln_info.get("state")
            # Check if state is a SimState object (has solver attribute)
            if state and hasattr(state, "solver"):
                # State is a SimState - pass it directly
                enhanced_vuln = self.output_manager.add_vulnerability(
                    title=vuln_info.get("title", "Unknown vulnerability"),
                    description=vuln_info.get("description", ""),
                    state=state,
                    context=self,
                    parameters=vuln_info.get("parameters", {}),
                    others=vuln_info.get("others", {}),
                )
                vuln_info["enhanced"] = enhanced_vuln
            else:
                # State is not a SimState (might be string or None)
                # Log warning but don't fail
                import logging

                logger = logging.getLogger(__name__)
                logger.debug(f"Vulnerability added without SimState: {vuln_info.get('title')}")

        self.vulnerabilities.append(vuln_info)
        # Buffer the vulnerability title for summary
        if "title" in vuln_info:
            self.vuln_buffer.append(vuln_info["title"])

    def add_error(self, error_msg: str) -> None:
        """Add an error message.

        Args:
            error_msg: Error message to record
        """
        self.error_messages.append(error_msg)

    def print_debug(self, msg: str) -> None:
        """Print debug message if debug mode is enabled.

        Args:
            msg: Debug message to print
        """
        if self.config.debug:
            import logging

            logger = logging.getLogger(__name__)
            logger.debug(msg)

    def print_info(self, msg: str) -> None:
        """Print info message.

        Args:
            msg: Info message to print
        """
        import logging

        logger = logging.getLogger(__name__)
        if self.config.verbose:
            logger.info(msg)
        else:
            logger.debug(msg)

    def print_error(self, msg: str) -> None:
        """Print error message and record it.

        Args:
            msg: Error message to print and record
        """
        import logging

        logger = logging.getLogger(__name__)
        logger.error(msg)
        self.add_error(msg)

    def print_vulnerability_summary(self) -> None:
        """Print a summary of found vulnerabilities."""
        if self.vuln_buffer:
            unique_vulns = list(set(self.vuln_buffer))
            print(f"\n[SUMMARY] Found {len(self.vulnerabilities)} vulnerabilities:")
            for vuln_type in unique_vulns:
                count = self.vuln_buffer.count(vuln_type)
                if count > 1:
                    print(f"  - {vuln_type} ({count} instances)")
                else:
                    print(f"  - {vuln_type}")
