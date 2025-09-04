"""Analysis context for managing state during driver analysis."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

import angr
from angr.calling_conventions import SimCC
from pydantic import BaseModel, Field, field_validator, model_validator

# Import kernel types to ensure they're registered with angr
from ..symbolic import kernel_types  # noqa: F401

if TYPE_CHECKING:
    from angr import SimState
    from ..output.manager import OutputManager


class AnalysisConfig(BaseModel):
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
    max_steps: int = 300000  # Maximum symbolic execution steps (balanced between 100k and 500k)
    max_states: int = 400  # Maximum concurrent states (balanced between 200 and 500)
    handler_max_steps: int = 0x80000  # Max steps for handler discovery (524288, balanced)
    explosion_threshold: int = 5000  # State explosion threshold (balanced between 2k and 10k)

    # Search strategy and beam options
    search_strategy: str = "dfs"  # dfs | beam
    beam_width: int = 64  # Max active states kept by beam search
    triage_steps: int = 0  # If >0, use tighter beam for first N steps
    triage_beam_width: int = 16  # Active states during triage window

    # Memory optimization settings
    cfg_simple: bool = False  # Use simplified CFG (less memory)
    max_symbolic_buffers: int = 100  # Limit symbolic buffer count (increased for better detection)
    max_buffer_size: int = 0x200  # Max size per buffer (512 bytes, increased)
    cleanup_interval: int = 2000  # Steps between dead state cleanup (less aggressive)

    # Specific IOCTL to analyze (hex string like "0x22201c")
    target_ioctl: str | None = None
    # Whether to perform per-IOCTL targeted hunts (may extend overall time)
    targeted_ioctls: bool = False

    # IOCTL handler address to skip discovery (hex string like "0x140007080")
    ioctl_handler_addr: str | None = None

    # Functions to exclude (list of hex addresses)
    exclude_functions: list[str] = Field(default_factory=list)

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("timeout must be > 0")
        return v

    @field_validator("ioctl_timeout")
    @classmethod
    def validate_ioctl_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("ioctl_timeout must be > 0")
        return v

    @field_validator("max_steps")
    @classmethod
    def validate_max_steps(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("max_steps must be > 0")
        return v

    @field_validator("max_states")
    @classmethod
    def validate_max_states(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("max_states must be > 0")
        return v

    @field_validator("bound")
    @classmethod
    def validate_bound(cls, v: int) -> int:
        if v < 0:
            raise ValueError("bound must be >= 0")
        return v

    @field_validator("length")
    @classmethod
    def validate_length(cls, v: int) -> int:
        if v < 0:
            raise ValueError("length must be >= 0")
        return v

    @field_validator("explosion_threshold")
    @classmethod
    def validate_explosion_threshold(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("explosion_threshold must be > 0")
        return v

    @field_validator("search_strategy")
    @classmethod
    def validate_search_strategy(cls, v: str) -> str:
        allowed = {"dfs", "beam"}
        if v not in allowed:
            raise ValueError(f"search_strategy must be one of {allowed}")
        return v

    @field_validator("beam_width")
    @classmethod
    def validate_beam_width(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("beam_width must be > 0")
        return v

    @field_validator("triage_steps")
    @classmethod
    def validate_triage_steps(cls, v: int) -> int:
        if v < 0:
            raise ValueError("triage_steps must be >= 0")
        return v

    @field_validator("triage_beam_width")
    @classmethod
    def validate_triage_beam_width(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("triage_beam_width must be > 0")
        return v

    @field_validator("cleanup_interval")
    @classmethod
    def validate_cleanup_interval(cls, v: int) -> int:
        if v < 0:
            raise ValueError("cleanup_interval must be >= 0")
        return v

    @field_validator("max_symbolic_buffers")
    @classmethod
    def validate_max_symbolic_buffers(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("max_symbolic_buffers must be > 0")
        return v

    @field_validator("max_buffer_size")
    @classmethod
    def validate_max_buffer_size(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("max_buffer_size must be > 0")
        return v

    @model_validator(mode="after")
    def validate_timeout_relationships(self) -> "AnalysisConfig":
        # Auto-adjust to maintain backward compatibility with tests that set a small timeout
        if self.ioctl_timeout > self.timeout:
            object.__setattr__(self, "ioctl_timeout", self.timeout)
        return self

    @classmethod
    def fast(cls) -> "AnalysisConfig":
        """Fast profile for quick analysis with minimal memory usage."""
        return cls(
            timeout=30,
            ioctl_timeout=10,
            bound=50,
            length=5000,
            max_steps=50000,
            max_states=100,
            handler_max_steps=0x10000,
            explosion_threshold=1000,
            cleanup_interval=500,  # Aggressive cleanup
            cfg_simple=True,  # Simple CFG for speed
            max_symbolic_buffers=30,
            max_buffer_size=0x80,  # Smaller buffers
            search_strategy="dfs",
            beam_width=48,
            triage_steps=0,
            triage_beam_width=12,
        )

    @classmethod
    def balanced(cls) -> "AnalysisConfig":
        """Balanced profile for good coverage with reasonable performance."""
        return cls(
            timeout=90,
            ioctl_timeout=30,
            bound=150,
            length=15000,
            max_steps=250000,
            max_states=350,
            handler_max_steps=0x60000,
            explosion_threshold=4000,
            cleanup_interval=1500,  # Regular cleanup
            cfg_simple=False,
            max_symbolic_buffers=80,
            max_buffer_size=0x180,
            search_strategy="dfs",
            beam_width=64,
            triage_steps=0,
            triage_beam_width=16,
        )

    @classmethod
    def thorough(cls) -> "AnalysisConfig":
        """Thorough profile for comprehensive analysis."""
        return cls(
            timeout=180,
            ioctl_timeout=60,
            bound=300,
            length=30000,
            max_steps=500000,
            max_states=500,
            handler_max_steps=0x100000,
            explosion_threshold=10000,
            cleanup_interval=3000,  # Less frequent cleanup
            cfg_simple=False,
            max_symbolic_buffers=150,
            max_buffer_size=0x400,
            search_strategy="dfs",
            beam_width=96,
            triage_steps=0,
            triage_beam_width=24,
        )

    @classmethod
    def paranoid(cls) -> "AnalysisConfig":
        """Ultra-conservative profile for debugging stuck drivers."""
        return cls(
            timeout=10,
            ioctl_timeout=5,
            bound=10,
            length=1000,
            max_steps=10000,
            max_states=50,
            handler_max_steps=0x1000,
            explosion_threshold=500,
            cleanup_interval=200,  # Very aggressive cleanup
            cfg_simple=True,
            max_symbolic_buffers=20,
            max_buffer_size=0x40,
            search_strategy="dfs",
            beam_width=16,
            triage_steps=0,
            triage_beam_width=8,
        )

    @classmethod
    def memory_safe(cls) -> "AnalysisConfig":
        """Memory-safe profile optimized to prevent OOM."""
        return cls(
            timeout=40,
            ioctl_timeout=15,
            bound=75,
            length=5000,
            max_steps=25000,
            max_states=40,
            handler_max_steps=0x2000,
            explosion_threshold=600,
            cleanup_interval=500,  # Frequent cleanup
            cfg_simple=True,  # Simple CFG for memory
            max_symbolic_buffers=30,
            max_buffer_size=0xC0,
            search_strategy="dfs",
            beam_width=24,
            triage_steps=0,
            triage_beam_width=8,
        )

    @classmethod
    def from_profile(cls, profile: str) -> "AnalysisConfig":
        """Create configuration from profile name.

        Args:
            profile: Profile name (fast, balanced, thorough, paranoid, memory_safe)

        Returns:
            AnalysisConfig instance with profile settings

        Raises:
            ValueError: If profile name is unknown
        """
        profiles = {
            "fast": cls.fast,
            "balanced": cls.balanced,
            "thorough": cls.thorough,
            "paranoid": cls.paranoid,
            "memory_safe": cls.memory_safe,
        }

        if profile not in profiles:
            raise ValueError(f"Unknown profile '{profile}'. Available: {', '.join(profiles.keys())}")

        return profiles[profile]()


@dataclass(init=False)
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

    def __init__(self, *args, **kwargs) -> None:
        """Flexible initializer supporting legacy and new signatures.

        Supported forms:
        - AnalysisContext(project, cfg, calling_convention, config, ...)
        - AnalysisContext(binary_path, project, config)  [legacy tests]
        """
        # Legacy: (binary_path, project, config)
        if len(args) == 3 and not kwargs:
            binary_path, project, config = args
            from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCStdcall
            import archinfo

            path = Path(binary_path) if isinstance(binary_path, str) else binary_path
            self.project = project
            # Build a CFG
            self.cfg = project.analyses.CFGFast()
            # Calling convention by arch
            if project.arch.name == archinfo.ArchX86.name:
                self.calling_convention = SimCCStdcall(project.arch)
            else:
                self.calling_convention = SimCCMicrosoftAMD64(project.arch)

            # Ensure config is AnalysisConfig
            self.config = config if isinstance(config, AnalysisConfig) else AnalysisConfig(**(config or {}))

            # Initialize defaults for remaining fields
            self.phase = 1
            self.driver_path = path
            self.driver_type = "unknown"
            self.device_names = []
            self.ioctl_handler = 0
            self.ioctl_codes = []
            self.vulnerabilities = []
            self.error_messages = []
            self.vuln_buffer = []
            self.simulation_manager = None
            self.irp_addr = 0x41410000
            self.irsp_addr = 0x41420000
            self.do_nothing_addr = 0x42420000
            self.system_buffer = None
            self.type3_input_buffer = None
            self.user_buffer = None
            self.output_buffer_length = None
            self.input_buffer_length = None
            self.io_control_code = None
            self.unique_addresses = set()
            self.detectors = []
            self.output_manager = None

            # Register hooks and detectors like create_for_driver
            from ..hooks import register_all_hooks

            register_all_hooks(project)
            from ..detectors import detector_registry

            self.detectors = detector_registry.create_instances(self)
            return

        # New signature via dataclass semantics using keywords
        for field_name in (
            "project",
            "cfg",
            "calling_convention",
            "config",
            "phase",
            "driver_path",
            "driver_type",
            "device_names",
            "ioctl_handler",
            "ioctl_codes",
            "vulnerabilities",
            "error_messages",
            "vuln_buffer",
            "simulation_manager",
            "irp_addr",
            "irsp_addr",
            "do_nothing_addr",
            "system_buffer",
            "type3_input_buffer",
            "user_buffer",
            "output_buffer_length",
            "input_buffer_length",
            "io_control_code",
            "unique_addresses",
            "detectors",
            "output_manager",
        ):
            if field_name in kwargs:
                setattr(self, field_name, kwargs[field_name])
        # Minimal required fields must be present
        if (
            not hasattr(self, "project")
            or not hasattr(self, "cfg")
            or not hasattr(self, "calling_convention")
            or not hasattr(self, "config")
        ):
            raise TypeError(
                "AnalysisContext requires (project, cfg, calling_convention, config) or (binary_path, project, config)"
            )

        # Set defaults for any optional fields not provided
        if not hasattr(self, "phase"):
            self.phase = 1
        if not hasattr(self, "driver_path"):
            self.driver_path = Path(".")
        if not hasattr(self, "driver_type"):
            self.driver_type = "unknown"
        if not hasattr(self, "device_names"):
            self.device_names = []
        if not hasattr(self, "ioctl_handler"):
            self.ioctl_handler = 0
        if not hasattr(self, "ioctl_codes"):
            self.ioctl_codes = []
        if not hasattr(self, "vulnerabilities"):
            self.vulnerabilities = []
        if not hasattr(self, "error_messages"):
            self.error_messages = []
        if not hasattr(self, "vuln_buffer"):
            self.vuln_buffer = []
        if not hasattr(self, "simulation_manager"):
            self.simulation_manager = None
        if not hasattr(self, "irp_addr"):
            self.irp_addr = 0x41410000
        if not hasattr(self, "irsp_addr"):
            self.irsp_addr = 0x41420000
        if not hasattr(self, "do_nothing_addr"):
            self.do_nothing_addr = 0x42420000
        if not hasattr(self, "system_buffer"):
            self.system_buffer = None
        if not hasattr(self, "type3_input_buffer"):
            self.type3_input_buffer = None
        if not hasattr(self, "user_buffer"):
            self.user_buffer = None
        if not hasattr(self, "output_buffer_length"):
            self.output_buffer_length = None
        if not hasattr(self, "input_buffer_length"):
            self.input_buffer_length = None
        if not hasattr(self, "io_control_code"):
            self.io_control_code = None
        if not hasattr(self, "unique_addresses"):
            self.unique_addresses = set()
        if not hasattr(self, "detectors"):
            # Auto-register detectors
            from ..detectors import detector_registry

            self.detectors = detector_registry.create_instances(self)
        if not hasattr(self, "output_manager"):
            self.output_manager = None

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
        import logging

        logger = logging.getLogger(__name__)

        context.detectors = detector_registry.create_instances(context)
        logger.debug(f"Created {len(context.detectors)} detectors: {[d.name for d in context.detectors]}")

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
            try:
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
            except Exception as e:
                # Don't let output manager errors prevent vulnerability recording
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Output manager error (vulnerability still recorded): {e}")

        # CRITICAL: Always append to vulnerabilities list regardless of output_manager
        self.vulnerabilities.append(vuln_info)

        # Buffer the vulnerability title for summary
        if "title" in vuln_info:
            self.vuln_buffer.append(vuln_info["title"])

        # Debug logging - more frequent for debugging
        if len(self.vulnerabilities) <= 10 or len(self.vulnerabilities) % 100 == 0:
            import logging

            logger = logging.getLogger(__name__)
            logger.info(f"Added vulnerability #{len(self.vulnerabilities)}: {vuln_info.get('title')}")

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
