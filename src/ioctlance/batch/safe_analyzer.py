"""Safe batch analyzer with conservative settings to prevent hangs."""

from pathlib import Path
from typing import Dict, Any

from ..core.analysis_context import AnalysisConfig, AnalysisContext
from ..core.driver_analyzer import DriverAnalyzer


# Preset configurations for different analysis profiles
ANALYSIS_PROFILES: dict[str, dict[str, Any]] = {
    "fast": {
        "timeout": 30,
        "ioctl_timeout": 10,
        "bound": 50,
        "length": 5000,
        "max_steps": 50000,
        "max_states": 100,
        "handler_max_steps": 0x10000,
        "explosion_threshold": 1000,
    },
    "balanced": {
        "timeout": 60,
        "ioctl_timeout": 20,
        "bound": 100,
        "length": 10000,
        "max_steps": 100000,
        "max_states": 200,
        "handler_max_steps": 0x20000,
        "explosion_threshold": 2000,
    },
    "thorough": {
        "timeout": 120,
        "ioctl_timeout": 40,
        "bound": 200,
        "length": 20000,
        "max_steps": 200000,
        "max_states": 300,
        "handler_max_steps": 0x40000,
        "explosion_threshold": 5000,
    },
    "paranoid": {
        # Ultra-conservative for debugging stuck drivers
        "timeout": 10,
        "ioctl_timeout": 5,
        "bound": 10,
        "length": 1000,
        "max_steps": 10000,
        "max_states": 50,
        "handler_max_steps": 0x1000,
        "explosion_threshold": 500,
    },
    "memory_safe": {
        # Balanced: Good coverage with strict memory safety
        "timeout": 40,  # Keep at 40 seconds
        "ioctl_timeout": 15,  # Keep at 15 seconds per IOCTL
        "bound": 75,  # Keep at 75 loop iterations
        "length": 5000,  # REDUCED from 8000 to 5000 (path explosion)
        "max_steps": 25000,  # REDUCED from 40000 to 25000 (step explosion)
        "max_states": 40,  # REDUCED from 75 to 40 (state explosion)
        "handler_max_steps": 0x2000,  # REDUCED from 0x4000 to 0x2000
        "explosion_threshold": 600,  # REDUCED from 1000 to 600
        # Memory optimization flags still enabled
        "cfg_simple": True,  # Keep simple CFG for memory
        "max_symbolic_buffers": 30,  # REDUCED from 40 to 30 buffers
        "max_buffer_size": 0xC0,  # REDUCED from 0x100 to 0xC0 (192 bytes)
    },
}


def analyze_driver_safe(
    driver_path: Path, profile: str = "fast", timeout_override: int | None = None, verbose: bool = False
) -> dict[str, Any]:
    """Analyze a driver with safe settings to prevent hangs.

    Args:
        driver_path: Path to the driver file
        profile: Analysis profile ('fast', 'balanced', 'thorough', 'paranoid')
        timeout_override: Override the profile timeout
        verbose: Enable verbose logging

    Returns:
        Analysis results dictionary
    """
    import time
    import logging

    logger = logging.getLogger(__name__)

    # Get profile configuration
    if profile not in ANALYSIS_PROFILES:
        logger.warning(f"Unknown profile '{profile}', using 'fast'")
        profile = "fast"

    profile_config = ANALYSIS_PROFILES[profile].copy()

    # Apply timeout override if provided
    if timeout_override is not None:
        profile_config["timeout"] = timeout_override
        # Scale other timeouts proportionally
        scale = timeout_override / ANALYSIS_PROFILES[profile]["timeout"]
        profile_config["ioctl_timeout"] = int(profile_config["ioctl_timeout"] * scale)

    # Add verbose flag
    profile_config["verbose"] = verbose
    profile_config["debug"] = verbose  # Enable debug in verbose mode

    # Create analysis configuration
    config = AnalysisConfig(**profile_config)

    # Log configuration if verbose
    if verbose:
        logger.info(f"Analyzing {driver_path.name} with profile '{profile}':")
        logger.info(f"  Timeout: {config.timeout}s")
        logger.info(f"  IOCTL timeout: {config.ioctl_timeout}s")
        logger.info(f"  Loop bound: {config.bound}")
        logger.info(f"  Path length: {config.length}")
        logger.info(f"  Max steps: {config.max_steps}")
        logger.info(f"  Max states: {config.max_states}")

    try:
        start_time = time.time()

        # Create context with safe configuration
        context = AnalysisContext.create_for_driver(driver_path, config)

        # Run analysis
        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        analysis_time = time.time() - start_time

        # Convert to dictionary
        result_dict = result.model_dump()
        result_dict["analysis_time"] = analysis_time
        result_dict["analysis_profile"] = profile
        result_dict["success"] = True
        result_dict["driver_path"] = str(driver_path)
        result_dict["filename"] = driver_path.name
        result_dict["vuln_count"] = len(result.vuln)

        if verbose:
            logger.info(
                f"Completed {driver_path.name} in {analysis_time:.1f}s - "
                f"{result_dict['vuln_count']} vulnerabilities found"
            )

        return result_dict

    except Exception as e:
        logger.error(f"Failed to analyze {driver_path.name}: {e}")
        return {
            "driver_path": str(driver_path),
            "filename": driver_path.name,
            "analysis_time": time.time() - start_time if "start_time" in locals() else 0,
            "analysis_profile": profile,
            "success": False,
            "error": [str(e)],
            "vuln_count": 0,
            "basic": {},
            "vuln": [],
        }


def get_profile_for_driver(driver_path: Path) -> str:
    """Heuristically determine the best profile for a driver.

    Args:
        driver_path: Path to the driver file

    Returns:
        Recommended profile name
    """
    import os

    # Get file size in KB
    file_size_kb = os.path.getsize(driver_path) / 1024

    # Small drivers can use thorough analysis
    if file_size_kb < 100:
        return "thorough"
    # Medium drivers use balanced
    elif file_size_kb < 500:
        return "balanced"
    # Large drivers need fast mode
    else:
        return "fast"
