"""
Patch for angr's ccall.py to handle invalid cc_op values gracefully.

This module patches angr's condition code calculation to prevent crashes
when encountering invalid or corrupted cc_op values in x86-64 binaries.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def patch_angr_ccall():
    """Apply runtime patch to angr's ccall module to handle invalid cc_op values."""
    try:
        import angr.engines.vex.claripy.ccall as ccall
        
        # Save original function
        original_pc_calculate_rdata_all_WRK = ccall.pc_calculate_rdata_all_WRK
        
        def patched_pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform="AMD64"):
            """Patched version that handles invalid cc_op values."""
            try:
                # Try the original function first
                return original_pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=platform)
            except KeyError as e:
                # Handle invalid cc_op
                if isinstance(e.args[0], int):
                    logger.debug(f"Invalid cc_op {e.args[0]} encountered, returning symbolic value")
                    # Return a symbolic value instead of crashing
                    import claripy
                    return state.solver.BVS("invalid_cc_rdata", 64)
                else:
                    # Re-raise if it's a different KeyError
                    raise
            except Exception:
                # Let other exceptions bubble up
                raise
        
        # Apply the patch
        ccall.pc_calculate_rdata_all_WRK = patched_pc_calculate_rdata_all_WRK
        logger.debug("Successfully patched angr ccall module")
        return True
        
    except ImportError:
        logger.warning("Could not import angr.engines.vex.claripy.ccall for patching")
        return False
    except Exception as e:
        logger.warning(f"Failed to patch angr ccall module: {e}")
        return False


def apply_patches():
    """Apply all runtime patches to angr."""
    patch_angr_ccall()