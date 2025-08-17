"""Raw opcode scanning and hooking for low-level vulnerability detection."""

import re
import subprocess
from functools import lru_cache
from pathlib import Path
from re import Pattern
from typing import Any

from ..core.analysis_context import AnalysisContext
from ..hooks import opcodes


@lru_cache(maxsize=32)
def _get_objdump_output_cached(file_path: str, file_size: int, file_mtime: float) -> tuple[str, ...]:
    """Get cached objdump output for a binary file.

    Args:
        file_path: Path to the binary file
        file_size: Size of the file (for cache key)
        file_mtime: Modification time of the file (for cache key)

    Returns:
        Tuple of objdump output lines
    """
    command = ["objdump", "--insn-width=16", "-d", file_path]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode == 0:
            return tuple(result.stdout.splitlines())
        else:
            return tuple()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return tuple()


class OpcodeScanner:
    """Scans binary for dangerous CPU instructions and hooks them."""

    # Map of instruction patterns to their hook functions and sizes
    INSTRUCTION_HOOKS = {
        # I/O port operations
        r"out[ \t]+%([a-z0-9]+),\(%([a-z0-9]+)\)$": ("out", "dynamic"),
        r"outsb": ("outs", 2),
        r"outsl": ("outs", 2),
        r"outsw": ("outs", 3),
        r"insb": ("ins", 2),
        r"insl": ("ins", 2),
        r"insw": ("ins", 3),
        # Privileged instructions
        r"wrmsr": ("wrmsr", 2),
        r"rdpmc": ("rdpmc", 2),
        r"[ \t]*int[ \t]*": ("int", 2),
        # String operations that can overflow
        r"rep movsb": ("rep_movsb", 2),
        r"rep movsw": ("rep_movsw", 3),
        r"rep movsd|rep movsl": ("rep_movsd", 2),
        r"rep stos %al": ("rep_stosb", 2),
        r"rep stos %ax": ("rep_stosw", 3),
        r"rep stos %eax": ("rep_stosd", 3),
        r"rep stos %rax": ("rep_stosq", 3),
        # Synchronization/security boundaries
        r"lock(?!.*(?:inc|dec))": ("lock", "dynamic"),
        r"lfence": ("lfence", 3),
        r"pushfw": ("pushfw", 2),
        r"popfw": ("popfw", 2),
        # Interrupt descriptor table manipulation
        r"sidt": ("sidt", 3),
        r"lidt": ("lidt", 3),
    }

    # Pre-compile regex patterns for better performance
    COMPILED_PATTERNS: dict[Pattern[str], tuple[str, Any]] = {
        re.compile(pattern): hook_info for pattern, hook_info in INSTRUCTION_HOOKS.items()
    }

    def __init__(self, context: AnalysisContext) -> None:
        """Initialize the opcode scanner.

        Args:
            context: Analysis context containing project and configuration
        """
        self.context = context
        self.project = context.project
        self.hooked_addresses = set()

    def scan_and_hook(self, driver_path: Path | str) -> dict[str, list[int]]:
        """Scan driver for dangerous opcodes and hook them.

        Args:
            driver_path: Path to the driver binary

        Returns:
            Dictionary mapping hook types to lists of hooked addresses
        """
        driver_path = Path(driver_path)
        if not driver_path.exists():
            self.context.print_error(f"Driver file not found: {driver_path}")
            return {}

        self.context.print_info("Scanning for dangerous CPU instructions...")

        # Get cached objdump output
        try:
            stat = driver_path.stat()
            objdump_lines = _get_objdump_output_cached(str(driver_path), stat.st_size, stat.st_mtime)

            if not objdump_lines:
                # objdump failed, try fallback
                self.context.print_error("objdump failed or not found. Trying capstone fallback.")
                return self._fallback_capstone_scan(driver_path)
        except FileNotFoundError:
            self.context.print_error("objdump not found. Please install binutils.")
            return self._fallback_capstone_scan(driver_path)

        hooks_installed = {}

        for line in objdump_lines:
            # Try to extract address from line
            try:
                addr = int(line.strip().split(":")[0], 16)
            except (ValueError, IndexError):
                continue

            # Check each instruction pattern using pre-compiled patterns
            for compiled_pattern, (hook_name, size) in self.COMPILED_PATTERNS.items():
                if compiled_pattern.search(line):
                    # Skip if already hooked
                    if addr in self.hooked_addresses:
                        continue

                    # Calculate hook size
                    if size == "dynamic":
                        # For dynamic size, parse from objdump output
                        size = self._calculate_instruction_size(line, compiled_pattern.pattern)

                    # Install the hook
                    if self._install_hook(addr, hook_name, size):
                        self.hooked_addresses.add(addr)

                        # Track for reporting
                        if hook_name not in hooks_installed:
                            hooks_installed[hook_name] = []
                        hooks_installed[hook_name].append(addr)

                        self.context.print_debug(f"Hooked {hook_name} at 0x{addr:x}")
                    break

        # Report summary
        total_hooks = sum(len(addrs) for addrs in hooks_installed.values())
        self.context.print_info(f"Installed {total_hooks} instruction hooks across {len(hooks_installed)} types")

        return hooks_installed

    def _calculate_instruction_size(self, line: str, pattern: str) -> int:
        """Calculate instruction size from objdump output.

        Args:
            line: Objdump output line
            pattern: Regex pattern that matched

        Returns:
            Instruction size in bytes
        """
        # Default sizes for specific patterns
        if "out" in pattern:
            # Parse 'out' instruction format
            parts = line.strip().split("out")[0].split()
            return len(parts) - 1 if parts else 2
        elif "lock" in pattern:
            # Parse 'lock' prefix
            parts = line.strip().split("lock")[0].split()
            return len(parts) - 1 if parts else 1
        else:
            return 2  # Default size

    def _install_hook(self, addr: int, hook_name: str, size: int) -> bool:
        """Install a hook at the given address.

        Args:
            addr: Address to hook
            hook_name: Name of the hook function
            size: Size of the instruction to hook

        Returns:
            True if hook was successfully installed
        """
        try:
            # Get the hook function from opcodes module
            hook_func = getattr(opcodes, f"{hook_name}_hook", None)
            if not hook_func:
                self.context.print_debug(f"Hook function {hook_name}_hook not found")
                return False

            # Install the hook
            self.project.hook(addr, hook_func, size)
            return True

        except Exception as e:
            self.context.print_debug(f"Failed to hook {hook_name} at 0x{addr:x}: {e}")
            return False

    def _fallback_capstone_scan(self, driver_path: Path) -> dict[str, list[int]]:
        """Fallback to capstone disassembler if objdump is not available.

        Args:
            driver_path: Path to the driver binary

        Returns:
            Dictionary mapping hook types to lists of hooked addresses
        """
        try:
            import capstone
        except ImportError:
            self.context.print_error(
                "Neither objdump nor capstone available. Install capstone with: pip install capstone"
            )
            return {}

        # Load the binary
        with open(driver_path, "rb") as f:
            binary_data = f.read()

        # Determine architecture
        if self.project.arch.name == "AMD64":
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        hooks_installed = {}
        base_addr = self.project.loader.main_object.min_addr

        # Disassemble and look for dangerous instructions
        # Use count=0 to disassemble all bytes
        for insn in cs.disasm(binary_data, base_addr, count=0):
            # Map capstone mnemonics to our hook names
            mnemonic_map = {
                "wrmsr": "wrmsr",
                "out": "out",
                "outsb": "outs",
                "outsl": "outs",
                "outsw": "outs",
                "insb": "ins",
                "insl": "ins",
                "insw": "ins",
                "int": "int",
                "rdpmc": "rdpmc",
                "lfence": "lfence",
                "pushfw": "pushfw",
                "popfw": "popfw",
                "sidt": "sidt",
                "lidt": "lidt",
            }

            # Check for rep prefix with string operations
            if insn.mnemonic.startswith("rep"):
                parts = insn.mnemonic.split()
                if len(parts) > 1:
                    if parts[1] == "movsb":
                        hook_name = "rep_movsb"
                    elif parts[1] == "movsw":
                        hook_name = "rep_movsw"
                    elif parts[1] in ("movsd", "movsl"):
                        hook_name = "rep_movsd"
                    elif parts[1] == "stosb":
                        hook_name = "rep_stosb"
                    elif parts[1] == "stosw":
                        hook_name = "rep_stosw"
                    elif parts[1] == "stosd":
                        hook_name = "rep_stosd"
                    elif parts[1] == "stosq":
                        hook_name = "rep_stosq"
                    else:
                        continue
                else:
                    continue
            elif insn.mnemonic in mnemonic_map:
                hook_name = mnemonic_map[insn.mnemonic]
            elif insn.mnemonic == "lock":
                # Check if it's not lock inc/dec
                if len(insn.op_str) > 0 and "inc" not in insn.op_str and "dec" not in insn.op_str:
                    hook_name = "lock"
                else:
                    continue
            else:
                continue

            # Install hook
            if insn.address not in self.hooked_addresses:
                if self._install_hook(insn.address, hook_name, insn.size):
                    self.hooked_addresses.add(insn.address)

                    if hook_name not in hooks_installed:
                        hooks_installed[hook_name] = []
                    hooks_installed[hook_name].append(insn.address)

        return hooks_installed


def scan_and_hook_opcodes(context: AnalysisContext) -> dict[str, list[int]]:
    """Convenience function to scan and hook dangerous opcodes.

    Args:
        context: Analysis context

    Returns:
        Dictionary mapping hook types to lists of hooked addresses
    """
    scanner = OpcodeScanner(context)
    return scanner.scan_and_hook(context.driver_path)
