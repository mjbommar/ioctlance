"""Batch verification tool for analyzing JSONL files."""

import json
import logging
from pathlib import Path
from typing import Any, Optional
from collections import Counter

from .manager import VerificationManager, VerificationLevel
from .registry import verifier_registry

# Import all verifiers to register them
from .unconstrained_verifier import UnconstrainedStateVerifier
from .double_free_verifier import DoubleFreeVerifier

logger = logging.getLogger(__name__)


class BatchVerifier:
    """Verify vulnerabilities from JSONL files."""

    def __init__(self, level: VerificationLevel = VerificationLevel.STANDARD):
        """Initialize batch verifier.

        Args:
            level: Verification level to use
        """
        self.level = level
        self.stats = {
            "total": 0,
            "verified": 0,
            "false_positives": 0,
            "reclassified": 0,
            "needs_review": 0,
            "by_type": Counter(),
            "reclassifications": Counter(),
        }

    def verify_jsonl(self, input_file: Path, output_file: Optional[Path] = None) -> dict:
        """Verify vulnerabilities from JSONL file.

        Args:
            input_file: Input JSONL file
            output_file: Optional output file for verified results

        Returns:
            Statistics dictionary
        """

        # Mock context for verification
        class MockContext:
            def __init__(self):
                self.config = MockConfig()
                self.io_control_code = None

        class MockConfig:
            def __init__(self):
                self.verification_enabled = True
                self.verification_level = "standard"
                self.filter_false_positives = True

        context = MockContext()
        manager = VerificationManager(context, self.level)

        verified_vulns = []

        with open(input_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                # Extract JSON from log line
                if ":" in line and line.startswith("/"):
                    line = line.split(":", 1)[1]

                try:
                    data = json.loads(line)

                    # Extract vulnerability info
                    if "data" in data and "vulnerability" in data["data"]:
                        vuln_info = data["data"]["vulnerability"]
                        self.stats["total"] += 1

                        # Track original type
                        original_type = vuln_info.get("title", "Unknown")
                        self.stats["by_type"][original_type] += 1

                        # Mock state for verification
                        if vuln_info.get("eval"):
                            # Create mock state with eval parameters
                            vuln_info["state"] = self._create_mock_state(vuln_info["eval"])

                        # Verify vulnerability
                        result = manager.verify_vulnerability(vuln_info)

                        if result is None:
                            self.stats["false_positives"] += 1
                            logger.info(f"Line {line_num}: Filtered as false positive")
                        else:
                            self.stats["verified"] += 1

                            # Check for reclassification
                            new_type = result.get("title", original_type)
                            if new_type != original_type:
                                self.stats["reclassified"] += 1
                                self.stats["reclassifications"][f"{original_type} -> {new_type}"] += 1

                            # Remove non-serializable state object before saving
                            if "state" in result:
                                del result["state"]

                            # Update original data with verification
                            data["data"]["vulnerability"] = result
                            verified_vulns.append(data)

                except json.JSONDecodeError as e:
                    logger.warning(f"Line {line_num}: Invalid JSON - {e}")
                except Exception as e:
                    logger.error(f"Line {line_num}: Error - {e}")

        # Write verified results
        if output_file and verified_vulns:
            with open(output_file, "w") as f:
                for vuln in verified_vulns:
                    json.dump(vuln, f)
                    f.write("\n")

        # Add manager stats
        self.stats.update(manager.stats)

        return self.stats

    def _create_mock_state(self, eval_params: dict) -> Any:
        """Create a mock state for verification.

        Args:
            eval_params: Evaluation parameters from vulnerability

        Returns:
            Mock state object
        """

        class MockState:
            def __init__(self, params):
                self.solver = MockSolver()
                self.inspect = MockInspect(params)
                self.history = MockHistory()
                self.regs = MockRegs()
                self.globals = params

        class MockSolver:
            def eval_one(self, addr, default=None):
                # Parse SystemBuffer for NULL check
                if hasattr(addr, "args") and addr.args:
                    return addr.args[0]
                return 0 if default is None else default

            def symbolic(self, val):
                return False

        class MockInspect:
            def __init__(self, params):
                # Set addresses based on buffer values
                sys_buf = params.get("SystemBuffer", "0x0")
                if sys_buf == "0x0":
                    self.mem_read_address = 0
                    self.mem_write_address = 0
                else:
                    self.mem_read_address = None
                    self.mem_write_address = None

        class MockHistory:
            def __init__(self):
                self.descriptions = MockDescriptions()

        class MockDescriptions:
            def __init__(self):
                self.hardcopy = []

        class MockRegs:
            def __init__(self):
                self.rsp = 0x1000
                self.rbp = 0x1000

        return MockState(eval_params)

    def print_report(self):
        """Print verification report."""
        if self.stats["total"] == 0:
            print("No vulnerabilities processed")
            return

        print(f"\n{'=' * 60}")
        print(f"Batch Verification Report (Level: {self.level.name})")
        print(f"{'=' * 60}")

        print(f"\nTotal Processed: {self.stats['total']}")
        print(f"Verified: {self.stats['verified']} ({self.stats['verified'] * 100 / self.stats['total']:.1f}%)")
        print(
            f"False Positives: {self.stats['false_positives']} ({self.stats['false_positives'] * 100 / self.stats['total']:.1f}%)"
        )
        print(
            f"Reclassified: {self.stats['reclassified']} ({self.stats['reclassified'] * 100 / self.stats['total']:.1f}%)"
        )

        if self.stats["by_type"]:
            print(f"\n--- Original Types ---")
            for vtype, count in self.stats["by_type"].most_common():
                print(f"  {vtype}: {count}")

        if self.stats["reclassifications"]:
            print(f"\n--- Reclassifications ---")
            for change, count in self.stats["reclassifications"].most_common():
                print(f"  {change}: {count}")

        print(f"\n{'=' * 60}\n")


def main():
    """Run batch verification on examples.jsonl."""
    import sys

    input_file = Path("examples.jsonl") if len(sys.argv) < 2 else Path(sys.argv[1])
    output_file = None if len(sys.argv) < 3 else Path(sys.argv[2])

    if not input_file.exists():
        print(f"Error: {input_file} not found")
        return

    print(f"Processing: {input_file}")

    verifier = BatchVerifier(VerificationLevel.STANDARD)
    stats = verifier.verify_jsonl(input_file, output_file)
    verifier.print_report()

    if output_file:
        print(f"Verified results written to: {output_file}")


if __name__ == "__main__":
    main()
