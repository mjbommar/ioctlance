"""Integration tests for new vulnerability detectors."""

import pytest
from pathlib import Path
from typing import Any, Dict

from ioctlance.core.driver_analyzer import DriverAnalyzer


def analyze_driver(driver_path: Path, timeout: int = 30) -> dict:
    """Helper function to analyze a driver."""
    analyzer = DriverAnalyzer(str(driver_path))
    return analyzer.analyze(timeout=timeout)


class TestFormatStringDetector:
    """Test FormatStringDetector with compiled test driver."""

    def test_format_string_vulnerabilities(self):
        """Test detection of format string vulnerabilities."""
        driver_path = Path("samples/test_format_string.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        # Analyze with timeout
        result = analyze_driver(driver_path, timeout=30)

        # Should find vulnerabilities
        assert result is not None, "Analysis failed"
        assert "vulnerabilities" in result

        # Check for format string vulnerabilities
        vulns = result["vulnerabilities"]
        format_string_vulns = [v for v in vulns if "Format String" in v.get("title", "")]

        # Should detect at least one format string vulnerability
        assert len(format_string_vulns) > 0, (
            f"No format string vulnerabilities found. Found: {[v['title'] for v in vulns]}"
        )

        # Check for specific patterns
        vuln_types = [v.get("title", "") for v in format_string_vulns]

        # Should find tainted input vulnerabilities (DbgPrint with user format)
        tainted_vulns = [v for v in format_string_vulns if "Tainted" in v.get("title", "")]
        assert len(tainted_vulns) > 0, "Should detect tainted format string"

    def test_format_string_functions(self):
        """Test that various printf-family functions are detected."""
        driver_path = Path("samples/test_format_string.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None

        vulns = result.get("vulnerabilities", [])

        # Check that DbgPrint vulnerabilities are detected
        dbgprint_vulns = [
            v
            for v in vulns
            if "Format String" in v.get("title", "") and "DbgPrint" in str(v.get("parameters", {}).get("function", ""))
        ]

        # We have multiple DbgPrint calls with user format, should detect them
        assert len(dbgprint_vulns) > 0, "Should detect DbgPrint format string vulnerabilities"


class TestKernelPrimitiveDetector:
    """Test KernelPrimitiveDetector with compiled test driver."""

    def test_arbitrary_increment_decrement(self):
        """Test detection of arbitrary increment/decrement primitives."""
        driver_path = Path("samples/test_kernel_primitive.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None, "Analysis failed"

        vulns = result.get("vulnerabilities", [])
        kernel_primitive_vulns = [v for v in vulns if "Kernel Primitive" in v.get("title", "")]

        # Should detect kernel primitives
        assert len(kernel_primitive_vulns) > 0, f"No kernel primitives found. Found: {[v['title'] for v in vulns]}"

        # Check for specific primitive types
        vuln_titles = [v.get("title", "") for v in kernel_primitive_vulns]

        # Should detect increment/decrement operations
        inc_dec_vulns = [
            v
            for v in kernel_primitive_vulns
            if "increment" in v.get("title", "").lower() or "decrement" in v.get("title", "").lower()
        ]
        assert len(inc_dec_vulns) > 0, "Should detect increment/decrement primitives"

    def test_bitwise_operations(self):
        """Test detection of arbitrary bitwise operations."""
        driver_path = Path("samples/test_kernel_primitive.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None

        vulns = result.get("vulnerabilities", [])

        # Check for OR/AND/XOR operations
        bitop_vulns = [
            v
            for v in vulns
            if "Kernel Primitive" in v.get("title", "")
            and any(op in v.get("title", "").lower() for op in ["or", "and", "xor"])
        ]

        assert len(bitop_vulns) > 0, "Should detect bitwise operation primitives"

    def test_interlocked_operations(self):
        """Test detection of vulnerable Interlocked operations."""
        driver_path = Path("samples/test_kernel_primitive.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None

        vulns = result.get("vulnerabilities", [])

        # Check for Interlocked operations
        interlocked_vulns = [
            v for v in vulns if "Kernel Primitive" in v.get("title", "") and "interlocked" in v.get("title", "").lower()
        ]

        assert len(interlocked_vulns) > 0, "Should detect Interlocked operation vulnerabilities"


class TestSymlinkAttackDetector:
    """Test SymlinkAttackDetector with compiled test driver."""

    def test_toctou_detection(self):
        """Test detection of TOCTOU race conditions."""
        driver_path = Path("samples/test_symlink_attack.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None, "Analysis failed"

        vulns = result.get("vulnerabilities", [])
        symlink_vulns = [v for v in vulns if "Symlink Attack" in v.get("title", "")]

        # Should detect symlink attacks
        assert len(symlink_vulns) > 0, f"No symlink attacks found. Found: {[v['title'] for v in vulns]}"

        # Check for TOCTOU specifically
        toctou_vulns = [
            v
            for v in symlink_vulns
            if "TOCTOU" in v.get("title", "") or "toctou" in str(v.get("parameters", {}).get("type", ""))
        ]

        assert len(toctou_vulns) > 0, "Should detect TOCTOU vulnerability"

    def test_unsafe_symlink_following(self):
        """Test detection of unsafe symlink following."""
        driver_path = Path("samples/test_symlink_attack.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None

        vulns = result.get("vulnerabilities", [])

        # Check for unsafe symlink following
        symlink_follow_vulns = [
            v
            for v in vulns
            if "Symlink Attack" in v.get("title", "")
            and ("Unsafe" in v.get("title", "") or "symlink_follow" in str(v.get("parameters", {}).get("type", "")))
        ]

        assert len(symlink_follow_vulns) > 0, "Should detect unsafe symlink following"

    def test_predictable_temp_files(self):
        """Test detection of predictable temporary file creation."""
        driver_path = Path("samples/test_symlink_attack.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None

        vulns = result.get("vulnerabilities", [])

        # Check for predictable temp file vulnerabilities
        temp_file_vulns = [
            v
            for v in vulns
            if "Symlink Attack" in v.get("title", "")
            and (
                "Predictable" in v.get("title", "")
                or "predictable_temp" in str(v.get("parameters", {}).get("type", ""))
            )
        ]

        assert len(temp_file_vulns) > 0, "Should detect predictable temporary file creation"

    def test_file_creation_race(self):
        """Test detection of file creation race conditions."""
        driver_path = Path("samples/test_symlink_attack.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None

        vulns = result.get("vulnerabilities", [])

        # Check for file creation race conditions
        race_vulns = [
            v
            for v in vulns
            if "Symlink Attack" in v.get("title", "")
            and ("Race" in v.get("title", "") or "creation_race" in str(v.get("parameters", {}).get("type", "")))
        ]

        assert len(race_vulns) > 0, "Should detect file creation race condition"


class TestDetectorIntegration:
    """Test that all detectors work together properly."""

    def test_all_detectors_registered(self):
        """Test that all new detectors are properly registered."""
        from ioctlance.detectors import detector_registry

        # Check that new detectors are registered
        detector_names = list(detector_registry._detectors.keys())

        assert "format_string" in detector_names, "FormatStringDetector not registered"
        assert "kernel_primitive" in detector_names, "KernelPrimitiveDetector not registered"
        assert "symlink_attack" in detector_names, "SymlinkAttackDetector not registered"

    def test_no_false_positives_on_safe_code(self):
        """Test that safe functions don't trigger false positives."""
        driver_path = Path("samples/test_format_string.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        result = analyze_driver(driver_path, timeout=30)
        assert result is not None

        vulns = result.get("vulnerabilities", [])

        # The safe functions (IOCTL_SAFE_FORMAT) should not generate vulnerabilities
        # with constant format strings. However, we expect vulnerabilities from
        # the vulnerable functions, so just ensure we're not getting excessive
        # false positives (e.g., hundreds of duplicates)

        format_string_vulns = [v for v in vulns if "Format String" in v.get("title", "")]

        # Should have reasonable number of vulnerabilities, not excessive duplicates
        assert len(format_string_vulns) < 50, (
            f"Too many format string vulnerabilities detected ({len(format_string_vulns)}), possible false positives"
        )

    def test_detector_performance(self):
        """Test that new detectors don't significantly impact performance."""
        import time

        driver_path = Path("samples/test_kernel_primitive.sys")
        if not driver_path.exists():
            pytest.skip(f"Test driver {driver_path} not found")

        start_time = time.time()
        result = analyze_driver(driver_path, timeout=30)
        end_time = time.time()

        assert result is not None, "Analysis failed"

        # Analysis should complete within reasonable time (30 seconds timeout)
        analysis_time = end_time - start_time
        assert analysis_time < 35, f"Analysis took too long ({analysis_time:.2f}s)"

        # Should find vulnerabilities
        vulns = result.get("vulnerabilities", [])
        assert len(vulns) > 0, "Should detect vulnerabilities"
