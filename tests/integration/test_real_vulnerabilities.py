"""Real integration tests for vulnerability detection without mocks."""

from pathlib import Path

import pytest

from ioctlance.core.analysis_context import AnalysisConfig, AnalysisContext
from ioctlance.core.driver_analyzer import DriverAnalyzer


class TestRealVulnerabilityDetection:
    """Test real vulnerability detection on actual driver samples."""

    @pytest.fixture
    def samples_dir(self):
        """Get the samples directory path."""
        return Path(__file__).parent.parent.parent / "samples"

    def test_detect_physical_memory_vulnerability(self, samples_dir):
        """Test detection of physical memory mapping vulnerability."""
        driver_path = samples_dir / "test_physical_memory.sys"

        if not driver_path.exists():
            pytest.skip(f"Test driver not found: {driver_path}")

        config = AnalysisConfig(timeout=15, debug=False)
        context = AnalysisContext.create_for_driver(driver_path, config)

        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        # Should detect physical memory vulnerability
        vuln_titles = [v.title for v in result.vuln]
        assert any("Physical Memory Mapping" in title for title in vuln_titles), \
            f"Expected physical memory vulnerability not found. Found: {vuln_titles}"

    def test_detect_process_termination_vulnerability(self, samples_dir):
        """Test detection of arbitrary process termination vulnerability."""
        driver_path = samples_dir / "test_process_termination.sys"

        if not driver_path.exists():
            pytest.skip(f"Test driver not found: {driver_path}")

        config = AnalysisConfig(timeout=15, debug=False)
        context = AnalysisContext.create_for_driver(driver_path, config)

        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        # Should detect process termination vulnerability
        vuln_titles = [v.title for v in result.vuln]
        assert any("Process Termination" in title for title in vuln_titles), \
            f"Expected process termination vulnerability not found. Found: {vuln_titles}"

    def test_rtdashpt_finds_vulnerabilities(self, samples_dir):
        """Test that RtDashPt.sys has expected vulnerabilities."""
        driver_path = samples_dir / "RtDashPt.sys"

        if not driver_path.exists():
            pytest.skip(f"Sample driver not found: {driver_path}")

        config = AnalysisConfig(timeout=30, debug=False)
        context = AnalysisContext.create_for_driver(driver_path, config)

        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        # Should find vulnerabilities
        assert len(result.vuln) > 0, "No vulnerabilities found in known vulnerable driver"

        # Should find specific types
        vuln_titles = [v.title for v in result.vuln]

        # RtDashPt is known to have stack buffer overflow
        assert any("buffer overflow" in title.lower() for title in vuln_titles), \
            f"Expected buffer overflow not found. Found: {vuln_titles}"

    def test_detector_coverage(self, samples_dir):
        """Test that multiple detector types are working."""
        detected_types = set()

        # Test multiple samples to get variety of detections
        test_files = [
            ("test_physical_memory.sys", "Physical Memory"),
            ("test_process_termination.sys", "Process Termination"),
            ("RtDashPt.sys", "overflow"),
        ]

        for filename, expected_pattern in test_files:
            driver_path = samples_dir / filename

            if not driver_path.exists():
                continue

            config = AnalysisConfig(timeout=15, debug=False)
            context = AnalysisContext.create_for_driver(driver_path, config)

            analyzer = DriverAnalyzer(context)
            result = analyzer.analyze()

            for vuln in result.vuln:
                # Track types of vulnerabilities we can detect
                if "null pointer" in vuln.title.lower():
                    detected_types.add("null_pointer")
                elif "physical memory" in vuln.title.lower():
                    detected_types.add("physical_memory")
                elif "process termination" in vuln.title.lower():
                    detected_types.add("process_termination")
                elif "buffer overflow" in vuln.title.lower():
                    detected_types.add("buffer_overflow")
                elif "tainted" in vuln.title.lower():
                    detected_types.add("tainted_object")

        # We should detect at least 3 different vulnerability types
        assert len(detected_types) >= 3, \
            f"Only detected {len(detected_types)} vulnerability types: {detected_types}"

    @pytest.mark.parametrize("driver_file,min_vulns", [
        ("test_physical_memory.sys", 1),
        ("test_process_termination.sys", 1),
        ("RtDashPt.sys", 1),
    ])
    def test_minimum_vulnerability_detection(self, samples_dir, driver_file, min_vulns):
        """Test that each driver has at least the minimum expected vulnerabilities."""
        driver_path = samples_dir / driver_file

        if not driver_path.exists():
            pytest.skip(f"Driver not found: {driver_path}")

        config = AnalysisConfig(timeout=20, debug=False)
        context = AnalysisContext.create_for_driver(driver_path, config)

        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        assert len(result.vuln) >= min_vulns, \
            f"{driver_file}: Expected at least {min_vulns} vulnerabilities, found {len(result.vuln)}"
