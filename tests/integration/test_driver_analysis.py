"""Integration tests for driver analysis functionality."""

import json
from pathlib import Path

import pytest

from ioctlance.core.analysis_context import AnalysisConfig, AnalysisContext
from ioctlance.core.driver_analyzer import DriverAnalyzer


class TestDriverAnalysis:
    """Test driver analysis on real sample files."""

    @pytest.fixture
    def samples_dir(self):
        """Get the samples directory path."""
        return Path(__file__).parent.parent.parent / "samples"

    def test_analyze_rtdashpt(self, samples_dir):
        """Test analysis of RtDashPt.sys driver."""
        driver_path = samples_dir / "RtDashPt.sys"

        if not driver_path.exists():
            pytest.skip(f"Sample driver not found: {driver_path}")

        # Create configuration with short timeout for testing
        config = AnalysisConfig(timeout=30, debug=False)
        context = AnalysisContext.create_for_driver(driver_path, config)

        # Run analysis
        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        # Basic assertions
        assert result is not None
        assert result.basic.path == str(driver_path)
        assert result.basic.ioctl_handler != "0x0"

        # Should find at least one IOCTL code
        assert len(result.basic.IoControlCodes) > 0

        # Should find some vulnerabilities (RtDashPt is known vulnerable)
        assert len(result.vuln) > 0

    def test_analyze_with_specific_ioctl(self, samples_dir):
        """Test targeted analysis with specific IOCTL code."""
        driver_path = samples_dir / "RtDashPt.sys"

        if not driver_path.exists():
            pytest.skip(f"Sample driver not found: {driver_path}")

        # Target specific IOCTL code
        config = AnalysisConfig(
            timeout=20,
            target_ioctl="0x22201c",
            debug=False
        )
        context = AnalysisContext.create_for_driver(driver_path, config)

        # Run analysis
        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        # Should still complete successfully
        assert result is not None
        assert result.basic.ioctl_handler != "0x0"

    @pytest.mark.parametrize("driver_name", [
        "RtDashPt.sys",
        "ilp60x64_3.sys",
    ])
    def test_analyze_multiple_drivers(self, samples_dir, driver_name):
        """Test analysis of multiple driver samples."""
        driver_path = samples_dir / driver_name

        if not driver_path.exists():
            pytest.skip(f"Sample driver not found: {driver_path}")

        config = AnalysisConfig(timeout=15, debug=False)
        context = AnalysisContext.create_for_driver(driver_path, config)

        # Run analysis
        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        # Basic validation
        assert result is not None
        assert result.basic.path == str(driver_path)

        # Should discover driver type
        assert context.driver_type in ["wdm", "wdf", "kmdf", "unknown"]

    def test_json_serialization(self, samples_dir):
        """Test that results can be serialized to JSON."""
        driver_path = samples_dir / "RtDashPt.sys"

        if not driver_path.exists():
            pytest.skip(f"Sample driver not found: {driver_path}")

        config = AnalysisConfig(timeout=15, debug=False)
        context = AnalysisContext.create_for_driver(driver_path, config)

        # Run analysis
        analyzer = DriverAnalyzer(context)
        result = analyzer.analyze()

        # Test JSON serialization
        json_str = result.model_dump_json()
        assert json_str is not None

        # Should be valid JSON
        data = json.loads(json_str)
        assert "basic" in data
        assert "vuln" in data
        assert "error" in data
