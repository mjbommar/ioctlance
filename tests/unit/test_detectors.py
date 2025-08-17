"""Unit tests for vulnerability detectors using real drivers."""

from pathlib import Path

import pytest

from ioctlance.core.analysis_context import AnalysisConfig, AnalysisContext
from ioctlance.detectors import detector_registry


class TestDetectorRegistry:
    """Test the detector registry functionality with real context."""

    @pytest.fixture
    def real_context(self):
        """Create a real analysis context using a test driver."""
        samples_dir = Path(__file__).parent.parent.parent / "samples"
        driver_path = samples_dir / "test_physical_memory.sys"

        if not driver_path.exists():
            # Fall back to any available .sys file
            sys_files = list(samples_dir.glob("*.sys"))
            if sys_files:
                driver_path = sys_files[0]
            else:
                pytest.skip("No test drivers available")

        config = AnalysisConfig(timeout=5, debug=False)
        return AnalysisContext.create_for_driver(driver_path, config)

    def test_registry_has_detectors(self):
        """Test that the registry contains registered detectors."""
        detectors = detector_registry.get_all_detectors()
        assert len(detectors) > 0

        # Check for some expected detectors
        detector_names = [d.__name__ for d in detectors]
        assert "NullPointerDetector" in detector_names
        assert "PhysicalMemoryDetector" in detector_names
        assert "StackBufferOverflowDetector" in detector_names
        assert "ProcessTerminationDetector" in detector_names

    def test_create_instances(self, real_context):
        """Test creating detector instances with real context."""
        instances = detector_registry.create_instances(real_context)

        assert len(instances) > 0
        assert all(hasattr(d, "check_state") for d in instances)
        assert all(hasattr(d, "name") for d in instances)

    def test_detector_names(self, real_context):
        """Test that all detectors have unique names."""
        instances = detector_registry.create_instances(real_context)
        names = [d.name for d in instances]

        # All names should be unique
        assert len(names) == len(set(names))

        # Should have expected detectors
        assert "null_pointer" in names
        assert "physical_memory_mapping" in names
        assert "stack_buffer_overflow" in names
        assert "process_termination" in names

    def test_detector_check_state(self, real_context):
        """Test that detectors can check states without errors."""
        instances = detector_registry.create_instances(real_context)

        # Create a blank state to test with
        state = real_context.project.factory.blank_state()

        # Each detector should be able to check the state with different event types
        event_types = ["mem_read", "mem_write", "call", "ret"]

        for detector in instances:
            for event_type in event_types:
                # Should not raise an exception
                result = detector.check_state(state, event_type)
                # Result should be None or a vulnerability dict
                assert result is None or isinstance(result, dict)


class TestSpecificDetectors:
    """Test specific detector implementations."""

    @pytest.fixture
    def physical_memory_context(self):
        """Get context for physical memory test driver."""
        samples_dir = Path(__file__).parent.parent.parent / "samples"
        driver_path = samples_dir / "test_physical_memory.sys"

        if not driver_path.exists():
            pytest.skip("test_physical_memory.sys not found")

        config = AnalysisConfig(timeout=5, debug=False)
        return AnalysisContext.create_for_driver(driver_path, config)

    @pytest.fixture
    def process_termination_context(self):
        """Get context for process termination test driver."""
        samples_dir = Path(__file__).parent.parent.parent / "samples"
        driver_path = samples_dir / "test_process_termination.sys"

        if not driver_path.exists():
            pytest.skip("test_process_termination.sys not found")

        config = AnalysisConfig(timeout=5, debug=False)
        return AnalysisContext.create_for_driver(driver_path, config)

    def test_physical_memory_detector_initialization(self, physical_memory_context):
        """Test PhysicalMemoryDetector initialization."""
        from ioctlance.detectors.physical_memory import PhysicalMemoryDetector

        detector = PhysicalMemoryDetector(physical_memory_context)
        assert detector.name == "physical_memory_mapping"
        assert detector.context == physical_memory_context

    def test_process_termination_detector_initialization(self, process_termination_context):
        """Test ProcessTerminationDetector initialization."""
        from ioctlance.detectors.process_termination import ProcessTerminationDetector

        detector = ProcessTerminationDetector(process_termination_context)
        assert detector.name == "process_termination"
        assert detector.context == process_termination_context
