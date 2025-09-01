"""Unit tests for the unified output system."""

import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, MagicMock

import pytest

from ioctlance.output.manager import OutputManager, OutputLevel
from ioctlance.output.formats import OutputFormat, VulnerabilitySummary, AnalysisSummary
from ioctlance.output.fingerprint import DriverFingerprint
from ioctlance.output.vulnerability_context import EnhancedVulnerability
from ioctlance.core.analysis_context import AnalysisContext, AnalysisConfig


class TestDriverFingerprint:
    """Test driver fingerprinting functionality."""
    
    def test_fingerprint_from_file(self, tmp_path):
        """Test creating fingerprint from file."""
        # Create a test file
        test_file = tmp_path / "test.sys"
        test_content = b"Test driver content"
        test_file.write_bytes(test_content)
        
        # Create fingerprint
        fingerprint = DriverFingerprint.from_file(test_file)
        
        # Check basic properties
        assert fingerprint.file_name == "test.sys"
        assert fingerprint.file_size == len(test_content)
        assert fingerprint.file_path == str(test_file.absolute())
        
        # Check hashes are generated
        assert len(fingerprint.blake2b) > 0
        assert len(fingerprint.sha256) > 0
        assert len(fingerprint.sha1) > 0
        assert len(fingerprint.md5) > 0
        
        # Check Blake2b hash is correct
        import hashlib
        expected_blake2b = hashlib.blake2b(test_content).hexdigest()
        assert fingerprint.blake2b == expected_blake2b
    
    def test_fingerprint_to_dict(self, tmp_path):
        """Test fingerprint dictionary conversion."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        
        fingerprint = DriverFingerprint.from_file(test_file)
        data = fingerprint.to_dict()
        
        assert isinstance(data, dict)
        assert "blake2b" in data
        assert "file_name" in data
        assert "fingerprinted_at" in data


class TestOutputManager:
    """Test output manager functionality."""
    
    @pytest.fixture
    def output_manager(self):
        """Create output manager for testing."""
        return OutputManager(
            output_level=OutputLevel.NORMAL,
            output_format=OutputFormat.JSON,
            dedup_vulnerabilities=True,
            capture_raw_state=False
        )
    
    @pytest.fixture
    def mock_state(self):
        """Create mock SimState."""
        state = MagicMock()
        state.addr = 0x140001234
        state.solver.eval_one.return_value = 0x222000
        state.solver.symbolic.return_value = True
        state.__str__ = lambda self: f"<SimState @ {hex(state.addr)}>"
        return state
    
    @pytest.fixture
    def mock_context(self):
        """Create mock analysis context."""
        context = MagicMock()
        context.io_control_code = MagicMock()
        context.system_buffer = MagicMock()
        context.input_buffer_length = MagicMock()
        context.output_buffer_length = MagicMock()
        return context
    
    def test_initialize(self, output_manager, tmp_path):
        """Test output manager initialization."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        
        output_manager.initialize(test_file, {"timeout": 120})
        
        assert output_manager.driver_path == test_file
        assert output_manager.fingerprint is not None
        assert output_manager.config == {"timeout": 120}
    
    def test_add_vulnerability(self, output_manager, mock_state, mock_context, tmp_path):
        """Test adding vulnerabilities."""
        # Initialize first
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        output_manager.initialize(test_file)
        
        # Add vulnerability
        vuln = output_manager.add_vulnerability(
            title="Test Vulnerability",
            description="Test description",
            state=mock_state,
            context=mock_context,
            parameters={"test": "param"}
        )
        
        assert len(output_manager.vulnerabilities) == 1
        assert output_manager.vulnerabilities[0].vulnerability.title == "Test Vulnerability"
    
    def test_deduplication(self, output_manager, mock_state, mock_context, tmp_path):
        """Test vulnerability deduplication."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        output_manager.initialize(test_file)
        
        # Add same vulnerability twice
        vuln1 = output_manager.add_vulnerability(
            title="Duplicate Vuln",
            description="Test",
            state=mock_state,
            context=mock_context
        )
        
        vuln2 = output_manager.add_vulnerability(
            title="Duplicate Vuln",
            description="Test",
            state=mock_state,
            context=mock_context
        )
        
        # Should be deduplicated
        assert len(output_manager.vulnerabilities) == 1
        assert vuln1 is vuln2
        assert vuln1.occurrence_count == 2
    
    def test_create_result(self, output_manager, tmp_path):
        """Test creating unified result."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        output_manager.initialize(test_file)
        
        # Create result
        result = output_manager.create_result(
            analysis_time=10.5,
            errors=["test error"]
        )
        
        assert result.fingerprint.file_name == "test.sys"
        assert result.analysis_time == 10.5
        assert result.errors == ["test error"]
        assert result.summary.driver_name == "test.sys"
    
    def test_format_json(self, output_manager, tmp_path):
        """Test JSON formatting."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        output_manager.initialize(test_file)
        
        result = output_manager.create_result(analysis_time=5.0)
        output = output_manager.format_output(result)
        
        # Should be valid JSON
        data = json.loads(output)
        assert "fingerprint" in data
        assert "summary" in data
    
    def test_format_markdown(self, output_manager, tmp_path):
        """Test Markdown formatting."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        output_manager.initialize(test_file)
        output_manager.output_format = OutputFormat.MARKDOWN
        
        result = output_manager.create_result(analysis_time=5.0)
        output = output_manager.format_output(result)
        
        # Should contain markdown elements
        assert "# Analysis Report" in output
        assert "## Summary" in output
    
    def test_save_output(self, output_manager, tmp_path):
        """Test saving output to file."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"content")
        output_manager.initialize(test_file)
        
        result = output_manager.create_result(analysis_time=5.0)
        output_file = tmp_path / "output.json"
        
        output_manager.save_output(result, output_file)
        
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
            assert "fingerprint" in data


class TestEnhancedVulnerability:
    """Test enhanced vulnerability context."""
    
    def test_from_detection(self):
        """Test creating enhanced vulnerability from detection."""
        mock_state = MagicMock()
        mock_state.addr = 0x140001234
        mock_state.solver.eval_one.return_value = 0x222000
        mock_state.__str__ = lambda self: f"<SimState @ {hex(mock_state.addr)}>"
        
        mock_context = MagicMock()
        mock_context.io_control_code = MagicMock()
        
        vuln = EnhancedVulnerability.from_detection(
            title="Test Vuln",
            description="Test description",
            state=mock_state,
            context=mock_context,
            capture_full_state=False
        )
        
        assert vuln.vulnerability.title == "Test Vuln"
        assert vuln.dedup_key.startswith("Test Vuln:")
        assert vuln.instance_id is not None
    
    def test_to_rich_dict(self):
        """Test converting to rich dictionary."""
        mock_state = MagicMock()
        mock_state.addr = 0x140001234
        mock_state.__str__ = lambda self: f"<SimState @ {hex(mock_state.addr)}>"
        
        vuln = EnhancedVulnerability.from_detection(
            title="Test",
            description="Desc",
            state=mock_state,
            capture_full_state=False
        )
        
        data = vuln.to_rich_dict(include_raw_state=False)
        
        assert "vulnerability" in data
        assert "context" in data
        assert "metadata" in data
        assert "raw_state" not in data


class TestAnalysisContextIntegration:
    """Test integration with analysis context."""
    
    def test_context_with_output_manager(self, tmp_path):
        """Test context creation with output manager."""
        test_file = tmp_path / "test.sys"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)  # Minimal PE header
        
        output_manager = OutputManager()
        config = AnalysisConfig(timeout=10)
        
        # This will fail with real angr loading, but tests the interface
        with pytest.raises(Exception):
            context = AnalysisContext.create_for_driver(
                test_file,
                config,
                output_manager=output_manager
            )
    
    def test_add_vulnerability_with_manager(self):
        """Test adding vulnerability with output manager."""
        mock_state = MagicMock()
        mock_state.addr = 0x140001234
        mock_state.solver.eval_one.return_value = 0x222000
        
        output_manager = Mock(spec=OutputManager)
        
        # Create minimal context
        context = AnalysisContext(
            project=None,
            cfg=None,
            calling_convention=None,
            config=AnalysisConfig(),
            output_manager=output_manager
        )
        
        # Add vulnerability
        vuln_info = {
            "title": "Test",
            "description": "Test",
            "state": mock_state
        }
        
        context.add_vulnerability(vuln_info)
        
        # Should call output manager
        output_manager.add_vulnerability.assert_called_once()


class TestOutputFormats:
    """Test various output format classes."""
    
    def test_vulnerability_summary(self):
        """Test vulnerability summary."""
        summary = VulnerabilitySummary(
            type="ARBITRARY_WRITE",
            severity="CRITICAL",
            count=3,
            ioctl_codes=["0x222000", "0x222004"]
        )
        
        # Test markdown row
        row = summary.to_markdown_row()
        assert "ARBITRARY_WRITE" in row
        assert "CRITICAL" in row
        
        # Test CSV row
        csv = summary.to_csv_row()
        assert "ARBITRARY_WRITE" in csv
        assert "0x222000;0x222004" in csv
    
    def test_analysis_summary(self):
        """Test analysis summary."""
        summary = AnalysisSummary(
            driver_name="test.sys",
            driver_hash="abc123",
            analysis_time=10.5,
            analysis_date=datetime.now().isoformat(),
            vulnerabilities_found=2,
            unique_vulnerabilities=1
        )
        
        # Test markdown generation
        markdown = summary.to_markdown()
        assert "# Analysis Report: test.sys" in markdown
        assert "abc123" in markdown
        
        # Test HTML generation
        html = summary.to_html()
        assert "<html>" in html
        assert "test.sys" in html
        
        # Test CSV generation
        csv = summary.to_csv()
        assert "Type,Severity,Count,IOCTL_Codes" in csv


if __name__ == "__main__":
    pytest.main([__file__, "-v"])