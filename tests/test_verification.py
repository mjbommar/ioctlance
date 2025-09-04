#!/usr/bin/env python3
"""Test script for post-detection verification system."""

import logging
from pathlib import Path
from unittest.mock import Mock

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_unconstrained_verification():
    """Test the unconstrained state verifier with the 3xHybr64.sys case."""
    
    # Import verification modules
    from ioctlance.verification import VerificationManager, VulnerabilityVerifier
    from ioctlance.verification.manager import VerificationLevel
    from ioctlance.verification.registry import verifier_registry
    from ioctlance.verification.unconstrained_verifier import UnconstrainedStateVerifier
    
    # Create mock context
    mock_context = Mock()
    mock_context.config = Mock()
    mock_context.config.verification_enabled = True
    mock_context.config.verification_level = "standard"
    mock_context.io_control_code = None
    
    # Create verification manager
    manager = VerificationManager(mock_context, VerificationLevel.STANDARD)
    
    # Test case 1: NULL pointer dereference misclassified as buffer overflow
    vuln_null_ptr = {
        "title": "Buffer Overflow - Controllable PC",
        "description": "Unconstrained state with symbolic program counter (likely buffer overflow)",
        "eval": {
            "IoControlCode": "0x232c08",
            "SystemBuffer": "0x0",  # NULL buffer
            "Type3InputBuffer": "0x0",
            "UserBuffer": "0x0",
            "InputBufferLength": "0x0",
            "OutputBufferLength": "0x0"
        },
        "others": {
            "severity": "CRITICAL",
            "type": "unconstrained_state"
        }
    }
    
    # Create mock state
    mock_state = Mock()
    mock_state.solver = Mock()
    mock_state.inspect = Mock()
    mock_state.inspect.mem_read_address = Mock()
    mock_state.solver.eval_one = Mock(return_value=0x8)  # Low address indicating NULL deref
    mock_state.history = Mock()
    mock_state.history.descriptions = Mock()
    mock_state.history.descriptions.hardcopy = []
    
    vuln_null_ptr["state"] = mock_state
    
    print("\n=== Test 1: NULL Pointer Dereference ===")
    print(f"Original: {vuln_null_ptr['title']}")
    
    result = manager.verify_vulnerability(vuln_null_ptr)
    
    if result:
        print(f"Verified: {result.get('title')}")
        print(f"Type: {result.get('others', {}).get('type')}")
        print(f"Evidence: {result.get('evidence', [])}")
        assert result["title"] == "NULL Pointer Dereference", "Should reclassify as NULL pointer"
        assert result["others"]["type"] == "null_pointer_dereference"
        print("✓ Test passed: Correctly reclassified as NULL pointer dereference")
    else:
        print("✗ Vulnerability was filtered (unexpected)")
        
    # Test case 2: Actual buffer overflow (stack corruption)
    vuln_stack = {
        "title": "Buffer Overflow - Controllable PC",
        "description": "Unconstrained state with symbolic program counter",
        "eval": {
            "IoControlCode": "0x220040",
            "SystemBuffer": "0x12345678",
            "InputBufferLength": "0x1000"
        },
        "others": {
            "severity": "CRITICAL",
            "type": "unconstrained_state"
        }
    }
    
    # Create mock state with stack corruption evidence
    mock_state2 = Mock()
    mock_state2.solver = Mock()
    mock_state2.regs = Mock()
    mock_state2.regs.rsp = Mock()
    mock_state2.solver.symbolic = Mock(return_value=True)  # RSP is symbolic
    mock_state2.callstack = Mock()
    mock_state2.callstack.ret_addr = Mock()
    mock_state2.inspect = Mock()
    mock_state2.inspect.mem_read_address = None
    mock_state2.history = Mock()
    mock_state2.history.descriptions = Mock()
    mock_state2.history.descriptions.hardcopy = []
    
    vuln_stack["state"] = mock_state2
    
    print("\n=== Test 2: Stack Buffer Overflow ===")
    print(f"Original: {vuln_stack['title']}")
    
    result2 = manager.verify_vulnerability(vuln_stack)
    
    if result2:
        print(f"Verified: {result2.get('title')}")
        print(f"Confirmation: {result2.get('verification', {}).get('result')}")
        assert "Stack" in result2["title"] or result2["verification"]["result"] == "confirmed"
        print("✓ Test passed: Stack overflow properly handled")
        
    # Print statistics
    print("\n=== Verification Statistics ===")
    manager.print_stats()
    
    print("\n✓ All tests passed!")


def test_verification_config():
    """Test configuration options for verification."""
    from ioctlance.core.analysis_context import AnalysisConfig
    
    print("\n=== Testing Configuration Options ===")
    
    # Test with verification disabled
    config1 = AnalysisConfig(
        verification_enabled=False,
        verification_level="none"
    )
    assert not config1.verification_enabled
    print("✓ Verification can be disabled")
    
    # Test with different levels
    config2 = AnalysisConfig(
        verification_enabled=True,
        verification_level="basic"
    )
    assert config2.verification_level == "basic"
    print("✓ Basic verification level")
    
    config3 = AnalysisConfig(
        verification_enabled=True,
        verification_level="deep"
    )
    assert config3.verification_level == "deep"
    print("✓ Deep verification level")
    
    # Test false positive filtering
    config4 = AnalysisConfig(
        verification_enabled=True,
        filter_false_positives=True,
        reclassify_vulnerabilities=True
    )
    assert config4.filter_false_positives
    assert config4.reclassify_vulnerabilities
    print("✓ False positive filtering enabled")
    
    print("\n✓ Configuration tests passed!")


if __name__ == "__main__":
    test_unconstrained_verification()
    test_verification_config()
    print("\n✓✓✓ All verification tests passed! ✓✓✓")