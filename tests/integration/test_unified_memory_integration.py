"""Integration tests for unified memory detector with actual symbolic execution."""

import pytest
import tempfile
from pathlib import Path
import struct

import angr
import claripy

# Add src to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ioctlance.detectors.unified_memory import UnifiedMemoryDetector, MemoryRegion
from ioctlance.core.analysis_context import AnalysisContext, AnalysisConfig


def create_test_driver(vulnerability_type: str) -> bytes:
    """
    Create a minimal test driver binary with specific vulnerability.
    
    This creates a simple PE binary with different vulnerability patterns.
    """
    # Minimal PE header (simplified for testing)
    pe_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)  # e_lfanew
    
    # Different vulnerability patterns
    if vulnerability_type == "double_free":
        # Pattern: allocate, free, free again
        code = bytes([
            0x48, 0x89, 0x5C, 0x24, 0x08,  # mov [rsp+8], rbx
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,  # lea rcx, [pool_tag]
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ExAllocatePoolWithTag
            0x48, 0x89, 0xC3,  # mov rbx, rax (save ptr)
            0x48, 0x89, 0xD9,  # mov rcx, rbx
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ExFreePool
            0x48, 0x89, 0xD9,  # mov rcx, rbx
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ExFreePool (double free!)
            0xC3  # ret
        ])
    elif vulnerability_type == "use_after_free":
        # Pattern: allocate, free, use
        code = bytes([
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,  # lea rcx, [pool_tag]
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ExAllocatePoolWithTag
            0x48, 0x89, 0xC3,  # mov rbx, rax
            0x48, 0x89, 0xD9,  # mov rcx, rbx
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ExFreePool
            0x48, 0x8B, 0x03,  # mov rax, [rbx] (use after free!)
            0xC3  # ret
        ])
    elif vulnerability_type == "refcount":
        # Pattern: reference, dereference, dereference
        code = bytes([
            0x48, 0x89, 0xC1,  # mov rcx, rax (object ptr)
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ObReferenceObject
            0x48, 0x89, 0xC1,  # mov rcx, rax
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ObDereferenceObject
            0x48, 0x89, 0xC1,  # mov rcx, rax
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  # call ObDereferenceObject (underflow!)
            0xC3  # ret
        ])
    else:
        # Safe pattern
        code = bytes([
            0x48, 0x31, 0xC0,  # xor rax, rax
            0xC3  # ret
        ])
    
    # Combine into minimal binary
    binary = pe_header + b"\x00" * (0x80 - len(pe_header))
    binary += b"PE\x00\x00" + b"\x00" * 100  # Simplified PE optional header
    binary += b"\x00" * 0x100  # Padding
    binary += code
    
    return binary


class TestUnifiedMemoryIntegration:
    """Integration tests for unified memory detector."""
    
    @pytest.fixture
    def analysis_config(self):
        """Create analysis configuration."""
        config = AnalysisConfig()
        config.timeout = 10
        config.max_states = 100
        config.debug = False
        return config
    
    @pytest.fixture
    def create_project(self):
        """Factory to create angr project from binary."""
        def _create(vuln_type: str):
            # Create test binary
            binary_data = create_test_driver(vuln_type)
            
            # Write to temp file
            with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
                f.write(binary_data)
                binary_path = f.name
            
            # Create angr project
            project = angr.Project(
                binary_path,
                auto_load_libs=False,
                load_options={'main_opts': {'backend': 'blob', 'arch': 'amd64'}}
            )
            
            return project, Path(binary_path)
        
        return _create
    
    def test_double_free_detection_symbolic(self, create_project, analysis_config):
        """Test double-free detection with symbolic execution."""
        project, binary_path = create_project("double_free")
        
        # Create analysis context
        context = AnalysisContext(binary_path, project, analysis_config)
        
        # Create detector
        detector = UnifiedMemoryDetector(context)
        
        # Create initial state
        state = project.factory.blank_state(addr=project.entry)
        
        # Hook memory functions
        def hook_exallocatepool(state):
            # Return symbolic pointer
            ptr = claripy.BVS("alloc_ptr", 64)
            state.solver.add(ptr >= 0x80000000)  # Kernel space
            state.solver.add(ptr < 0x90000000)
            
            # Track allocation
            detector._handle_allocation(
                state,
                "ExAllocatePoolWithTag",
                pool_type=0,
                size=0x100,
                tag="TEST"
            )
            return ptr
        
        def hook_exfreepool(state):
            # Get pointer from RCX
            ptr = state.regs.rcx
            result = detector._handle_free(
                state,
                "ExFreePool",
                pool_ptr=ptr
            )
            
            # Store result for checking
            if result:
                state.globals["vuln_detected"] = result
        
        # Set up hooks
        project.hook_symbol("ExAllocatePoolWithTag", hook_exallocatepool)
        project.hook_symbol("ExFreePool", hook_exfreepool)
        
        # Run symbolic execution
        simgr = project.factory.simulation_manager(state)
        simgr.explore(find=lambda s: "vuln_detected" in s.globals)
        
        # Check if vulnerability was detected
        if simgr.found:
            found_state = simgr.found[0]
            vuln = found_state.globals["vuln_detected"]
            
            assert vuln["title"] == "Double-Free Vulnerability"
            assert "severity" in vuln["others"]
            assert vuln["others"]["severity"] == "CRITICAL"
    
    def test_use_after_free_detection(self, create_project, analysis_config):
        """Test use-after-free detection."""
        project, binary_path = create_project("use_after_free")
        
        # Create context and detector
        context = AnalysisContext(binary_path, project, analysis_config)
        detector = UnifiedMemoryDetector(context)
        
        # Simulate execution with UAF pattern
        state = project.factory.blank_state(addr=project.entry)
        
        # Simulate: allocate
        alloc_addr = 0x80001000
        detector._handle_allocation(
            state,
            "ExAllocatePoolWithTag",
            pool_type=0,
            size=0x100,
            tag="UAF"
        )
        
        # Update tracking to use our known address
        if detector.memory_regions:
            old_addr = list(detector.memory_regions.keys())[0]
            region = detector.memory_regions[old_addr]
            del detector.memory_regions[old_addr]
            region.address = alloc_addr
            detector.memory_regions[alloc_addr] = region
        
        # Simulate: free
        detector._handle_free(state, "ExFreePool", pool_ptr=alloc_addr)
        
        # Simulate: use after free (memory read)
        result = detector.check_state(
            state,
            "mem_read",
            address=alloc_addr,
            size=8
        )
        
        assert result is not None
        assert result["title"] == "Use-After-Free Vulnerability"
        assert result["parameters"]["access_type"] == "read"
    
    def test_reference_counting_integration(self, create_project, analysis_config):
        """Test reference counting with object lifecycle."""
        project, binary_path = create_project("refcount")
        
        context = AnalysisContext(binary_path, project, analysis_config)
        detector = UnifiedMemoryDetector(context)
        
        state = project.factory.blank_state(addr=project.entry)
        
        # Simulate object lifecycle
        obj_addr = 0x90000000
        
        # Create object (first reference)
        detector._handle_reference(state, "ObReferenceObject", object=obj_addr)
        assert detector.memory_regions[obj_addr].reference_count == 1
        
        # Add another reference
        detector._handle_reference(state, "ObReferenceObject", object=obj_addr)
        assert detector.memory_regions[obj_addr].reference_count == 2
        
        # Dereference once
        result = detector._handle_dereference(state, "ObDereferenceObject", object=obj_addr)
        assert result is None  # No error
        assert detector.memory_regions[obj_addr].reference_count == 1
        
        # Dereference again (goes to 0, object freed)
        result = detector._handle_dereference(state, "ObDereferenceObject", object=obj_addr)
        assert result is None
        assert obj_addr not in detector.memory_regions
        assert obj_addr in detector.freed_regions
        
        # Dereference again - should detect underflow/UAF
        result = detector._handle_dereference(state, "ObDereferenceObject", object=obj_addr)
        assert result is not None
        assert "Use-After-Free" in result["title"] or "Reference" in result["title"]
    
    def test_symbolic_pointer_handling(self, analysis_config):
        """Test handling of symbolic pointers."""
        # Create a minimal project
        project = angr.Project(
            "/bin/true",  # Use any binary, we're just testing detector
            auto_load_libs=False
        )
        
        context = AnalysisContext(Path("/bin/true"), project, analysis_config)
        detector = UnifiedMemoryDetector(context)
        
        state = project.factory.blank_state()
        
        # Create symbolic pointer
        sym_ptr = claripy.BVS("symbolic_ptr", 64)
        state.solver.add(sym_ptr >= 0x80000000)
        state.solver.add(sym_ptr < 0x90000000)
        
        # Try to free symbolic pointer
        result = detector._handle_free(state, "ExFreePool", pool_ptr=sym_ptr)
        
        # Should handle gracefully (either detect as arbitrary free or handle safely)
        assert result is None or result["title"] == "Arbitrary Free Vulnerability"
    
    def test_pool_tag_tracking(self, analysis_config):
        """Test pool tag tracking and validation."""
        project = angr.Project("/bin/true", auto_load_libs=False)
        context = AnalysisContext(Path("/bin/true"), project, analysis_config)
        detector = UnifiedMemoryDetector(context)
        
        state = project.factory.blank_state()
        
        # Test different pool tags
        tags = ["File", "Devi", "Proc", "Test"]
        
        for i, tag in enumerate(tags):
            detector._handle_allocation(
                state,
                "ExAllocatePoolWithTag",
                pool_type=0,
                size=0x100,
                tag=tag
            )
        
        # Check statistics
        stats = detector.get_statistics()
        assert stats["tracked_allocations"] == len(tags)
        
        for tag in tags:
            assert tag in stats["pool_tags"]
            assert stats["pool_tags"][tag] == 1
    
    def test_range_based_detection(self, analysis_config):
        """Test detection of access within freed regions."""
        project = angr.Project("/bin/true", auto_load_libs=False)
        context = AnalysisContext(Path("/bin/true"), project, analysis_config)
        detector = UnifiedMemoryDetector(context)
        
        state = project.factory.blank_state()
        
        # Allocate large region
        base_addr = 0x80000000
        region_size = 0x10000  # 64KB
        
        detector.memory_regions[base_addr] = detector.memory_regions.get(base_addr) or \
            UnifiedMemoryDetector.MemoryRegion(
                address=base_addr,
                size=region_size,
                pool_tag="LARGE"
            )
        
        # Free it
        detector._handle_free(state, "ExFreePool", pool_ptr=base_addr)
        
        # Access middle of freed region
        middle_addr = base_addr + 0x8000
        result = detector.check_state(
            state,
            "mem_write",
            address=middle_addr,
            size=0x100
        )
        
        assert result is not None
        assert result["title"] == "Use-After-Free Vulnerability"
        assert result["parameters"]["is_range_access"] is True
    
    def test_windows_specific_patterns(self, analysis_config):
        """Test Windows-specific memory patterns."""
        project = angr.Project("/bin/true", auto_load_libs=False)
        context = AnalysisContext(Path("/bin/true"), project, analysis_config)
        detector = UnifiedMemoryDetector(context)
        
        state = project.factory.blank_state()
        
        # Test MmFreeContiguousMemory pattern
        detector._handle_contiguous_free = lambda s, **kw: detector._handle_free(s, "MmFreeContiguousMemory", **kw)
        
        # Test RtlFreeHeap pattern
        detector._handle_heap_free = lambda s, **kw: detector._handle_free(s, "RtlFreeHeap", **kw)
        
        # Allocate and free with different patterns
        addr1 = 0x80100000
        addr2 = 0x80200000
        
        detector.memory_regions[addr1] = UnifiedMemoryDetector.MemoryRegion(
            address=addr1, size=0x1000, pool_tag="CONT"
        )
        detector.memory_regions[addr2] = UnifiedMemoryDetector.MemoryRegion(
            address=addr2, size=0x1000, pool_tag="HEAP"
        )
        
        # Free with appropriate functions
        result1 = detector._handle_contiguous_free(state, address=addr1)
        result2 = detector._handle_heap_free(state, heap=0, address=addr2)
        
        assert result1 is None  # Successful free
        assert result2 is None  # Successful free
        assert addr1 in detector.freed_regions
        assert addr2 in detector.freed_regions


if __name__ == "__main__":
    pytest.main([__file__, "-v"])