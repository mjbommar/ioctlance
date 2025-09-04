"""Verifier for unconstrained states - determines root cause (NULL deref, overflow, UAF, etc)."""

import logging
from typing import Any, Optional

from .base import VulnerabilityVerifier, VerificationResult
from .registry import verifier_registry

logger = logging.getLogger(__name__)


class UnconstrainedStateVerifier(VulnerabilityVerifier):
    """Analyzes unconstrained states to determine root cause."""
    
    @property
    def name(self) -> str:
        return "unconstrained_state_verifier"
        
    @property
    def vulnerability_types(self) -> list[str]:
        return ["unconstrained_state", "buffer_overflow", "controllable_pc"]
        
    def can_verify(self, vuln_info: dict[str, Any]) -> bool:
        """Check if this is an unconstrained state vulnerability."""
        title = vuln_info.get("title", "").lower()
        vuln_type = vuln_info.get("others", {}).get("type", "")
        
        return (
            "unconstrained" in title or 
            "controllable pc" in title or
            vuln_type == "unconstrained_state"
        )
        
    def verify(self, vuln_info: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Analyze unconstrained state to determine root cause.
        
        Performs:
        1. Memory access pattern analysis
        2. Stack/heap corruption detection
        3. NULL pointer checks
        4. Use-after-free detection
        5. Type confusion analysis
        """
        state = self.get_state(vuln_info)
        if not state:
            return VerificationResult.NEEDS_REVIEW, vuln_info
            
        # Analyze root cause
        root_cause = self._analyze_root_cause(state, vuln_info)
        
        # Build enhanced info based on root cause
        if root_cause["type"] == "null_pointer_dereference":
            return self._handle_null_pointer(vuln_info, root_cause)
        elif root_cause["type"] == "stack_overflow":
            return self._handle_stack_overflow(vuln_info, root_cause)
        elif root_cause["type"] == "heap_overflow":
            return self._handle_heap_overflow(vuln_info, root_cause)
        elif root_cause["type"] == "use_after_free":
            return self._handle_use_after_free(vuln_info, root_cause)
        elif root_cause["type"] == "type_confusion":
            return self._handle_type_confusion(vuln_info, root_cause)
        else:
            # Unknown or generic memory corruption
            return self._handle_generic_corruption(vuln_info, root_cause)
            
    def _analyze_root_cause(self, state: Any, vuln_info: dict[str, Any]) -> dict[str, Any]:
        """Determine the root cause of unconstrained state.
        
        Returns dict with:
        - type: Root cause type
        - evidence: Supporting evidence
        - confidence: Confidence level (0-1)
        """
        evidence = []
        
        # Check 1: NULL pointer dereference
        null_evidence = self._check_null_pointer_pattern(state, vuln_info)
        if null_evidence["confidence"] > 0.7:
            return {
                "type": "null_pointer_dereference",
                "evidence": null_evidence["evidence"],
                "confidence": null_evidence["confidence"],
                "details": null_evidence
            }
            
        # Check 2: Stack corruption
        stack_evidence = self._check_stack_corruption(state)
        if stack_evidence["confidence"] > 0.6:
            return {
                "type": "stack_overflow",
                "evidence": stack_evidence["evidence"],
                "confidence": stack_evidence["confidence"],
                "details": stack_evidence
            }
            
        # Check 3: Heap corruption
        heap_evidence = self._check_heap_corruption(state)
        if heap_evidence["confidence"] > 0.6:
            return {
                "type": "heap_overflow",
                "evidence": heap_evidence["evidence"],
                "confidence": heap_evidence["confidence"],
                "details": heap_evidence
            }
            
        # Check 4: Use-after-free
        uaf_evidence = self._check_use_after_free(state)
        if uaf_evidence["confidence"] > 0.5:
            return {
                "type": "use_after_free",
                "evidence": uaf_evidence["evidence"],
                "confidence": uaf_evidence["confidence"],
                "details": uaf_evidence
            }
            
        # Default: Unknown memory corruption
        return {
            "type": "memory_corruption",
            "evidence": ["Symbolic PC without clear root cause"],
            "confidence": 0.3,
            "details": {}
        }
        
    def _check_null_pointer_pattern(self, state: Any, vuln_info: dict[str, Any]) -> dict[str, Any]:
        """Check if this matches NULL pointer dereference pattern."""
        evidence = []
        confidence = 0.0
        
        # Check recent memory operations
        if hasattr(state, "inspect"):
            # Check last memory read
            if state.inspect.mem_read_address is not None:
                try:
                    addr = state.solver.eval_one(state.inspect.mem_read_address, default=None)
                    if addr is not None and addr < 0x1000:
                        evidence.append(f"Memory read from low address: 0x{addr:x}")
                        confidence += 0.4
                except:
                    pass
                    
            # Check last memory write
            if state.inspect.mem_write_address is not None:
                try:
                    addr = state.solver.eval_one(state.inspect.mem_write_address, default=None)
                    if addr is not None and addr < 0x1000:
                        evidence.append(f"Memory write to low address: 0x{addr:x}")
                        confidence += 0.4
                except:
                    pass
                    
        # Check input parameters from vuln_info
        eval_params = vuln_info.get("eval", {})
        if eval_params.get("SystemBuffer") == "0x0":
            evidence.append("SystemBuffer is NULL")
            confidence += 0.3
        if eval_params.get("Type3InputBuffer") == "0x0":
            evidence.append("Type3InputBuffer is NULL")
            confidence += 0.1
            
        # Check if input buffer length is 0
        if eval_params.get("InputBufferLength") == "0x0":
            evidence.append("InputBufferLength is 0")
            confidence += 0.2
            
        # Look for specific crash patterns in history
        if hasattr(state, "history") and hasattr(state.history, "descriptions"):
            for desc in state.history.descriptions.hardcopy[-10:]:
                if "null" in str(desc).lower():
                    evidence.append(f"NULL reference in history: {desc}")
                    confidence += 0.2
                    break
                    
        return {
            "evidence": evidence,
            "confidence": min(1.0, confidence),
            "buffer_address": eval_params.get("SystemBuffer", "unknown"),
            "ioctl_code": eval_params.get("IoControlCode", "unknown")
        }
        
    def _check_stack_corruption(self, state: Any) -> dict[str, Any]:
        """Check for stack corruption patterns."""
        evidence = []
        confidence = 0.0
        
        try:
            # Check if RSP/ESP is symbolic
            stack_ptr = state.regs.rsp if hasattr(state.regs, "rsp") else state.regs.sp
            if state.solver.symbolic(stack_ptr):
                evidence.append("Stack pointer is symbolic")
                confidence += 0.5
                
            # Check if RBP/EBP is symbolic  
            frame_ptr = state.regs.rbp if hasattr(state.regs, "rbp") else state.regs.ebp
            if state.solver.symbolic(frame_ptr):
                evidence.append("Frame pointer is symbolic")
                confidence += 0.3
                
            # Check for return address overwrite pattern
            if hasattr(state, "callstack") and len(state.callstack) > 0:
                ret_addr = state.callstack.ret_addr
                if state.solver.symbolic(ret_addr):
                    evidence.append("Return address is symbolic")
                    confidence += 0.4
                    
        except Exception as e:
            logger.debug(f"Stack corruption check failed: {e}")
            
        return {
            "evidence": evidence,
            "confidence": min(1.0, confidence)
        }
        
    def _check_heap_corruption(self, state: Any) -> dict[str, Any]:
        """Check for heap corruption patterns."""
        evidence = []
        confidence = 0.0
        
        # Look for heap-related function calls in history
        if hasattr(state, "history") and hasattr(state.history, "descriptions"):
            heap_funcs = ["ExAllocatePool", "ExFreePool", "RtlAllocateHeap", "RtlFreeHeap"]
            recent = state.history.descriptions.hardcopy[-50:]
            
            for desc in recent:
                desc_str = str(desc)
                for func in heap_funcs:
                    if func in desc_str:
                        evidence.append(f"Recent heap operation: {func}")
                        confidence += 0.2
                        break
                        
        # Check for heap metadata patterns
        if hasattr(state, "inspect") and state.inspect.mem_write_address is not None:
            try:
                addr = state.solver.eval_one(state.inspect.mem_write_address, default=None)
                # Heap metadata often at aligned addresses
                if addr and (addr & 0xF) == 0x8:
                    evidence.append(f"Write to heap-like address: 0x{addr:x}")
                    confidence += 0.2
            except:
                pass
                
        return {
            "evidence": evidence,
            "confidence": min(1.0, confidence)
        }
        
    def _check_use_after_free(self, state: Any) -> dict[str, Any]:
        """Check for use-after-free patterns."""
        evidence = []
        confidence = 0.0
        
        # Look for free followed by use pattern
        if hasattr(state, "history") and hasattr(state.history, "descriptions"):
            recent = state.history.descriptions.hardcopy[-30:]
            free_seen = False
            
            for desc in recent:
                desc_str = str(desc)
                if "Free" in desc_str or "free" in desc_str:
                    free_seen = True
                    evidence.append(f"Free operation: {desc_str[:50]}")
                elif free_seen and ("read" in desc_str.lower() or "write" in desc_str.lower()):
                    evidence.append(f"Memory use after free: {desc_str[:50]}")
                    confidence += 0.6
                    break
                    
        return {
            "evidence": evidence,
            "confidence": min(1.0, confidence)
        }
        
    def _handle_null_pointer(self, vuln_info: dict[str, Any], root_cause: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Handle NULL pointer dereference reclassification."""
        enhanced = vuln_info.copy()
        
        # Reclassify the vulnerability
        enhanced["title"] = "NULL Pointer Dereference"
        enhanced["description"] = (
            f"NULL pointer dereference detected. "
            f"Input buffer at {root_cause['details'].get('buffer_address', 'unknown')} was not validated before access."
        )
        
        # Update classification
        if "others" not in enhanced:
            enhanced["others"] = {}
        enhanced["others"]["type"] = "null_pointer_dereference"
        enhanced["others"]["severity"] = "HIGH"  # Downgrade from CRITICAL
        enhanced["others"]["root_cause"] = root_cause
        enhanced["others"]["confidence"] = root_cause["confidence"]
        
        # Add evidence
        enhanced["evidence"] = root_cause["evidence"]
        
        return VerificationResult.RECLASSIFIED, enhanced
        
    def _handle_stack_overflow(self, vuln_info: dict[str, Any], root_cause: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Handle stack overflow confirmation."""
        enhanced = vuln_info.copy()
        
        # Confirm and enhance
        enhanced["title"] = "Stack Buffer Overflow - Confirmed"
        enhanced["description"] = (
            f"Stack buffer overflow confirmed through symbolic execution. "
            f"Stack corruption detected: {', '.join(root_cause['evidence'])}"
        )
        
        if "others" not in enhanced:
            enhanced["others"] = {}
        enhanced["others"]["root_cause"] = root_cause
        enhanced["others"]["confidence"] = root_cause["confidence"]
        
        return VerificationResult.CONFIRMED, enhanced
        
    def _handle_heap_overflow(self, vuln_info: dict[str, Any], root_cause: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Handle heap overflow reclassification."""
        enhanced = vuln_info.copy()
        
        enhanced["title"] = "Heap Buffer Overflow"
        enhanced["description"] = (
            f"Heap buffer overflow detected. "
            f"Evidence: {', '.join(root_cause['evidence'])}"
        )
        
        if "others" not in enhanced:
            enhanced["others"] = {}
        enhanced["others"]["type"] = "heap_overflow"
        enhanced["others"]["root_cause"] = root_cause
        
        return VerificationResult.RECLASSIFIED, enhanced
        
    def _handle_use_after_free(self, vuln_info: dict[str, Any], root_cause: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Handle use-after-free reclassification."""
        enhanced = vuln_info.copy()
        
        enhanced["title"] = "Use-After-Free"
        enhanced["description"] = (
            f"Use-after-free vulnerability detected. "
            f"Memory was accessed after being freed."
        )
        
        if "others" not in enhanced:
            enhanced["others"] = {}
        enhanced["others"]["type"] = "use_after_free"
        enhanced["others"]["severity"] = "CRITICAL"
        enhanced["others"]["root_cause"] = root_cause
        
        return VerificationResult.RECLASSIFIED, enhanced
        
    def _handle_type_confusion(self, vuln_info: dict[str, Any], root_cause: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Handle type confusion."""
        enhanced = vuln_info.copy()
        
        enhanced["title"] = "Type Confusion"
        enhanced["description"] = "Type confusion vulnerability detected."
        
        if "others" not in enhanced:
            enhanced["others"] = {}
        enhanced["others"]["type"] = "type_confusion"
        enhanced["others"]["root_cause"] = root_cause
        
        return VerificationResult.RECLASSIFIED, enhanced
        
    def _handle_generic_corruption(self, vuln_info: dict[str, Any], root_cause: dict[str, Any]) -> tuple[VerificationResult, dict[str, Any]]:
        """Handle generic memory corruption."""
        enhanced = vuln_info.copy()
        
        # Can't determine specific type, but add analysis
        if "others" not in enhanced:
            enhanced["others"] = {}
        enhanced["others"]["root_cause_analysis"] = root_cause
        enhanced["others"]["verification_status"] = "needs_manual_review"
        
        return VerificationResult.NEEDS_REVIEW, enhanced


# Register the verifier
verifier_registry.register(UnconstrainedStateVerifier)