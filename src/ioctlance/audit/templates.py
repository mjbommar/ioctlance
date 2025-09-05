"""Claude Code prompt templates for vulnerability auditing."""

from typing import Any
from pathlib import Path


class AuditPromptTemplates:
    """Manages prompt templates for Claude Code auditing."""

    @staticmethod
    def investigation_prompt(driver_path: Path, vulnerability: dict[str, Any]) -> str:
        """
        Generate investigation prompt for vulnerability analysis.

        This prompt guides Claude Code through:
        1. Binary analysis with objdump/nm/strings
        2. Static analysis with IOCTLance Python API
        3. Classification based on evidence
        4. Detailed evidence collection
        """

        title = vulnerability.get("title", "Unknown")
        ioctl = vulnerability.get("eval", {}).get("IoControlCode", "unknown")
        severity = vulnerability.get("others", {}).get("severity", "UNKNOWN")

        return f"""# Vulnerability Investigation Task

You are a security researcher auditing a potential vulnerability. Your goal is to determine if this is a true positive (real vulnerability) or false positive.

## Target Information
- **Driver**: `{driver_path}`
- **Vulnerability**: {title}
- **IOCTL**: {ioctl}
- **Severity**: {severity}

## Investigation Steps

### Step 1: Binary Reconnaissance
```bash
# Verify the file exists and get basic info
file {driver_path}
ls -la {driver_path}

# Find the IOCTL dispatch table
objdump -d {driver_path} | grep -E "DispatchDeviceControl|{ioctl}" -B 5 -A 20

# Look for dangerous functions
nm {driver_path} | grep -E "(memcpy|strcpy|sprintf|memmove|strcat)"

# Check for input validation strings
strings {driver_path} | grep -iE "(check|verify|validate|bound|limit|size)"
```

### Step 2: Targeted Static Analysis
```python
# Use IOCTLance to analyze the specific IOCTL
import sys
sys.path.insert(0, '/home/mjbommar/src/ioctlance/src')

from pathlib import Path
from ioctlance.core import analyze_driver

driver = Path("{driver_path}")
if driver.exists():
    # Quick targeted scan
    result = analyze_driver(str(driver), timeout=60)

    # Find our specific vulnerability
    for vuln in result.get('vulnerabilities', []):
        if vuln.get('eval', {{}}).get('IoControlCode') == "{ioctl}":
            print("FOUND MATCHING VULNERABILITY:")
            print(f"  Type: {{vuln.get('others', {{}}).get('type')}}")
            print(f"  Title: {{vuln.get('title')}}")
            print(f"  Constraints: {{vuln.get('constraints', [])}}")
```

### Step 3: Deep Dive Analysis
```bash
# Disassemble the specific IOCTL handler
objdump -d {driver_path} | awk '/{ioctl}/,/^$/' | head -100

# Look for the actual vulnerable instruction
objdump -d {driver_path} | grep -E "(call.*memcpy|call.*strcpy)" -B 10 -A 5
```

## Classification Guidelines

### Classify as TRUE_POSITIVE if:
- User-controlled input reaches dangerous functions without validation
- Buffer sizes are not checked before copy operations
- Integer overflows can occur in size calculations
- The vulnerability can lead to code execution or privilege escalation

### Classify as FALSE_POSITIVE if:
- It's actually a NULL pointer dereference (not a buffer overflow)
- Input validation prevents the vulnerable condition
- The code path is unreachable from user mode
- Security checks make exploitation impossible

### Classify as NEEDS_REVIEW if:
- Complex constraints need manual analysis
- Partial mitigations might be bypassable
- More context is needed

## Required Output Format
```json
{{
  "classification": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW",
  "confidence": 85,
  "evidence": {{
    "vulnerable_address": "0x1400",
    "vulnerable_instruction": "call memcpy",
    "ioctl_handler": "0x1200",
    "control_flow": "DispatchDeviceControl -> sub_1200 -> memcpy"
  }},
  "constraints": ["InputBufferLength must be > 0x100"],
  "mitigations": ["ProbeForRead called but may be insufficient"],
  "investigation_commands": [
    "objdump -d driver.sys | grep 222003",
    "nm driver.sys | grep memcpy"
  ],
  "reasoning": "The IOCTL handler at 0x1200 calls memcpy without validating the user-supplied size parameter, allowing a buffer overflow."
}}
```

Be precise and evidence-based in your classification."""

    @staticmethod
    def report_generation_prompt(
        driver_path: Path, vulnerability: dict[str, Any], audit_evidence: dict[str, Any]
    ) -> str:
        """
        Generate report creation prompt.

        Creates a comprehensive security report with:
        - Executive summary for management
        - Technical details with CVSS scoring
        - Proof of concept
        - Root cause analysis
        - Remediation guidance
        """

        driver_name = driver_path.name
        title = vulnerability.get("title", "Unknown")
        ioctl = vulnerability.get("eval", {}).get("IoControlCode", "unknown")

        return f"""# Technical Security Report Generation

Create a professional vulnerability report for audit documentation.

## Vulnerability Summary
- **Driver**: {driver_name}
- **Issue**: {title}
- **IOCTL**: {ioctl}
- **Classification**: TRUE_POSITIVE
- **Evidence**: {audit_evidence}

## Report Structure

### 1. Executive Summary (2-3 paragraphs)
Write for non-technical executives:
- What is the vulnerability in business terms?
- What is the potential impact to the organization?
- What actions should be taken immediately?
- Include a clear risk rating

### 2. Technical Analysis
#### CVSS v3.1 Scoring
Calculate the base score:
- **Attack Vector (AV)**: [Network/Adjacent/Local/Physical]
- **Attack Complexity (AC)**: [Low/High]
- **Privileges Required (PR)**: [None/Low/High]
- **User Interaction (UI)**: [None/Required]
- **Scope (S)**: [Unchanged/Changed]
- **Confidentiality Impact (C)**: [None/Low/High]
- **Integrity Impact (I)**: [None/Low/High]
- **Availability Impact (A)**: [None/Low/High]

#### CWE Classification
Identify the specific weakness:
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow
- CWE-476: NULL Pointer Dereference
- CWE-190: Integer Overflow
- CWE-416: Use After Free

### 3. Proof of Concept
```c
// Exploitation code structure
HANDLE hDevice = CreateFile(
    "\\\\\\\\.\\\\{driver_name}",
    GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, 0, NULL
);

// Trigger the vulnerability
BYTE exploit_buffer[0x1000];
// Fill with payload...
DeviceIoControl(
    hDevice,
    {ioctl},  // Vulnerable IOCTL
    exploit_buffer,
    sizeof(exploit_buffer),
    NULL, 0, NULL, NULL
);
```

### 4. Root Cause Analysis
Explain the programming error:
- Missing bounds checking
- Incorrect size calculation
- Unsafe memory operations
- Race condition
- Logic error

### 5. Remediation Plan
#### Immediate Fix
```c
// Add input validation
if (InputBufferLength > MAX_SAFE_SIZE) {{
    return STATUS_INVALID_BUFFER_SIZE;
}}

// Use safe functions
RtlCopyMemory(dest, src, min(size, MAX_SIZE));
```

#### Long-term Improvements
- Security development lifecycle integration
- Static analysis tooling (PREfast, CodeQL)
- Fuzzing with WDK tools
- Code review process

### 6. Testing & Verification
- Unit tests for boundary conditions
- Fuzzing with AFL/LibFuzzer
- Static analysis verification
- Penetration testing

## Output Requirements

Provide the complete report in Markdown format.

End with metadata:
```json
{{
  "metadata": {{
    "severity": "CRITICAL",
    "cvss_score": 8.8,
    "cwe_id": "CWE-121",
    "effort_to_fix": "LOW",
    "effort_to_exploit": "MEDIUM"
  }}
}}
```"""

    @staticmethod
    def quick_triage_prompt(driver_path: Path, ioctl: str) -> str:
        """
        Quick triage prompt for rapid classification.

        Used for fast initial assessment before deep analysis.
        """

        return f"""# Quick Vulnerability Triage

Perform a rapid assessment of a potential vulnerability.

## Target
- Driver: `{driver_path}`
- IOCTL: {ioctl}

## Quick Checks
```bash
# Check if driver exists
test -f {driver_path} && echo "EXISTS" || echo "NOT FOUND"

# Quick pattern matching
objdump -d {driver_path} | grep -c "{ioctl}"
objdump -d {driver_path} | grep -E "(memcpy|strcpy)" | head -5
```

## Rapid Classification
Based on initial indicators, classify as:
- LIKELY_TRUE: Strong indicators of vulnerability
- LIKELY_FALSE: Appears to be false positive
- REQUIRES_ANALYSIS: Needs deeper investigation

Output: {{"classification": "...", "reason": "..."}}"""

    @staticmethod
    def comparative_analysis_prompt(driver_path: Path, similar_vulns: list) -> str:
        """
        Comparative analysis prompt.

        Compares against known vulnerabilities for better classification.
        """

        return f"""# Comparative Vulnerability Analysis

Compare this potential vulnerability against known patterns.

## Target Driver
`{driver_path}`

## Known Similar Vulnerabilities
{similar_vulns}

## Analysis Tasks
1. Check if this matches known vulnerability patterns
2. Compare code structure with previously confirmed issues
3. Identify unique characteristics

## Questions to Answer
- Is this the same vulnerability type as known issues?
- Are the constraints similar or different?
- What makes this unique or common?

Output your comparative analysis with similarity scores."""
