# IOCTLance Audit Module

Automated vulnerability auditing system powered by Claude Code CLI for Windows driver security analysis.

## Architecture

```
audit/
├── __init__.py           # Module exports
├── auditor.py            # Core VulnerabilityAuditor class
├── batch_auditor.py      # Batch processing for multiple vulnerabilities
├── report_generator.py   # Technical report generation
└── templates.py          # Claude Code prompt templates
```

## Components

### VulnerabilityAuditor

The core auditor that analyzes individual vulnerabilities:

```python
from ioctlance.audit import VulnerabilityAuditor

auditor = VulnerabilityAuditor(claude_command="claude", verbose=True)
result = auditor.audit(
    driver_path=Path("driver.sys"),
    vulnerability=vuln_dict,
    timeout=300
)

print(f"Classification: {result.classification}")
print(f"Confidence: {result.confidence}%")
```

**Features:**
- Binary analysis with objdump/nm/strings
- Static analysis with IOCTLance Python API
- Evidence-based classification
- Detailed reasoning and constraints

### BatchAuditor 

Processes multiple vulnerabilities from batch results:

```python
from ioctlance.audit import BatchAuditor, BatchAuditConfig

config = BatchAuditConfig(
    parallel_workers=4,
    filter_severity="HIGH",
    skip_likely_false_positives=True
)

auditor = BatchAuditor(config)
summary = auditor.audit_batch_results(
    Path("batch_results.jsonl"),
    Path("summary.json")
)
```

**Features:**
- Parallel/sequential processing
- Filtering by severity and type
- False positive detection
- Progress tracking with Rich

### ReportGenerator

Creates professional security reports:

```python
from ioctlance.audit import ReportGenerator

generator = ReportGenerator()
report = generator.generate_report(
    driver_path=Path("driver.sys"),
    vulnerability=vuln_dict,
    audit_result=audit_result
)

generator.save_report(report, Path("report.md"), format="markdown")
```

**Features:**
- Executive summaries
- CVSS scoring
- CWE classification  
- Proof of concept
- Remediation guidance

## How Auditing Works

### 1. Investigation Phase

The auditor uses Claude Code to:

1. **Verify the driver exists**
   ```bash
   file driver.sys
   ls -la driver.sys
   ```

2. **Analyze the IOCTL handler**
   ```bash
   objdump -d driver.sys | grep "0x222003"
   nm driver.sys | grep memcpy
   strings driver.sys | grep check
   ```

3. **Re-analyze with IOCTLance**
   ```python
   from ioctlance.core import analyze_driver
   result = analyze_driver("driver.sys", timeout=60)
   ```

### 2. Classification Logic

Vulnerabilities are classified as:

- **TRUE_POSITIVE**: 
  - User input reaches dangerous functions
  - No validation prevents exploitation
  - Can lead to code execution/privilege escalation
  
- **FALSE_POSITIVE**:
  - NULL pointer dereference (not buffer overflow)
  - Input validation prevents exploitation
  - Unreachable from user mode
  
- **NEEDS_REVIEW**:
  - Complex constraints need manual analysis
  - Partial mitigations might be bypassable
  - Insufficient information

### 3. False Positive Detection

Common patterns detected:

```python
# NULL pointer misclassified as buffer overflow
if vuln['eval']['SystemBuffer'] == '0x0':
    return FALSE_POSITIVE

# Unconstrained state with NULL description
if 'unconstrained_state' in vuln['type'] and 'NULL' in vuln['description']:
    return FALSE_POSITIVE
```

## Prompt Templates

The `templates.py` module provides specialized prompts:

### Investigation Prompt
Guides Claude through binary analysis, static analysis, and classification.

### Report Generation Prompt  
Creates comprehensive security reports with CVSS scores and remediation.

### Quick Triage Prompt
Rapid assessment for initial filtering.

### Comparative Analysis Prompt
Compares against known vulnerability patterns.

## CLI Integration

The module includes `cli_audit.py` for command-line usage:

```bash
# Single vulnerability
ioctlance-audit single driver.sys '{"title":"Buffer Overflow"}'

# Batch processing
ioctlance-audit batch results.jsonl -o summary.json

# With filtering
ioctlance-audit batch results.jsonl --filter-severity CRITICAL
```

## Data Models

### AuditResult

```python
class AuditResult(BaseModel):
    classification: AuditClassification
    confidence: int  # 0-100
    evidence: Dict[str, Any]
    reasoning: str
    investigation_commands: List[str]
    vulnerable_address: Optional[str]
    constraints: List[str]
    mitigations: List[str]
```

### BatchAuditSummary

```python
class BatchAuditSummary(BaseModel):
    timestamp: datetime
    total_vulnerabilities: int
    total_audited: int
    classifications: Dict[str, int]
    results: List[Dict[str, Any]]
```

### TechnicalReport

```python
class TechnicalReport(BaseModel):
    title: str
    driver_name: str
    vulnerability_type: str
    generated_at: datetime
    executive_summary: str
    technical_details: str
    proof_of_concept: str
    root_cause_analysis: str
    remediation: str
    references: str
    metadata: ReportMetadata
    audit_result: AuditResult
```

## Configuration

### BatchAuditConfig Options

- `parallel_workers`: Number of parallel audit workers (1-10)
- `timeout_per_audit`: Timeout in seconds per audit (60-1800) 
- `filter_severity`: Minimum severity level to audit
- `filter_type`: Specific vulnerability type to audit
- `skip_likely_false_positives`: Filter common false positives
- `audit_limit`: Maximum vulnerabilities to audit
- `verbose`: Enable verbose output

## Performance

- **Sequential**: ~30-60 seconds per vulnerability
- **Parallel (4 workers)**: ~4x speedup for large batches
- **Timeout handling**: Graceful handling of complex drivers

## Error Handling

The system handles:
- Claude Code timeouts
- Malformed JSON responses
- Missing driver files
- Parse errors with fallback classification

## Testing

Comprehensive test coverage in `tests/test_audit.py`:

```bash
# Run all audit tests
uv run pytest tests/test_audit.py -v

# Run specific test class
uv run pytest tests/test_audit.py::TestVulnerabilityAuditor -v
```

## Future Enhancements

- [ ] Machine learning for pattern recognition
- [ ] Integration with CVE databases
- [ ] Automated patch generation
- [ ] Cloud-based audit orchestration
- [ ] Real-time monitoring integration

## Dependencies

- Claude Code CLI (npm package)
- Python 3.13+
- Pydantic for data validation
- Rich for terminal UI
- Standard binary analysis tools (objdump, nm, strings)