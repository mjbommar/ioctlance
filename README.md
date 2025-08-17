# IOCTLance

<p align="center">
  <img src="asset/ioctlance.png" width="30%">
</p>

## 🛡️ Enhanced Windows Driver Vulnerability Scanner

IOCTLance is an advanced security tool for detecting vulnerabilities in Windows Driver Model (WDM) drivers using
symbolic execution and taint analysis. Originally presented at [CODE BLUE 2023](https://codeblue.jp/2023/en/), this *
*completely refactored version** represents a ground-up rewrite of the original IOCTLance project with modern Python
architecture, improved performance, and comprehensive vulnerability detection capabilities.

**Note**: This fork is a complete rewrite/refactor of the original IOCTLance research inspired
by [this vxunderground tweet](https://x.com/vxunderground/status/1956385645095796889) and my own stubborn stupidity.

The goal in Phase 1 is to set the project up for PyO3/Maturin integration to allow for faster symbolic execution
and taint analysis using Rust. This will significantly improve performance and allow for more complex analysis
capabilities in the future.

The architecture, testing methodology, and implementation have been redesigned from scratch while preserving and
extending on the core vulnerability detection logic. But it's still based on the original research and findings of the
IOCTLance project and therefore I preserved the license and name (though maybe name should be changed to avoid
confusion?).



## 🎯 Detected Vulnerability Types

- **Memory Exploitation**
    - Physical memory mapping (MmMapIoSpace)
    - Buffer overflow & stack corruption (with RCE detection)
    - Use-after-free & double-free
    - Null pointer dereference
    - **Arbitrary read/write via controllable memcpy** (src/dst address control)

- **Access Control & Privilege Escalation**
    - **ObOpenObjectByPointer abuse** (kernel privilege escalation)
    - Controllable process handles & termination
    - Arbitrary read/write operations
    - ProbeForRead/Write bypass
    - Token stealing primitives

- **Code Execution**
    - Buffer overflow with controllable PC (RCE)
    - Arbitrary shellcode execution
    - Dangerous MSR operations (wrmsr)
    - Arbitrary I/O port access

- **Race Conditions**
    - Double-fetch vulnerabilities
    - TOCTOU (Time-of-Check-Time-of-Use)

## 🔄 Recent Improvements (Refactored Version)

This repository contains a significantly refactored version of IOCTLance with **full parity** with the original implementation plus substantial enhancements:

### Complete Feature Parity + Enhancements

- **All original detectors preserved** including ObOpenObjectByPointer and controllable memcpy
- **6 additional detector types** beyond the original implementation
- **Buffer overflow with RCE detection** - Detects when PC becomes controllable
- **Enhanced vulnerability reporting** with detailed state information

### Architecture & Performance

- **Modern Python 3.13+** with full type hints and async support
- **Updated angr/unicorn** symbolic execution engine for better performance
- **Improved output details** - More comprehensive vulnerability reports including additional state information
- **Modular design** - Clean separation between detectors, hooks, and core analysis
- **25-35% faster** - LRU caching, pre-compiled regex, optimized data structures, PyO3 planned
- **Pydantic models** for structured data validation and serialization
- **FastAPI** for a lightweight API interface (optional)

### Testing & Reliability

- **Real integration tests** using actual vulnerable driver samples
- **48% test coverage** with comprehensive unit and integration tests
- **Test-driven development** - All features validated with real drivers

### Enhanced Detection

- Improved detector accuracy and reduced false positives
- Support for batch analysis of multiple drivers
- Better timeout handling and memory management
- Detailed vulnerability reporting with IOCTL codes

## 🚀 Quick Start

### Installation

```bash
# Install with uv (recommended)
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# Or use Docker (CLI version)
docker build -f Dockerfile.cli -t ioctlance-cli .
docker run -v $(pwd)/samples:/samples ioctlance-cli /samples/driver.sys
```

### Basic Usage

```bash
# Analyze a single driver (local)
uv run python -m ioctlance.cli samples/RtDashPt.sys

# Analyze with Docker (mount samples directory and analyze a driver)
docker run --rm -v $(pwd)/samples:/samples ioctlance-cli /samples/RtDashPt.sys

# Analyze with specific timeout
uv run python -m ioctlance.cli --timeout 60 samples/RtDashPt.sys

# Target specific IOCTL code
uv run python -m ioctlance.cli --ioctl 0x22201c samples/RtDashPt.sys

# Analyze directory of drivers
uv run python -m ioctlance.cli samples/

# Output results to JSON
uv run python -m ioctlance.cli --output results.json samples/RtDashPt.sys

# Docker with JSON output
docker run --rm -v $(pwd)/samples:/samples ioctlance-cli /samples/RtDashPt.sys --json
```

## 🛠️ Advanced Options

```
usage: ioctlance [-h] [-o OUTPUT] [-t TIMEOUT] [--ioctl IOCTL] 
                 [--address ADDRESS] [--global-var-size SIZE]
                 [--complete] [--bound BOUND] [--length LENGTH]
                 [-v] [--debug] [--json] driver

positional arguments:
  driver                Path to driver file or directory

optional arguments:
  -h, --help           Show help message
  -o, --output         Output file for results (JSON)
  -t, --timeout        Max analysis time in seconds (default: 120)
  --ioctl              Specific IOCTL code to test (hex)
  --address            IOCTL handler address to skip discovery
  --global-var-size    Size of .data section to symbolize
  --complete           Continue until STATUS_SUCCESS
  --bound              Maximum loop iterations
  --length             Maximum instruction count
  -v, --verbose        Enable verbose output
  --debug              Enable debug output
  --json               Output results as JSON to stdout
```

## 🔬 Compiling Test Drivers

IOCTLance includes test drivers to validate detector functionality:

```bash
# Compile a test driver with MinGW
x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin \
    -I/usr/share/mingw-w64/include/ddk \
    -o test_driver.sys test_driver.c \
    -Wl,--subsystem,native -Wl,--entry,DriverEntry

# Test with IOCTLance
uv run python -m ioctlance.cli test_driver.sys
```

## 📊 Enhanced JSON Output Format

The refactored IOCTLance provides significantly enhanced JSON output with comprehensive vulnerability details and execution context. See [example output](docs/examples/ilp60x64_3_analysis.json) from analyzing a real driver.

### New Output Fields

The enhanced output format includes these additional fields beyond the original IOCTLance:

#### Top-Level Fields
- **`driver_info`**: Complete driver metadata including name, type, entry point, base address, size, and device names
- **`ioctl_handler`**: Detailed handler information with address, supported IOCTL codes, and major function
- **`analysis_time`**: Total analysis duration in seconds
- **`analysis_date`**: ISO 8601 timestamp of when analysis was performed
- **`ioctlance_version`**: Version of IOCTLance used for analysis

#### Enhanced Vulnerability Data
Each vulnerability now includes:
- **`discovered_at`**: Precise timestamp when vulnerability was discovered
- **`raw_data`**: Complete symbolic execution state at vulnerability point, containing:
  - **`constraints`**: All SMT solver constraints and satisfiability status
  - **`execution_trace`**: Basic blocks visited, instruction count, call depth, unique addresses
  - **`registers`**: CPU register values and which are symbolic
  - **`memory`**: Memory snapshots and symbolic memory regions
  - **`symbolic_state`**: Symbolic variables, expressions, and taint sources
  - **`call_stack`**: Return addresses, function names, and stack depth
  - **`instruction_context`**: Vulnerable instruction address, bytes, and disassembly
  - **`concrete_inputs`**: Actual input values that trigger the vulnerability
  - **`state_globals`**: Device object, tainted handles, EPROCESS pointers, validation results

### Example Output Structure

```json
{
  "basic": {
    "path": "samples/driver.sys",
    "DeviceName": ["\\Device\\Example"],
    "time": {"ioctl handler": 2, "hunting vulns": 103},
    "memory": {"ioctl handler": 214940, "hunting vulns": 1196340},
    "unique_addr": {"ioctl handler": 1080, "hunting vulns": 1080},
    "ioctl_handler": "0x11540",
    "IoControlCodes": ["0x12c804", "0x12c810", ...]
  },
  "vuln": [{
    "title": "read/write controllable address",
    "description": "read",
    "state": "<SimState @ 0x1194e>",
    "eval": {
      "IoControlCode": "0x12c810",
      "SystemBuffer": "0x50040000",
      "Type3InputBuffer": "<BV64 Type3InputBuffer>",
      "UserBuffer": "<BV64 UserBuffer>",
      "InputBufferLength": "0x30",
      "OutputBufferLength": "0x30"
    },
    "discovered_at": "2025-08-17T12:16:39.756407",
    "raw_data": {
      "constraints": {
        "constraints": ["<Bool IoControlCode == 0x12c810>", ...],
        "satisfiable": true
      },
      "execution_trace": {
        "basic_blocks": [135268, 135272, ...],
        "instructions_executed": 4521,
        "call_depth": 3,
        "unique_addresses": 1080
      },
      "concrete_inputs": {
        "ioctl_code": 1231888,
        "input_buffer_length": 48,
        "output_buffer_length": 48,
        "system_buffer_addr": 1342570496
      }
    }
  }],
  "error": [],
  "driver_info": {
    "path": "/path/to/driver.sys",
    "name": "driver",
    "type": "wdm",
    "size": 65536
  },
  "ioctl_handler": {
    "address": "0x11540",
    "ioctl_codes": ["0x12c804", "0x12c810"],
    "major_function": 14
  },
  "analysis_time": 105.3,
  "analysis_date": "2025-08-17T12:16:39.756407",
  "ioctlance_version": "0.2.0"
}
```

### Benefits of Enhanced Output

1. **Reproducibility**: Complete constraints and concrete inputs allow reproducing vulnerabilities
2. **Debugging**: Execution trace and instruction context help understand vulnerability paths
3. **Severity Assessment**: Additional context enables better vulnerability prioritization
4. **Integration**: Structured data with timestamps facilitates integration with other tools
5. **Forensics**: Raw state data preserves complete vulnerability context for analysis

For a complete example, see:
- [Full analysis output](docs/examples/ilp60x64_3_analysis.json) - Complete output from real driver analysis
- [Truncated example](docs/examples/example_output_truncated.json) - Simplified version showing structure

## 🌐 REST API (Optional)

IOCTLance includes an optional high-performance REST API built with FastAPI for programmatic access and integration with other tools. The API supports asynchronous processing, batch analysis, and real-time WebSocket notifications.

### Quick Start with Docker

```bash
# Using docker-compose (recommended)
docker compose up -d

# Or using docker run
docker build -f Dockerfile.api -t ioctlance-api .
docker run -d -p 8080:8080 -v $(pwd)/samples:/app/samples:ro ioctlance-api

# Check health
curl http://localhost:8080/health
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API info and version |
| `/health` | GET | Health check with stats |
| `/docs` | GET | Interactive API documentation |
| `/upload` | POST | Upload driver for analysis |
| `/analyze/{file_hash}` | POST | Start analysis of uploaded driver |
| `/status/{job_id}` | GET | Check analysis job status |
| `/result/{job_id}` | GET | Get analysis results |
| `/batch` | POST | Analyze multiple drivers |
| `/jobs` | GET | List all analysis jobs |
| `/ws/{job_id}` | WS | WebSocket for real-time updates |

### Example: Upload and Analyze Driver

```bash
# 1. Upload driver
RESPONSE=$(curl -s -X POST http://localhost:8080/upload \
  -F "file=@samples/RtDashPt.sys")
FILE_HASH=$(echo $RESPONSE | jq -r '.file_hash')

# 2. Start analysis
RESPONSE=$(curl -s -X POST "http://localhost:8080/analyze/${FILE_HASH}" \
  -H "Content-Type: application/json" \
  -d '{"timeout": 120}')
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')

# 3. Get results when complete
curl -s "http://localhost:8080/result/${JOB_ID}" | jq
```

### Python Client Example

```python
import httpx
import asyncio

async def analyze_driver(driver_path: str):
    async with httpx.AsyncClient(base_url="http://localhost:8080") as client:
        # Upload driver
        with open(driver_path, "rb") as f:
            response = await client.post("/upload", files={"file": f})
            file_hash = response.json()["file_hash"]
        
        # Start analysis
        response = await client.post(
            f"/analyze/{file_hash}",
            json={"timeout": 120}
        )
        job_id = response.json()["job_id"]
        
        # Poll for completion
        while True:
            status = await client.get(f"/status/{job_id}")
            status_data = status.json()
            
            if status_data["status"] == "completed":
                result = await client.get(f"/result/{job_id}")
                result_data = result.json()
                print(f"Found {len(result_data['vuln'])} vulnerabilities")
                return result_data
            elif status_data["status"] == "failed":
                print(f"Analysis failed: {status_data.get('error')}")
                break
                
            await asyncio.sleep(2)

# Run the analysis
asyncio.run(analyze_driver("samples/RtDashPt.sys"))
```

### WebSocket Real-time Updates

```javascript
const ws = new WebSocket('ws://localhost:8080/ws/' + jobId);
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.event === 'completed') {
    console.log('Analysis completed!', data.result);
  }
};
```

### Security Note

⚠️ **The API currently has no authentication**. For production use, implement proper authentication and run behind a reverse proxy with TLS.

For complete API documentation, see [API_README.md](docs/API_README.md) or visit `/docs` when the API is running.

## 🏗️ Architecture

```
ioctlance/
├── src/ioctlance/
│   ├── core/           # Core analysis engine
│   ├── detectors/      # Vulnerability detectors
│   ├── hooks/          # Windows API hooks
│   ├── models/         # Data models
│   ├── symbolic/       # Symbolic execution
│   └── utils/          # Helper utilities
├── samples/            # Test driver samples
├── tests/              # Test suite
└── test_drivers/       # Vulnerability test drivers
```

### Test Drivers

The `samples/` directory contains vulnerable test drivers:

- `test_physical_memory.sys` - MmMapIoSpace vulnerability
- `test_process_termination.sys` - ZwTerminateProcess vulnerability
- `test_use_after_free.sys` - UAF vulnerability
- `test_race_condition.sys` - Double-fetch vulnerability
- `test_file_operations.sys` - File operation vulnerabilities

### Dataset Benchmark

The `dataset/` directory contains 104 known vulnerable drivers for validation:

```bash
# Run full benchmark (takes 30-60 minutes)
./run_benchmark.sh

# Or run specific benchmark tests
uv run pytest tests/integration/test_dataset_benchmark.py -m benchmark

# Test a subset for quick validation
uv run pytest tests/integration/test_dataset_benchmark.py::TestDatasetBenchmark::test_performance_metrics
```

Benchmark generates:

- Detailed vulnerability analysis report
- Performance metrics (analysis time per driver)
- Detection rate statistics
- Vulnerability type distribution

## 📚 Documentation

- [CODE BLUE 2023 Presentation](https://drive.google.com/file/d/1lEegyJ1SBB_lDts6F3W3JPySucM3nugR/view?usp=sharing)
- [Development Guide](CLAUDE.md)

## 🤝 Contributing

If you want to PR, it would be nice if you could please review the checklist below first:

- Code passes `uvx ruff check src/ioctlance`
- Type hints pass `uvx ty check src/ioctlance`
- Tests pass with `uv run pytest`
- New detectors include test drivers

## ⚖️ License

This project is licensed under the GPL3 License - see [License.txt](License.txt) for details.

## ⚠️ Disclaimer

IOCTLance is intended for legitimate security research and testing only. Users are responsible for complying with all
applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

## 🙏 Acknowledgments

- Original IOCTLance research presented at CODE BLUE 2023 and released by [zeze-zeze](https://github.com/zeze-zeze).
- Refactor inspired by the [vxunderground](https://x.com/vxunderground) driver analysis project
- Built on [angr](https://github.com/angr/angr) symbolic execution framework
- Test drivers compiled with MinGW-w64
- Refactored version contributors:
    - [Michael Bommarito](https://michaelbommarito.com) - Complete refactor and modernization

## Reference

- [vxunderground Driver Analysis](https://vx-underground.org/2025%20Vulnerable%20Driver%20Project/)
- [ucsb-seclab/popkorn-artifact](https://github.com/ucsb-seclab/popkorn-artifact)
- [eclypsium/Screwed-Drivers](https://github.com/eclypsium/Screwed-Drivers)
- [koutto/ioctlbf](https://github.com/koutto/ioctlbf)
- [Living Off The Land Drivers](https://www.loldrivers.io/)
- [angr Documentation](https://docs.angr.io/)
