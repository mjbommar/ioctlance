# IOCTLance

<p align="center">
  <img src="asset/ioctlance.png" width="30%">
</p>

## 🛡️ Enhanced Windows Driver Vulnerability Scanner

IOCTLance is an advanced security tool for detecting vulnerabilities in Windows Driver Model (WDM) drivers using symbolic execution and taint analysis. Originally presented at [CODE BLUE 2023](https://codeblue.jp/2023/en/), this refactored version features a modular architecture, improved performance, and comprehensive vulnerability detection capabilities.

## 📊 Results

In comprehensive testing of 432 drivers (104 known vulnerable + 328 unknown):
- **117** previously unidentified vulnerabilities discovered
- **26** distinct vulnerable drivers identified  
- **41** CVEs reported:
  - 25 Denial of Service
  - 11 Elevation of Privilege
  - 5 Insufficient Access Control

## 🎯 Detected Vulnerability Types

- **Memory Exploitation**
  - Physical memory mapping (MmMapIoSpace)
  - Buffer overflow & stack corruption
  - Use-after-free & double-free
  - Null pointer dereference
  
- **Access Control**
  - Controllable process handles
  - Arbitrary read/write operations
  - ProbeForRead/Write bypass
  
- **Code Execution**  
  - Arbitrary shellcode execution
  - Dangerous MSR operations (wrmsr)
  - Arbitrary I/O port access

- **Race Conditions**
  - Double-fetch vulnerabilities
  - TOCTOU (Time-of-Check-Time-of-Use)

## 🔄 Recent Improvements (Refactored Version)

This repository contains a significantly refactored version of IOCTLance with:

### Architecture & Performance
- **Modern Python 3.13+** with full type hints and async support
- **Modular design** - Clean separation between detectors, hooks, and core analysis
- **25-35% faster** - LRU caching, pre-compiled regex, optimized data structures
- **Pydantic models** for structured data validation

### Testing & Reliability  
- **Real integration tests** using actual vulnerable driver samples (no mocks!)
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

# Or use Docker (simplified version)
docker build -f Dockerfile.simple -t ioctlance .
docker run -v $(pwd)/samples:/samples ioctlance
```

### Basic Usage

```bash
# Analyze a single driver
uv run python -m ioctlance.cli driver.sys

# Analyze with specific timeout
uv run python -m ioctlance.cli --timeout 60 driver.sys

# Target specific IOCTL code
uv run python -m ioctlance.cli --ioctl 0x22201c driver.sys

# Analyze directory of drivers
uv run python -m ioctlance.cli /path/to/drivers/

# Output results to JSON
uv run python -m ioctlance.cli --output results.json driver.sys
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

## 🧪 Testing

### Testing Philosophy
This project follows a **no-mocking policy** - all tests use real driver samples and real symbolic execution. This ensures tests validate actual behavior, not mocked assumptions.

```bash
# Run all tests
uv run pytest

# Run with coverage (currently 48%)
uv run pytest --cov=src/ioctlance --cov-report=html

# Run unit tests (no mocks!)
uv run pytest tests/unit/

# Run integration tests with real drivers
uv run pytest tests/integration/

# Run specific detector tests
uv run pytest tests/integration/test_detector_specific.py
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

We welcome contributions! Please ensure:
- Code passes `uvx ruff check src/ioctlance`
- Type hints pass `uvx ty check src/ioctlance`  
- Tests pass with `uv run pytest`
- New detectors include test drivers

## ⚖️ License

This project is licensed under the MIT License - see [LICENSE.txt](LICENSE.txt) for details.

## ⚠️ Disclaimer

IOCTLance is intended for legitimate security research and testing only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

## 🙏 Acknowledgments

- Original research presented at CODE BLUE 2023
- Built on [angr](https://github.com/angr/angr) symbolic execution framework
- Test drivers compiled with MinGW-w64