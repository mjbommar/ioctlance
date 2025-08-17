# IOCTLance Development Guide

## Core Principles

**THIS IS PRODUCTION** - This tool is used by security researchers to find real vulnerabilities. False positives waste time. False negatives miss critical issues. Your code has real impact.

## Development Workflow

### 1. Research Before Coding
```bash
# Always understand the data models and APIs first
uv run python -c "import angr; help(angr.SimState)"
uv run python -c "from module import Class; print(dir(Class))"

# Search the web for documentation when needed
# Never guess or make up APIs - verify everything
```

### 2. Test-Driven Development
```bash
# Write integration tests FIRST that are expected to fail
uv run pytest tests/integration/test_new_feature.py -xvs

# Use real driver samples - NEVER mock
uv run python -m ioctlance.cli samples/RtDashPt.sys --timeout 10
```

### 3. Code Quality Checks (REQUIRED)
```bash
# Run these before EVERY commit
uvx ruff check src/ioctlance
uvx mypy src/ioctlance  # Currently shows warnings - fix if possible
uv run pytest tests/

# Never say "done" without running these checks
```

## Testing Philosophy

1. **NO MOCKS** - Use real driver samples from `samples/` directory
2. **Integration > Unit** - Test actual functionality, not isolated components
3. **Real samples** - Every detector must have a corresponding test driver
4. **Validate with pytest** - All tests must pass with `uv run pytest`

### Creating Test Drivers
```bash
# Compile Windows drivers with MinGW-w64
x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin \
    -I/usr/share/mingw-w64/include/ddk \
    -o test_driver.sys test_driver.c \
    -Wl,--subsystem,native -Wl,--entry,DriverEntry

# Test immediately
uv run python -m ioctlance.cli test_driver.sys --timeout 30
```

## Code Style Guidelines

### Type Hints (Required)
```python
from typing import Optional, List, Dict, Any
from pathlib import Path

def analyze_driver(
    driver_path: Path,
    timeout: Optional[int] = 120
) -> Dict[str, Any]:
    """Always use type hints for function signatures."""
    pass
```

### Data Models (Pydantic)
```python
from pydantic import BaseModel, Field, field_validator

class AnalysisResult(BaseModel):
    """Use Pydantic for all data structures."""
    path: Path
    vulnerabilities: List[str] = Field(default_factory=list)
    
    @field_validator('path')
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        if not v.suffix == '.sys':
            raise ValueError('Must be a .sys file')
        return v
```

### Error Handling
```python
# Be explicit about error conditions
if symbolic_var is not None:  # NOT: if symbolic_var:
    process_variable(symbolic_var)

# Use proper exception handling
try:
    result = analyze_driver(path)
except Exception as e:
    logger.error(f"Analysis failed: {e}")
    # Don't hide errors - surface them appropriately
```

## Architecture Patterns

### 1. Separation of Concerns
- `core/` - Analysis orchestration
- `detectors/` - Vulnerability detection logic
- `hooks/` - API interception
- `models/` - Data structures
- `utils/` - Helper functions

### 2. Plugin Architecture
```python
from abc import ABC, abstractmethod

class BaseDetector(ABC):
    """All detectors inherit from base class."""
    
    @abstractmethod
    def detect(self, state: SimState) -> Optional[Vulnerability]:
        """Must implement detection logic."""
        pass
```

### 3. Context Management
```python
from contextlib import contextmanager

@contextmanager
def analysis_context(driver_path: Path):
    ctx = create_context(driver_path)
    try:
        yield ctx
    finally:
        ctx.cleanup()
```

## Performance Optimization

```python
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_operation(param: str) -> Any:
    """Cache frequently called functions."""
    pass

# Exit early when possible
if not should_continue:
    return early_result
```

## Docker Guidelines

### CLI Container
```dockerfile
ENTRYPOINT ["uv", "run", "python", "-m", "ioctlance.cli"]
CMD ["--help"]  # Default args, replaced by user input
```

### API Container
```dockerfile
EXPOSE 8080
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health
CMD ["uv", "run", "uvicorn", "ioctlance.api.app:app", "--host", "0.0.0.0"]
```

## Git Workflow

```bash
# Commit format: type: Brief description (under 50 chars)
# Types: feat, fix, docs, test, refactor, perf, chore
git commit -m "fix: Handle symbolic values in state comparison"

# Pre-commit checks
uvx ruff check src/ioctlance && uv run pytest tests/unit/
```

## Debugging & Documentation

```bash
# Quick introspection
uv run python -c "import module; print(module.__file__)"

# Interactive debugging
uv run python -m ipdb src/ioctlance/cli.py samples/driver.sys

# State inspection
uv run python -c "from ioctlance.core import analyze; print(analyze('driver.sys', debug=True).solver.constraints)"
```

**Documentation**: Docstrings required, type hints mandatory, comments only for non-obvious logic.

## Security & Final Notes

- Never log sensitive data or paths with usernames
- Validate all inputs, use Path objects for files
- Set timeouts for symbolic execution
- Handle symbolic/tainted data carefully

**Remember**: Research first, test with real data, check your work, performance matters, security is critical.