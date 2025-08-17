"""Driver data models for IOCTLance."""

from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class DriverInfo(BaseModel):
    """Represents a Windows driver to be analyzed."""

    path: Path = Field(..., description="Path to the driver file")
    name: str = Field(..., description="Driver name")
    type: str = Field(default="unknown", description="Driver type (wdm, wdf, etc.)")
    entry_point: int | None = Field(None, description="Driver entry point address")
    base_address: int | None = Field(None, description="Base load address")
    size: int | None = Field(None, description="Driver file size in bytes")
    device_names: list[str] = Field(default_factory=list, description="Device names exposed by driver")

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Validate driver path exists and is a .sys file."""
        if not v.exists():
            raise ValueError(f"Driver file does not exist: {v}")
        if v.suffix.lower() not in [".sys", ".dll"]:
            raise ValueError(f"Invalid driver file extension: {v.suffix}")
        return v

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate driver type."""
        valid_types = ["wdm", "wdf", "kmdf", "umdf", "unknown"]
        if v.lower() not in valid_types:
            raise ValueError(f"Invalid driver type: {v}. Must be one of {valid_types}")
        return v.lower()

    @classmethod
    def from_file(cls, file_path: Path | str) -> "DriverInfo":
        """Create DriverInfo from a file path."""
        path = Path(file_path) if isinstance(file_path, str) else file_path
        return cls(path=path, name=path.stem, size=path.stat().st_size if path.exists() else None)

    def __str__(self) -> str:
        """String representation."""
        return f"Driver({self.name}, type={self.type}, path={self.path})"


class IOCTLHandler(BaseModel):
    """Represents an IOCTL handler in a driver."""

    address: str = Field(..., description="Handler address in hex format")
    ioctl_codes: list[str] = Field(default_factory=list, description="Supported IOCTL codes")
    major_function: int = Field(14, description="IRP major function (14 for DEVICE_CONTROL)")

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        """Validate address format."""
        if not v.startswith("0x"):
            # Convert to hex format if needed
            try:
                addr = int(v, 16)
                return f"0x{addr:x}"
            except ValueError:
                raise ValueError("Address must be in hexadecimal format") from None
        return v

    @field_validator("ioctl_codes")
    @classmethod
    def validate_ioctl_codes(cls, v: list[str]) -> list[str]:
        """Validate IOCTL codes format."""
        validated = []
        for code in v:
            if not code.startswith("0x"):
                try:
                    # Try to convert to hex format
                    val = int(code, 16)
                    validated.append(f"0x{val:x}")
                except ValueError:
                    raise ValueError(f"Invalid IOCTL code format: {code}") from None
            else:
                validated.append(code)
        return validated
