"""Analysis result data models for IOCTLance."""

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .driver import DriverInfo, IOCTLHandler
from .vulnerability import Vulnerability


class PerformanceMetrics(BaseModel):
    """Performance metrics for analysis phases."""

    time: dict[str, int] = Field(default_factory=dict, description="Time in seconds per phase")
    memory: dict[str, int] = Field(default_factory=dict, description="Memory usage in KB per phase")
    unique_addr: dict[str, int] = Field(default_factory=dict, description="Unique addresses explored per phase")


class BasicInfo(BaseModel):
    """Basic analysis information."""

    path: str = Field(..., description="Path to analyzed driver")
    DeviceName: list[str] = Field(default_factory=list, description="Device names found")
    time: dict[str, int] = Field(default_factory=dict, description="Time metrics")
    memory: dict[str, int] = Field(default_factory=dict, description="Memory metrics")
    unique_addr: dict[str, int] = Field(default_factory=dict, description="Unique addresses explored")
    ioctl_handler: str = Field(..., description="IOCTL handler address")
    IoControlCodes: list[str] = Field(default_factory=list, description="Discovered IOCTL codes")


class AnalysisResult(BaseModel):
    """Complete analysis result for a driver."""

    basic: BasicInfo = Field(..., description="Basic analysis information")
    vuln: list[Vulnerability] = Field(default_factory=list, description="Discovered vulnerabilities")
    error: list[str] = Field(default_factory=list, description="Errors during analysis")

    # Additional fields for the refactored version
    driver_info: DriverInfo | None = Field(None, description="Driver information")
    ioctl_handler: IOCTLHandler | None = Field(None, description="IOCTL handler details")
    analysis_time: float | None = Field(None, description="Total analysis time in seconds")
    analysis_date: datetime = Field(default_factory=datetime.now, description="Analysis timestamp")
    ioctlance_version: str = Field(default="0.2.0", description="IOCTLance version used")

    @property
    def vulnerability_count(self) -> int:
        """Get total number of vulnerabilities found."""
        return len(self.vuln)

    @property
    def has_vulnerabilities(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.vuln) > 0

    @property
    def critical_vulnerabilities(self) -> list[Vulnerability]:
        """Get critical severity vulnerabilities."""
        return [v for v in self.vuln if v.severity == "CRITICAL"]

    @property
    def high_vulnerabilities(self) -> list[Vulnerability]:
        """Get high severity vulnerabilities."""
        return [v for v in self.vuln if v.severity == "HIGH"]

    def to_json_compatible(self) -> dict[str, Any]:
        """Convert to JSON-compatible dictionary matching original format."""
        return {
            "basic": self.basic.model_dump(),
            "vuln": [v.model_dump(exclude={"discovered_at"}) for v in self.vuln],
            "error": self.error,
        }

    @classmethod
    def from_legacy_format(cls, data: dict[str, Any]) -> "AnalysisResult":
        """Create AnalysisResult from legacy JSON format."""
        basic = BasicInfo(**data.get("basic", {}))

        vulnerabilities = []
        for vuln_data in data.get("vuln", []):
            vulnerabilities.append(Vulnerability(**vuln_data))

        return cls(basic=basic, vuln=vulnerabilities, error=data.get("error", []))

    def save_to_file(self, output_path: Path | str) -> None:
        """Save analysis result to JSON file."""
        import json

        path = Path(output_path) if isinstance(output_path, str) else output_path
        with open(path, "w") as f:
            json.dump(self.to_json_compatible(), f, indent=4)

    @classmethod
    def load_from_file(cls, file_path: Path | str) -> "AnalysisResult":
        """Load analysis result from JSON file."""
        import json

        path = Path(file_path) if isinstance(file_path, str) else file_path
        with open(path) as f:
            data = json.load(f)
        return cls.from_legacy_format(data)
