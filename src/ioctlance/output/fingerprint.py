"""Driver fingerprinting and identification."""

import hashlib
from pathlib import Path
from typing import Any
from datetime import datetime

from pydantic import BaseModel, Field


class DriverFingerprint(BaseModel):
    """Complete driver fingerprint for identification and tracking."""

    # File hashes
    blake2b: str = Field(..., description="BLAKE2b hash of the driver")
    sha256: str = Field(..., description="SHA256 hash of the driver")
    sha1: str = Field(..., description="SHA1 hash of the driver")
    md5: str = Field(..., description="MD5 hash of the driver")

    # File metadata
    file_path: str = Field(..., description="Original file path")
    file_name: str = Field(..., description="File name")
    file_size: int = Field(..., description="File size in bytes")

    # PE metadata
    imphash: str | None = Field(None, description="Import hash")
    compilation_timestamp: int | None = Field(None, description="PE compilation timestamp")
    compilation_date: str | None = Field(None, description="Human-readable compilation date")

    # Version info
    file_version: str | None = Field(None, description="File version from resources")
    product_version: str | None = Field(None, description="Product version from resources")
    company_name: str | None = Field(None, description="Company name from resources")
    product_name: str | None = Field(None, description="Product name from resources")
    original_filename: str | None = Field(None, description="Original filename from resources")

    # Fingerprint metadata
    fingerprinted_at: datetime = Field(default_factory=datetime.now, description="When fingerprint was created")

    @classmethod
    def from_file(cls, driver_path: Path) -> "DriverFingerprint":
        """Create fingerprint from driver file.

        Args:
            driver_path: Path to driver file

        Returns:
            DriverFingerprint instance
        """
        # Read file content
        with open(driver_path, "rb") as f:
            content = f.read()

        # Calculate hashes
        blake2b_hash = hashlib.blake2b(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        md5_hash = hashlib.md5(content).hexdigest()

        fingerprint = cls(
            blake2b=blake2b_hash,
            sha256=sha256_hash,
            sha1=sha1_hash,
            md5=md5_hash,
            file_path=str(driver_path.absolute()),
            file_name=driver_path.name,
            file_size=driver_path.stat().st_size,
        )

        # Try to extract PE metadata
        try:
            import pefile

            pe = pefile.PE(str(driver_path))

            # Import hash
            if hasattr(pe, "get_imphash"):
                fingerprint.imphash = pe.get_imphash()

            # Compilation timestamp
            if hasattr(pe, "FILE_HEADER") and hasattr(pe.FILE_HEADER, "TimeDateStamp"):
                fingerprint.compilation_timestamp = pe.FILE_HEADER.TimeDateStamp
                try:
                    from datetime import datetime

                    fingerprint.compilation_date = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
                except:
                    pass

            # Version info
            if hasattr(pe, "VS_VERSIONINFO"):
                for fileinfo in pe.VS_VERSIONINFO:
                    if hasattr(fileinfo, "StringFileInfo"):
                        for st in fileinfo.StringFileInfo:
                            for entry in st.entries.values():
                                if "FileVersion" in entry:
                                    fingerprint.file_version = entry["FileVersion"]
                                if "ProductVersion" in entry:
                                    fingerprint.product_version = entry["ProductVersion"]
                                if "CompanyName" in entry:
                                    fingerprint.company_name = entry["CompanyName"]
                                if "ProductName" in entry:
                                    fingerprint.product_name = entry["ProductName"]
                                if "OriginalFilename" in entry:
                                    fingerprint.original_filename = entry["OriginalFilename"]

            pe.close()
        except:
            # PE parsing failed, but we still have hashes
            pass

        return fingerprint

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = self.model_dump()
        # Convert datetime to ISO format
        data["fingerprinted_at"] = self.fingerprinted_at.isoformat()
        return data
