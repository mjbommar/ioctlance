"""Binary metadata models for comprehensive driver analysis."""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class DataDirectory(BaseModel):
    """PE Data Directory entry."""

    name: str
    rva: int = 0
    size: int = 0


class Section(BaseModel):
    """PE Section information."""

    name: str
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    characteristics: int = 0
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = False


class ImportedFunction(BaseModel):
    """Imported function with full metadata."""

    name: str
    short_name: str
    library: str
    data: int | None = None
    iat_value: int | None = None
    hint: int | None = None
    ordinal: int | None = None
    is_ordinal: bool = False


class ExportedFunction(BaseModel):
    """Exported function metadata."""

    name: str
    ordinal: int
    rva: int = 0
    forwarder: str | None = None
    is_forwarded: bool = False


class Resource(BaseModel):
    """Resource entry metadata."""

    type: str
    name: str | None = None
    language: str | None = None
    size: int = 0
    entropy: float | None = None


class Certificate(BaseModel):
    """Digital certificate metadata."""

    subject: str
    issuer: str
    serial_number: str
    not_before: str | None = None
    not_after: str | None = None
    signature_algorithm: str | None = None
    is_valid: bool = False
    is_trusted: bool = False


class VersionInfo(BaseModel):
    """Version information from resources."""

    file_version: str | None = None
    product_version: str | None = None
    company_name: str | None = None
    file_description: str | None = None
    internal_name: str | None = None
    original_filename: str | None = None
    product_name: str | None = None
    legal_copyright: str | None = None
    comments: str | None = None


class RichHeader(BaseModel):
    """Rich header metadata (compiler information)."""

    compiler_id: int | None = None
    compiler_version: str | None = None
    product_id: int | None = None
    product_version: str | None = None
    entries: list[dict[str, Any]] = Field(default_factory=list)


class DebugInfo(BaseModel):
    """Debug information metadata."""

    has_debug: bool = False
    pdb_filename: str | None = None
    pdb_guid: str | None = None
    pdb_age: int | None = None
    debug_type: str | None = None


class DotNetMetadata(BaseModel):
    """.NET metadata if applicable."""

    is_dotnet: bool = False
    clr_version: str | None = None
    assembly_name: str | None = None
    assembly_version: str | None = None
    target_framework: str | None = None
    dependencies: list[str] = Field(default_factory=list)


class Anomaly(BaseModel):
    """Detected anomalies or suspicious characteristics."""

    type: str
    description: str
    severity: str = "info"  # info, low, medium, high, critical
    details: dict[str, Any] | None = None


class CompleteMetadata(BaseModel):
    """Complete binary metadata including ALL available information."""

    # === File Information ===
    file_path: str
    file_size: int = 0
    file_hash_md5: str | None = None
    file_hash_sha1: str | None = None
    file_hash_sha256: str | None = None
    file_hash_ssdeep: str | None = None

    # === PE Header Information ===
    binary_type: str | None = None
    magic: str | None = None
    machine: str | None = None
    timestamp: int | None = None
    timestamp_human: str | None = None
    checksum: int | None = None
    checksum_valid: bool = False
    characteristics: int | None = None
    dll_characteristics: int | None = None
    subsystem: str | None = None
    subsystem_version: str | None = None

    # === Architecture and Platform ===
    is_64bit: bool = False
    is_32bit: bool = False
    is_driver: bool = False
    is_dll: bool = False
    is_exe: bool = False
    is_gui: bool = False
    is_console: bool = False

    # === Security Features ===
    has_nx: bool = False
    has_dep: bool = False
    has_aslr: bool = False
    has_pie: bool = False
    is_pie: bool = False  # Alternative name for PIE
    has_cfg: bool = False
    has_rfg: bool = False
    has_safeseh: bool = False
    has_gs: bool = False
    has_authenticode: bool = False
    is_signed: bool = False

    # === Size Information ===
    sizeof_code: int = 0
    sizeof_initialized_data: int = 0
    sizeof_uninitialized_data: int = 0
    sizeof_image: int = 0
    sizeof_headers: int = 0
    sizeof_stack_reserve: int = 0
    sizeof_stack_commit: int = 0
    sizeof_heap_reserve: int = 0
    sizeof_heap_commit: int = 0
    virtual_size: int = 0

    # === Memory Layout ===
    image_base: int = 0
    entry_point: int = 0
    base_of_code: int = 0
    base_of_data: int | None = None
    section_alignment: int = 0
    file_alignment: int = 0

    # === Version Information ===
    major_linker_version: int | None = None
    minor_linker_version: int | None = None
    major_image_version: int | None = None
    minor_image_version: int | None = None
    major_operating_system_version: int | None = None
    minor_operating_system_version: int | None = None
    major_subsystem_version: int | None = None
    minor_subsystem_version: int | None = None
    win32_version_value: int | None = None

    # === Loader Information ===
    loader_flags: int | None = None
    number_of_rva_and_sizes: int | None = None

    # === Sections ===
    sections: list[Section] = Field(default_factory=list)
    num_sections: int = 0
    section_names: list[str] = Field(default_factory=list)

    # === Data Directories ===
    data_directories: list[DataDirectory] = Field(default_factory=list)

    # === Imports ===
    imports: list[ImportedFunction] = Field(default_factory=list)
    import_libraries: list[str] = Field(default_factory=list)
    num_imports: int = 0
    num_import_libraries: int = 0
    imphash: str | None = None
    imphash_sorted: str | None = None

    # === Exports ===
    exports: list[ExportedFunction] = Field(default_factory=list)
    export_name: str | None = None
    num_exports: int = 0

    # === Resources ===
    resources: list[Resource] = Field(default_factory=list)
    has_resources: bool = False
    num_resources: int = 0
    resource_types: list[str] = Field(default_factory=list)

    # === Certificates and Signatures ===
    certificates: list[Certificate] = Field(default_factory=list)
    has_certificates: bool = False
    num_certificates: int = 0

    # === Version and Product Info ===
    version_info: VersionInfo | None = None

    # === Rich Header (Compiler Info) ===
    rich_header: RichHeader | None = None
    has_rich_header: bool = False

    # === Debug Information ===
    debug_info: DebugInfo | None = None

    # === .NET Information ===
    dotnet_metadata: DotNetMetadata | None = None

    # === Overlay Information ===
    has_overlay: bool = False
    overlay_size: int = 0
    overlay_offset: int = 0

    # === TLS (Thread Local Storage) ===
    has_tls: bool = False
    tls_callbacks: list[int] = Field(default_factory=list)
    num_tls_callbacks: int = 0

    # === Relocations ===
    has_relocations: bool = False
    num_relocations: int = 0

    # === Exception Handling ===
    has_exceptions: bool = False
    exception_functions: list[dict[str, Any]] = Field(default_factory=list)

    # === Delay Imports ===
    delay_imports: list[ImportedFunction] = Field(default_factory=list)
    num_delay_imports: int = 0

    # === Bound Imports ===
    bound_imports: list[str] = Field(default_factory=list)
    num_bound_imports: int = 0

    # === Symbol Information ===
    symbols: list[str] = Field(default_factory=list)
    num_symbols: int = 0
    has_symbols: bool = False

    # === Entropy Analysis ===
    file_entropy: float = 0.0
    is_packed: bool = False
    packer_detection: str | None = None

    # === Suspicious Characteristics ===
    suspicious_imports: list[str] = Field(default_factory=list)
    suspicious_exports: list[str] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)
    has_kernel_imports: bool = False
    has_memory_mapping: bool = False
    has_process_manipulation: bool = False
    has_registry_access: bool = False
    has_file_operations: bool = False
    has_network_operations: bool = False
    has_crypto_operations: bool = False

    # === Anomalies and Warnings ===
    anomalies: list[Anomaly] = Field(default_factory=list)
    num_anomalies: int = 0

    # === Raw Metadata (for anything not captured above) ===
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class BinaryAnalysisResult(BaseModel):
    """Result of binary metadata analysis."""

    metadata: CompleteMetadata
    vulnerability_indicators: list[str] = Field(default_factory=list)
    security_score: int = 0  # 0-100, higher is more secure
    risk_level: str = "unknown"  # low, medium, high, critical
    recommendations: list[str] = Field(default_factory=list)
