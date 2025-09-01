"""Binary metadata extraction using binary-inspector."""

import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Import the models
from ..models.binary_metadata import (
    CompleteMetadata,
    ImportedFunction,
    ExportedFunction,
    Section,
    DataDirectory,
    Resource,
    Certificate,
    VersionInfo,
    RichHeader,
    DebugInfo,
    DotNetMetadata,
    Anomaly,
    BinaryAnalysisResult,
)


def calculate_file_hashes(file_path: Path) -> dict[str, str]:
    """Calculate various hashes for a file.

    Args:
        file_path: Path to the file

    Returns:
        Dictionary with hash values
    """
    hashes = {}

    try:
        with open(file_path, "rb") as f:
            content = f.read()

        hashes["md5"] = hashlib.md5(content).hexdigest()
        hashes["sha1"] = hashlib.sha1(content).hexdigest()
        hashes["sha256"] = hashlib.sha256(content).hexdigest()

    except Exception as e:
        logger.error(f"Failed to calculate hashes: {e}")

    return hashes


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy value (0-8)
    """
    if not data:
        return 0.0

    import math

    # Calculate frequency of each byte
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)

    for count in freq.values():
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)

    return entropy


def extract_complete_metadata(driver_path: Path) -> CompleteMetadata | None:
    """Extract ALL available metadata from a Windows driver file.

    Args:
        driver_path: Path to the driver file

    Returns:
        CompleteMetadata object with all extracted information
    """
    try:
        from binary_inspector import binary
        import lief  # binary-inspector uses lief internally

        # Initialize metadata object
        metadata = CompleteMetadata(file_path=str(driver_path), file_size=driver_path.stat().st_size)

        # Calculate file hashes
        hashes = calculate_file_hashes(driver_path)
        metadata.file_hash_md5 = hashes.get("md5")
        metadata.file_hash_sha1 = hashes.get("sha1")
        metadata.file_hash_sha256 = hashes.get("sha256")

        # Parse binary with binary-inspector
        parsed = binary.parse_binary(str(driver_path))
        if not parsed:
            logger.warning(f"Failed to parse binary: {driver_path}")
            return metadata

        # Get PE metadata from binary-inspector
        raw_metadata = binary.get_pe_metadata(str(driver_path), parsed)
        if raw_metadata:
            # Store raw metadata for reference
            metadata.raw_metadata = raw_metadata

            # === Basic PE Information ===
            metadata.binary_type = raw_metadata.get("binary_type")
            metadata.magic = raw_metadata.get("magic")
            metadata.machine = raw_metadata.get("machine")
            metadata.timestamp = raw_metadata.get("time_date_stamps")

            if metadata.timestamp:
                try:
                    metadata.timestamp_human = datetime.fromtimestamp(metadata.timestamp).isoformat()
                except:
                    pass

            metadata.checksum = raw_metadata.get("checksum")
            
            # Convert characteristics to int if it's a string (like "EXECUTABLE_IMAGE, LARGE_ADDRESS_AWARE")
            raw_characteristics = raw_metadata.get("characteristics")
            if raw_characteristics:
                try:
                    if isinstance(raw_characteristics, str):
                        # Check if it's a hex value
                        if raw_characteristics.startswith("0x"):
                            metadata.characteristics = int(raw_characteristics, 16)
                        # Check if it's a numeric string
                        elif raw_characteristics.isdigit():
                            metadata.characteristics = int(raw_characteristics)
                        else:
                            # It's a string with flag names - set to None to avoid Pydantic error
                            # Store the string representation separately if needed
                            metadata.raw_metadata["characteristics_string"] = raw_characteristics
                            metadata.characteristics = None
                            # Check for DLL flag in the string
                            metadata.is_dll = "DLL" in raw_characteristics
                    else:
                        metadata.characteristics = int(raw_characteristics)
                        metadata.is_dll = bool(metadata.characteristics & 0x2000) if metadata.characteristics else False
                except (ValueError, TypeError):
                    logger.debug(f"Could not parse characteristics: {raw_characteristics}")
                    metadata.characteristics = None
            else:
                metadata.characteristics = None
                
            metadata.dll_characteristics = raw_metadata.get("dll_characteristics")
            metadata.subsystem = raw_metadata.get("subsystem")

            # === Architecture ===
            if metadata.machine:
                metadata.is_64bit = any(x in metadata.machine.lower() for x in ["x64", "amd64", "x86_64"])
                metadata.is_32bit = not metadata.is_64bit

            metadata.is_driver = raw_metadata.get("is_driver", False)
            metadata.is_gui = raw_metadata.get("is_gui", False)
            
            # is_dll and is_exe already set in characteristics parsing above
            if not hasattr(metadata, 'is_dll') or metadata.is_dll is None:
                metadata.is_dll = False
            metadata.is_exe = not metadata.is_dll

            # === Security Features ===
            metadata.has_nx = raw_metadata.get("has_nx", False)
            metadata.is_pie = raw_metadata.get("is_pie", False)
            metadata.has_pie = metadata.is_pie

            # Convert dll_characteristics to int if it's a string
            if metadata.dll_characteristics:
                try:
                    if isinstance(metadata.dll_characteristics, str):
                        # Try to parse as hex or decimal
                        if metadata.dll_characteristics.startswith("0x"):
                            dll_chars = int(metadata.dll_characteristics, 16)
                        else:
                            dll_chars = int(metadata.dll_characteristics)
                    else:
                        dll_chars = int(metadata.dll_characteristics)

                    metadata.dll_characteristics = dll_chars
                    metadata.has_aslr = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                    metadata.has_dep = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                    metadata.has_cfg = bool(dll_chars & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
                    metadata.has_rfg = bool(dll_chars & 0x2000)  # IMAGE_DLLCHARACTERISTICS_GUARD_RF
                except (ValueError, TypeError):
                    logger.debug(f"Could not parse dll_characteristics: {metadata.dll_characteristics}")

            # === Size Information ===
            metadata.sizeof_code = raw_metadata.get("sizeof_code", 0)
            metadata.sizeof_initialized_data = raw_metadata.get("sizeof_initialized_data", 0)
            metadata.sizeof_uninitialized_data = raw_metadata.get("sizeof_uninitialized_data", 0)
            metadata.sizeof_image = raw_metadata.get("sizeof_image", 0)
            metadata.sizeof_headers = raw_metadata.get("sizeof_headers", 0)
            metadata.sizeof_stack_reserve = raw_metadata.get("sizeof_stack_reserve", 0)
            metadata.sizeof_stack_commit = raw_metadata.get("sizeof_stack_commit", 0)
            metadata.sizeof_heap_reserve = raw_metadata.get("sizeof_heap_reserve", 0)
            metadata.sizeof_heap_commit = raw_metadata.get("sizeof_heap_commit", 0)
            metadata.virtual_size = raw_metadata.get("virtual_size", 0)

            # === Memory Layout ===
            metadata.image_base = raw_metadata.get("imagebase", 0)
            metadata.entry_point = raw_metadata.get("addressof_entrypoint", 0)
            metadata.base_of_code = raw_metadata.get("baseof_code", 0)
            metadata.base_of_data = raw_metadata.get("baseof_data")
            metadata.section_alignment = raw_metadata.get("section_alignment", 0)
            metadata.file_alignment = raw_metadata.get("file_alignment", 0)

            # === Version Information ===
            metadata.major_linker_version = raw_metadata.get("major_linker_version")
            metadata.minor_linker_version = raw_metadata.get("minor_linker_version")
            metadata.major_image_version = raw_metadata.get("major_image_version")
            metadata.minor_image_version = raw_metadata.get("minor_image_version")
            metadata.major_operating_system_version = raw_metadata.get("major_operating_system_version")
            metadata.minor_operating_system_version = raw_metadata.get("minor_operating_system_version")
            metadata.major_subsystem_version = raw_metadata.get("major_subsystem_version")
            metadata.minor_subsystem_version = raw_metadata.get("minor_subsystem_version")
            metadata.win32_version_value = raw_metadata.get("win32_version_value")

            # === Loader Information ===
            metadata.loader_flags = raw_metadata.get("loader_flags")
            metadata.number_of_rva_and_sizes = raw_metadata.get("numberof_rva_and_size")

            # === Data Directories ===
            data_dirs = raw_metadata.get("data_directories", {})
            if isinstance(data_dirs, dict):
                for name, info in data_dirs.items():
                    if isinstance(info, dict):
                        dd = DataDirectory(name=name, rva=info.get("RVA", 0), size=info.get("size", 0))
                        metadata.data_directories.append(dd)

                        # Check for specific directories
                        if name == "CERTIFICATE_TABLE" and info.get("size", 0) > 0:
                            metadata.has_certificates = True
                        elif name == "TLS_TABLE" and info.get("size", 0) > 0:
                            metadata.has_tls = True
                        elif name == "EXCEPTION_TABLE" and info.get("size", 0) > 0:
                            metadata.has_exceptions = True
                        elif name == "BASE_RELOCATION_TABLE" and info.get("size", 0) > 0:
                            metadata.has_relocations = True

            # === Process Imports ===
            suspicious_imports = {
                # Memory manipulation
                "MmMapIoSpace",
                "MmMapIoSpaceEx",
                "MmMapLockedPages",
                "MmMapLockedPagesSpecifyCache",
                "MmGetPhysicalAddress",
                "MmGetSystemAddressForMdlSafe",
                "MmBuildMdlForNonPagedPool",
                "MmAllocateContiguousMemory",
                "MmAllocateNonCachedMemory",
                # Process manipulation
                "ZwTerminateProcess",
                "ZwOpenProcess",
                "PsLookupProcessByProcessId",
                "ZwQueryInformationProcess",
                "ZwSetInformationProcess",
                "KeAttachProcess",
                "KeDetachProcess",
                "KeStackAttachProcess",
                # Registry access
                "ZwCreateKey",
                "ZwOpenKey",
                "ZwSetValueKey",
                "ZwQueryValueKey",
                "ZwDeleteKey",
                "ZwDeleteValueKey",
                "RtlWriteRegistryValue",
                # File operations
                "ZwCreateFile",
                "ZwOpenFile",
                "ZwWriteFile",
                "ZwReadFile",
                "ZwDeleteFile",
                "ZwQueryInformationFile",
                "ZwSetInformationFile",
                # System calls
                "ZwQuerySystemInformation",
                "ZwSetSystemInformation",
                "ZwLoadDriver",
                "ZwUnloadDriver",
                # Token manipulation
                "ZwOpenProcessToken",
                "ZwAdjustPrivilegesToken",
                # Dangerous string functions
                "strcpy",
                "strcat",
                "sprintf",
                "vsprintf",
                "gets",
                "wcscpy",
                "wcscat",
                "swprintf",
                "vswprintf",
                # Memory operations
                "RtlCopyMemory",
                "memcpy",
                "memmove",
                # Network operations
                "NdisSendNetBufferLists",
                "NdisReturnNetBufferLists",
                "WSKSend",
                "WSKReceive",
                "TdiSend",
                "TdiReceive",
                # Crypto operations
                "BCryptGenerateSymmetricKey",
                "BCryptEncrypt",
                "BCryptDecrypt",
                "CryptAcquireContext",
                "CryptEncrypt",
                "CryptDecrypt",
            }

            raw_imports = raw_metadata.get("imports", [])
            import_libs = set()

            for imp in raw_imports:
                if isinstance(imp, dict):
                    full_name = imp.get("name", "")
                    short_name = imp.get("short_name", "")

                    library = "unknown"
                    if "::" in full_name:
                        library, _ = full_name.split("::", 1)
                        import_libs.add(library)

                    imported_func = ImportedFunction(
                        name=full_name,
                        short_name=short_name,
                        library=library,
                        data=imp.get("data"),
                        iat_value=imp.get("iat_value"),
                        hint=imp.get("hint"),
                        ordinal=imp.get("ordinal"),
                        is_ordinal=imp.get("is_ordinal", False),
                    )
                    metadata.imports.append(imported_func)

                    # Check for suspicious imports
                    if short_name in suspicious_imports:
                        metadata.suspicious_imports.append(short_name)

                    # Categorize imports
                    lib_lower = library.lower()
                    if lib_lower in ["ntoskrnl.exe", "hal.dll"]:
                        metadata.has_kernel_imports = True

                    if any(mem in short_name for mem in ["MmMap", "MmGet", "MmAllocate", "Physical"]):
                        metadata.has_memory_mapping = True

                    if any(proc in short_name for proc in ["Process", "Thread", "Token"]):
                        metadata.has_process_manipulation = True

                    if any(reg in short_name for reg in ["Registry", "ZwCreateKey", "ZwOpenKey", "RtlWriteRegistry"]):
                        metadata.has_registry_access = True

                    if any(file in short_name for file in ["ZwCreateFile", "ZwOpenFile", "ZwWriteFile", "ZwReadFile"]):
                        metadata.has_file_operations = True

                    if any(net in short_name for net in ["Ndis", "WSK", "Tdi", "Tcp", "Socket"]):
                        metadata.has_network_operations = True

                    if any(
                        crypto in short_name for crypto in ["BCrypt", "Crypt", "Hash", "Cipher", "Encrypt", "Decrypt"]
                    ):
                        metadata.has_crypto_operations = True

            metadata.import_libraries = sorted(list(import_libs))
            metadata.num_imports = len(metadata.imports)
            metadata.num_import_libraries = len(metadata.import_libraries)

            # Import hashes
            metadata.imphash = raw_metadata.get("imphash_pefile") or raw_metadata.get("imphash_lief")

            # === Process Exports ===
            raw_exports = raw_metadata.get("exports", [])
            if raw_exports:
                for exp in raw_exports:
                    if isinstance(exp, dict):
                        exported_func = ExportedFunction(
                            name=exp.get("name", ""),
                            ordinal=exp.get("ordinal", 0),
                            rva=exp.get("rva", 0),
                            forwarder=exp.get("forwarder"),
                            is_forwarded=exp.get("is_forwarded", False),
                        )
                        metadata.exports.append(exported_func)

                        # Check for suspicious exports
                        exp_name = exp.get("name", "")
                        if any(sus in exp_name.lower() for sus in ["hook", "inject", "hide", "rootkit"]):
                            metadata.suspicious_exports.append(exp_name)

            metadata.num_exports = len(metadata.exports)
            metadata.export_name = raw_metadata.get("name")

            # === Sections ===
            sections = raw_metadata.get("sections", [])
            if sections:
                for sec in sections:
                    if hasattr(sec, "__dict__"):
                        sec_dict = sec.__dict__
                    elif isinstance(sec, dict):
                        sec_dict = sec
                    else:
                        continue

                    section = Section(
                        name=sec_dict.get("name", ""),
                        virtual_address=sec_dict.get("virtual_address", 0),
                        virtual_size=sec_dict.get("virtual_size", 0),
                        raw_size=sec_dict.get("sizeof_raw_data", 0),
                        entropy=sec_dict.get("entropy", 0.0),
                        characteristics=sec_dict.get("characteristics", 0),
                    )

                    # Check section permissions
                    if section.characteristics:
                        section.is_executable = bool(section.characteristics & 0x20000000)
                        section.is_writable = bool(section.characteristics & 0x80000000)
                        section.is_readable = bool(section.characteristics & 0x40000000)

                    metadata.sections.append(section)
                    metadata.section_names.append(section.name)

            metadata.num_sections = len(metadata.sections)

            # === Resources ===
            resources = raw_metadata.get("resources")
            if resources:
                metadata.has_resources = True
                # Process resources if needed

            # === Certificates ===
            signatures = raw_metadata.get("signatures")
            if signatures:
                metadata.has_certificates = True
                metadata.is_signed = True
                # Process certificates if available

            # === .NET Metadata ===
            dotnet_deps = raw_metadata.get("dotnet_dependencies", [])
            # Convert to list if it's a dict or other type
            if isinstance(dotnet_deps, dict):
                dotnet_deps = list(dotnet_deps.keys()) if dotnet_deps else []
            elif not isinstance(dotnet_deps, list):
                dotnet_deps = []

            metadata.dotnet_metadata = DotNetMetadata(
                is_dotnet=raw_metadata.get("is_dotnet", False), dependencies=dotnet_deps
            )

            # === Debug Information ===
            metadata.debug_info = DebugInfo(has_debug=bool(raw_metadata.get("debug")))

            # === Symbols ===
            symbols = raw_metadata.get("symtab_symbols", [])
            if symbols:
                metadata.has_symbols = True
                metadata.num_symbols = len(symbols)
                # Extract symbol names from dict entries
                if isinstance(symbols, list) and symbols:
                    # If symbols are dicts, extract the 'name' field
                    if isinstance(symbols[0], dict):
                        metadata.symbols = [sym.get("name", str(sym)) for sym in symbols[:100]]
                    else:
                        # Already strings
                        metadata.symbols = symbols[:100]
                else:
                    metadata.symbols = []

            # === TLS Callbacks ===
            tls_callbacks = raw_metadata.get("tls_callbacks", [])
            if tls_callbacks:
                metadata.has_tls = True
                metadata.tls_callbacks = tls_callbacks
                metadata.num_tls_callbacks = len(tls_callbacks)

            # === Exception Functions ===
            exception_funcs = raw_metadata.get("exception_functions", [])
            if exception_funcs:
                metadata.has_exceptions = True
                metadata.exception_functions = exception_funcs

            # === Relocations ===
            num_relocs = raw_metadata.get("num_relocation", 0)
            if num_relocs > 0:
                metadata.has_relocations = True
                metadata.num_relocations = num_relocs

            # === Entropy Analysis ===
            with open(driver_path, "rb") as f:
                file_data = f.read()
                metadata.file_entropy = calculate_entropy(file_data)

            # High entropy might indicate packing
            if metadata.file_entropy > 7.0:
                metadata.is_packed = True
                metadata.anomalies.append(
                    Anomaly(
                        type="high_entropy",
                        description=f"File entropy is {metadata.file_entropy:.2f}, possible packing",
                        severity="medium",
                    )
                )

            # === Detect Anomalies ===
            detect_anomalies(metadata)

        # === Use LIEF for additional parsing if available ===
        try:
            import lief

            lief.logging.disable()

            pe = lief.parse(str(driver_path))
            if pe:
                # Get additional data that binary-inspector might miss

                # Overlay detection
                if pe.overlay:
                    metadata.has_overlay = True
                    metadata.overlay_size = len(pe.overlay)
                    metadata.overlay_offset = pe.sizeof_headers + sum(s.sizeof_raw_data for s in pe.sections)

                # Rich header
                if pe.rich_header and pe.rich_header.entries:
                    metadata.has_rich_header = True
                    metadata.rich_header = RichHeader(
                        entries=[{"id": e.id, "build_id": e.build_id, "count": e.count} for e in pe.rich_header.entries]
                    )

                # Load config if available
                if pe.load_configuration:
                    cfg = pe.load_configuration
                    if hasattr(cfg, "guard_cf_check_function"):
                        metadata.has_cfg = cfg.guard_cf_check_function != 0
                    if hasattr(cfg, "guard_rf_verify_stackpointer"):
                        metadata.has_rfg = cfg.guard_rf_verify_stackpointer != 0

        except ImportError:
            pass  # LIEF not available
        except Exception as e:
            logger.debug(f"LIEF parsing failed: {e}")

        metadata.num_anomalies = len(metadata.anomalies)

        return metadata

    except ImportError:
        logger.error("binary-inspector not installed. Run: uv add binary-inspector")
        return None
    except Exception as e:
        logger.error(f"Failed to extract binary metadata from {driver_path}: {e}")
        import traceback

        traceback.print_exc()
        return None


def detect_anomalies(metadata: CompleteMetadata) -> None:
    """Detect anomalies and suspicious characteristics in the binary.

    Args:
        metadata: CompleteMetadata object to analyze and update
    """
    anomalies = []

    # Check for missing security features
    if not metadata.has_nx and not metadata.has_dep:
        anomalies.append(
            Anomaly(type="missing_dep", description="Binary compiled without DEP/NX protection", severity="high")
        )

    if not metadata.has_aslr:
        anomalies.append(Anomaly(type="missing_aslr", description="Binary compiled without ASLR", severity="medium"))

    if metadata.is_64bit and not metadata.has_cfg:
        anomalies.append(
            Anomaly(type="missing_cfg", description="64-bit binary compiled without Control Flow Guard", severity="low")
        )

    # Check for suspicious section characteristics
    for section in metadata.sections:
        if section.is_executable and section.is_writable:
            anomalies.append(
                Anomaly(
                    type="rwx_section",
                    description=f"Section '{section.name}' is both writable and executable",
                    severity="high",
                    details={"section": section.name},
                )
            )

        if section.entropy > 7.5:
            anomalies.append(
                Anomaly(
                    type="high_entropy_section",
                    description=f"Section '{section.name}' has high entropy ({section.entropy:.2f})",
                    severity="medium",
                    details={"section": section.name, "entropy": section.entropy},
                )
            )

    # Check for suspicious imports
    if len(metadata.suspicious_imports) > 10:
        anomalies.append(
            Anomaly(
                type="many_suspicious_imports",
                description=f"Binary imports {len(metadata.suspicious_imports)} suspicious functions",
                severity="medium",
                details={"count": len(metadata.suspicious_imports)},
            )
        )

    # Check for TLS callbacks (often used by malware)
    if metadata.has_tls and metadata.num_tls_callbacks > 0:
        anomalies.append(
            Anomaly(
                type="tls_callbacks",
                description=f"Binary has {metadata.num_tls_callbacks} TLS callback(s)",
                severity="low",
                details={"count": metadata.num_tls_callbacks},
            )
        )

    # Check timestamp
    if metadata.timestamp:
        # Check for future timestamp
        if metadata.timestamp > datetime.now().timestamp():
            anomalies.append(
                Anomaly(
                    type="future_timestamp",
                    description="Binary has a timestamp in the future",
                    severity="medium",
                    details={"timestamp": metadata.timestamp_human},
                )
            )
        # Check for very old timestamp (before Windows XP)
        elif metadata.timestamp < 1000000000:  # Before Sept 2001
            anomalies.append(
                Anomaly(
                    type="ancient_timestamp",
                    description="Binary has suspiciously old timestamp",
                    severity="low",
                    details={"timestamp": metadata.timestamp_human},
                )
            )

    # Check for missing imports (suspicious for drivers)
    if metadata.is_driver and metadata.num_imports == 0:
        anomalies.append(Anomaly(type="no_imports", description="Driver has no imports (suspicious)", severity="high"))

    # Check for overlay
    if metadata.has_overlay and metadata.overlay_size > 1024 * 1024:  # > 1MB
        anomalies.append(
            Anomaly(
                type="large_overlay",
                description=f"Binary has large overlay ({metadata.overlay_size} bytes)",
                severity="medium",
                details={"size": metadata.overlay_size},
            )
        )

    metadata.anomalies.extend(anomalies)


def analyze_binary_for_vulnerabilities(metadata: CompleteMetadata) -> BinaryAnalysisResult:
    """Analyze binary metadata for vulnerability indicators.

    Args:
        metadata: Complete binary metadata

    Returns:
        BinaryAnalysisResult with vulnerability analysis
    """
    result = BinaryAnalysisResult(metadata=metadata)

    # Check for vulnerability indicators
    if metadata.has_memory_mapping:
        result.vulnerability_indicators.append("Imports physical memory mapping functions (CVE-2019-16098 pattern)")

    if metadata.has_process_manipulation:
        result.vulnerability_indicators.append("Imports process manipulation functions (privilege escalation risk)")

    dangerous_funcs = ["strcpy", "strcat", "sprintf", "vsprintf", "gets"]
    used_dangerous = [f for f in metadata.suspicious_imports if f in dangerous_funcs]
    if used_dangerous:
        result.vulnerability_indicators.append(
            f"Uses dangerous string functions: {', '.join(used_dangerous)} (buffer overflow risk)"
        )

    # Calculate security score (0-100, higher is better)
    score = 100

    # Deduct for missing protections
    if not metadata.has_nx:
        score -= 20
        result.recommendations.append("Enable NX/DEP protection")
    if not metadata.has_aslr:
        score -= 15
        result.recommendations.append("Enable ASLR")
    if metadata.is_64bit and not metadata.has_cfg:
        score -= 10
        result.recommendations.append("Enable Control Flow Guard")
    if not metadata.is_signed:
        score -= 10
        result.recommendations.append("Sign the driver with a valid certificate")

    # Deduct for risky imports
    if metadata.has_memory_mapping:
        score -= 15
    if len(metadata.suspicious_imports) > 5:
        score -= min(len(metadata.suspicious_imports) * 2, 20)

    # Deduct for anomalies
    for anomaly in metadata.anomalies:
        if anomaly.severity == "critical":
            score -= 20
        elif anomaly.severity == "high":
            score -= 10
        elif anomaly.severity == "medium":
            score -= 5
        elif anomaly.severity == "low":
            score -= 2

    result.security_score = max(0, score)

    # Determine risk level
    if result.security_score >= 80:
        result.risk_level = "low"
    elif result.security_score >= 60:
        result.risk_level = "medium"
    elif result.security_score >= 40:
        result.risk_level = "high"
    else:
        result.risk_level = "critical"

    return result
