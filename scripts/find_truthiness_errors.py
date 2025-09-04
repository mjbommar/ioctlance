#!/usr/bin/env python3
"""
Script to find all symbolic truthiness errors in IOCTLance detectors.
"""

import json
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, List, Set

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ioctlance.core.analysis_context import AnalysisConfig, AnalysisContext
from ioctlance.core.driver_analyzer import DriverAnalyzer
from ioctlance.output.manager import OutputManager, OutputFormat, OutputLevel


def analyze_driver_for_truthiness(driver_path: Path) -> Dict:
    """Analyze a driver and capture any truthiness errors."""
    results = {
        "driver": str(driver_path),
        "truthiness_errors": [],
        "vulnerabilities_found": 0,
        "ioctl_codes": [],
        "success": False
    }
    
    try:
        # Create output manager
        output_manager = OutputManager(
            output_level=OutputLevel.NORMAL,
            output_format=OutputFormat.JSON,
            dedup_vulnerabilities=True,
            capture_raw_state=False
        )
        
        # Use thorough profile to maximize coverage
        config = AnalysisConfig.from_profile("thorough")
        config.timeout = 60  # Shorter timeout for testing
        
        # Create context
        context = AnalysisContext.create_for_driver(
            driver_path, 
            config, 
            output_manager=output_manager
        )
        
        # Monkey-patch the error handler to capture truthiness errors
        original_print_error = context.print_error
        captured_errors = []
        
        def capture_error(msg):
            original_print_error(msg)
            if "truthiness" in msg.lower():
                captured_errors.append(msg)
        
        context.print_error = capture_error
        
        # Run analysis
        analyzer = DriverAnalyzer(context)
        raw_result = analyzer.analyze()
        
        # Get results
        results["success"] = True
        results["vulnerabilities_found"] = len(raw_result.vuln) if raw_result.vuln else 0
        results["ioctl_codes"] = [h.ioctl_code for h in raw_result.basic.IoControlCodes] if raw_result.basic.IoControlCodes else []
        results["truthiness_errors"] = captured_errors
        
    except Exception as e:
        error_str = str(e)
        tb = traceback.format_exc()
        
        results["error"] = error_str
        results["traceback"] = tb
        
        # Check if it's a truthiness error
        if "truthiness" in error_str:
            # Extract the location from traceback
            tb_lines = tb.split('\n')
            for i, line in enumerate(tb_lines):
                if 'File "/home/mjbommar/src/ioctlance' in line:
                    # Get the file and line number
                    next_line = tb_lines[i+1] if i+1 < len(tb_lines) else ""
                    results["truthiness_errors"].append({
                        "file": line.strip(),
                        "code": next_line.strip(),
                        "error": error_str
                    })
    
    return results


def find_all_truthiness_errors():
    """Find all truthiness errors across test drivers."""
    
    # Test drivers to analyze
    test_drivers = [
        "samples/test_use_after_free.sys",
        "samples/RtDashPt.sys",
        "samples/test_arbitrary_rw.sys",
        "samples/test_double_fetch.sys",
        "samples/test_heap_overflow.sys",
        "samples/test_info_disclosure.sys",
        "samples/test_integer_overflow.sys",
        "samples/test_null_pointer.sys",
        "samples/test_probe_bypass.sys",
        "samples/test_stack_overflow.sys",
    ]
    
    all_errors = {}
    error_locations = set()
    
    print("Finding truthiness errors in IOCTLance detectors...\n")
    
    for driver_name in test_drivers:
        driver_path = Path(driver_name)
        if not driver_path.exists():
            print(f"[SKIP] {driver_name} not found")
            continue
            
        print(f"[TEST] {driver_name}...", end=" ")
        results = analyze_driver_for_truthiness(driver_path)
        
        if results["truthiness_errors"]:
            print(f"FOUND {len(results['truthiness_errors'])} errors")
            all_errors[driver_name] = results["truthiness_errors"]
            
            # Extract unique error locations
            for error in results["truthiness_errors"]:
                if isinstance(error, dict) and "file" in error:
                    # Parse the file location
                    file_line = error["file"]
                    if "line" in file_line:
                        parts = file_line.split(", line")
                        if len(parts) == 2:
                            file_path = parts[0].replace('File "', '').strip('"')
                            line_num = parts[1].strip()
                            error_locations.add((file_path, line_num, error.get("code", "")))
        else:
            if results["success"]:
                print(f"OK (found {results['vulnerabilities_found']} vulns)")
            else:
                print("ERROR")
                if "error" in results:
                    print(f"  {results['error']}")
    
    # Report unique error locations
    if error_locations:
        print("\n" + "="*60)
        print("UNIQUE TRUTHINESS ERROR LOCATIONS:")
        print("="*60)
        
        # Group by file
        by_file = {}
        for file_path, line_num, code in sorted(error_locations):
            if file_path not in by_file:
                by_file[file_path] = []
            by_file[file_path].append((line_num, code))
        
        for file_path, locations in by_file.items():
            # Only show our files
            if "/home/mjbommar/src/ioctlance" in file_path:
                rel_path = file_path.replace("/home/mjbommar/src/ioctlance/", "")
                print(f"\n{rel_path}:")
                for line_num, code in locations:
                    print(f"  Line {line_num}: {code}")
    
    # Save results
    output_file = Path("truthiness_errors.json")
    with open(output_file, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "errors_by_driver": all_errors,
            "unique_locations": [
                {"file": f, "line": l, "code": c} 
                for f, l, c in error_locations
            ]
        }, f, indent=2)
    
    print(f"\nResults saved to {output_file}")
    
    return len(error_locations) > 0


if __name__ == "__main__":
    has_errors = find_all_truthiness_errors()
    sys.exit(1 if has_errors else 0)