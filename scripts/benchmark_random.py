#!/usr/bin/env python3
"""
Comprehensive benchmarking script for IOCTLance.

This script randomly selects and analyzes drivers, collecting detailed
metrics for performance analysis, regression detection, and continuous improvement.
"""

import json
import random
import sys
import time
import traceback
import psutil
import hashlib
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import subprocess

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ioctlance.core.analysis_context import AnalysisConfig, AnalysisContext
from ioctlance.core.driver_analyzer import DriverAnalyzer
from ioctlance.output.manager import OutputManager, UnifiedAnalysisResult
from ioctlance.output.formats import OutputFormat, OutputLevel
from ioctlance.output.fingerprint import DriverFingerprint
from ioctlance.__version__ import __version__


class PerformanceMonitor:
    """Monitor system performance during analysis."""
    
    def __init__(self):
        self.process = psutil.Process()
        self.start_time = None
        self.start_memory = None
        self.start_cpu_time = None
        self.peak_memory = 0
        
    def start(self):
        """Start monitoring."""
        self.start_time = time.time()
        self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        self.start_cpu_time = self.process.cpu_times()
        self.peak_memory = self.start_memory
        
    def update_peak(self):
        """Update peak memory usage."""
        current_memory = self.process.memory_info().rss / 1024 / 1024
        self.peak_memory = max(self.peak_memory, current_memory)
        
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        elapsed_time = time.time() - self.start_time
        current_memory = self.process.memory_info().rss / 1024 / 1024
        memory_delta = current_memory - self.start_memory
        cpu_times = self.process.cpu_times()
        cpu_user = cpu_times.user - self.start_cpu_time.user
        cpu_system = cpu_times.system - self.start_cpu_time.system
        
        return {
            "elapsed_time": elapsed_time,
            "memory_start_mb": self.start_memory,
            "memory_current_mb": current_memory,
            "memory_delta_mb": memory_delta,
            "memory_peak_mb": self.peak_memory,
            "cpu_user_seconds": cpu_user,
            "cpu_system_seconds": cpu_system,
            "cpu_total_seconds": cpu_user + cpu_system,
            "cpu_percent": (cpu_user + cpu_system) / elapsed_time * 100 if elapsed_time > 0 else 0
        }


class BenchmarkResult:
    """Container for benchmark results."""
    
    def __init__(self, driver_path: Path, seed: int):
        self.driver_path = driver_path
        self.driver_name = driver_path.name
        self.driver_size = driver_path.stat().st_size
        self.seed = seed
        self.start_time = None
        self.end_time = None
        self.success = False
        self.error = None
        self.error_type = None
        self.traceback = None
        self.vulnerabilities = []
        self.vulnerability_types = set()
        self.vulnerability_count = 0
        self.ioctl_codes = []
        self.performance_metrics = {}
        self.timeout_occurred = False
        self.analysis_phases = {}
        self.detector_stats = defaultdict(int)
        self.raw_output = None
        self.fingerprint = None
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "driver": {
                "path": str(self.driver_path),
                "name": self.driver_name,
                "size_bytes": self.driver_size,
                "fingerprint": self.fingerprint
            },
            "execution": {
                "seed": self.seed,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else None,
                "success": self.success,
                "timeout": self.timeout_occurred
            },
            "results": {
                "vulnerability_count": self.vulnerability_count,
                "vulnerability_types": list(self.vulnerability_types),
                "vulnerabilities": self.vulnerabilities,
                "ioctl_codes": self.ioctl_codes,
                "detector_stats": dict(self.detector_stats)
            },
            "performance": self.performance_metrics,
            "error": {
                "message": self.error,
                "type": self.error_type,
                "traceback": self.traceback
            } if self.error else None,
            "phases": self.analysis_phases
        }


class BenchmarkRunner:
    """Main benchmark runner."""
    
    def __init__(self, 
                 driver_dir: Path,
                 num_drivers: int = 100,
                 timeout: int = 120,
                 seed: Optional[int] = None,
                 profile: str = "balanced",
                 verbose: bool = True):
        self.driver_dir = driver_dir
        self.num_drivers = num_drivers
        self.timeout = timeout
        self.seed = seed or int(time.time())
        self.profile = profile
        self.verbose = verbose
        self.results = []
        self.start_time = None
        self.end_time = None
        
        # Set random seed for reproducibility
        random.seed(self.seed)
        
        # Performance monitor
        self.perf_monitor = PerformanceMonitor()
        
    def select_drivers(self) -> List[Path]:
        """Select random drivers from the directory."""
        print(f"[*] Scanning {self.driver_dir} for .sys files...")
        all_drivers = list(self.driver_dir.rglob("*.sys"))
        print(f"[*] Found {len(all_drivers)} total drivers")
        
        if len(all_drivers) < self.num_drivers:
            print(f"[!] Warning: Only {len(all_drivers)} drivers available, using all")
            selected = all_drivers
        else:
            selected = random.sample(all_drivers, self.num_drivers)
            
        print(f"[*] Selected {len(selected)} drivers (seed: {self.seed})")
        return sorted(selected)  # Sort for consistent ordering
        
    def analyze_driver(self, driver_path: Path) -> BenchmarkResult:
        """Analyze a single driver and collect metrics."""
        result = BenchmarkResult(driver_path, self.seed)
        result.start_time = datetime.now()
        
        # Get driver fingerprint
        try:
            fingerprint = DriverFingerprint.from_file(driver_path)
            result.fingerprint = {
                "blake2b": fingerprint.blake2b,
                "sha256": fingerprint.sha256,
                "md5": fingerprint.md5
            }
        except Exception as e:
            result.fingerprint = {"error": str(e)}
        
        # Start performance monitoring
        self.perf_monitor.start()
        
        try:
            # Create output manager (lightweight for benchmarking)
            output_manager = OutputManager(
                output_level=OutputLevel.VERBOSE if self.verbose else OutputLevel.NORMAL,
                output_format=OutputFormat.JSON,
                dedup_vulnerabilities=True,
                capture_raw_state=False  # Reduce memory usage for benchmarks
            )
            
            # Use unified configuration system for all profiles
            if self.profile in ["fast", "balanced", "thorough", "paranoid", "memory_safe"]:
                # Use profile-based configuration
                config = AnalysisConfig.from_profile(self.profile)
                # Override timeout if specified
                if self.timeout != config.timeout:
                    config.timeout = self.timeout
            else:
                # Use standard configuration
                config = AnalysisConfig(
                    timeout=self.timeout,
                    debug=False,
                    verbose=self.verbose
                )
            
            # Apply common settings
            config.verbose = self.verbose
            config.debug = False
            
            # Create context with configuration
            context = AnalysisContext.create_for_driver(
                driver_path, 
                config, 
                output_manager=output_manager
            )
            
            # Track phase timing
            phase_start = time.time()
            
            # Run analysis
            analyzer = DriverAnalyzer(context)
            
            # Phase 1: Binary analysis
            phase1_start = time.time()
            raw_result = analyzer.analyze()
            phase1_time = time.time() - phase1_start
            result.analysis_phases["binary_analysis"] = phase1_time
            
            # Get unified result
            analysis_time = time.time() - phase_start
            unified_result = output_manager.create_result(
                raw_result=raw_result,
                analysis_time=analysis_time
            )
            
            # Extract results
            result.success = len(unified_result.errors) == 0
            result.vulnerability_count = len(unified_result.vulnerabilities)
            
            # Collect vulnerability details
            for vuln in unified_result.vulnerabilities:
                vuln_data = {
                    "type": vuln.type,
                    "severity": vuln.severity,
                    "confidence": vuln.confidence,
                    "description": vuln.description,
                    "ioctl_code": vuln.ioctl_code,
                    "address": vuln.address,
                    "detector": vuln.detector
                }
                result.vulnerabilities.append(vuln_data)
                result.vulnerability_types.add(vuln.type)
                result.detector_stats[vuln.detector] += 1
                
            # Collect IOCTL codes
            if unified_result.summary and unified_result.summary.ioctl_codes:
                result.ioctl_codes = [f"0x{code:08x}" for code in unified_result.summary.ioctl_codes]
                
            # Update peak memory during analysis
            self.perf_monitor.update_peak()
            
        except subprocess.TimeoutExpired:
            result.timeout_occurred = True
            result.error = f"Analysis timeout after {self.timeout} seconds"
            result.error_type = "TimeoutError"
            
        except Exception as e:
            result.error = str(e)
            result.error_type = type(e).__name__
            result.traceback = traceback.format_exc()
            
        finally:
            result.end_time = datetime.now()
            result.performance_metrics = self.perf_monitor.get_metrics()
            
        return result
        
    def run_benchmark(self) -> Dict[str, Any]:
        """Run the full benchmark."""
        self.start_time = datetime.now()
        print(f"\n{'='*60}")
        print(f"IOCTLance Benchmark Run")
        print(f"{'='*60}")
        print(f"Start time: {self.start_time.isoformat()}")
        print(f"Random seed: {self.seed}")
        print(f"Profile: {self.profile}")
        print(f"Timeout: {self.timeout}s")
        print(f"{'='*60}\n")
        
        # Select drivers
        drivers = self.select_drivers()
        
        # Analyze each driver
        for i, driver_path in enumerate(drivers, 1):
            print(f"\n[{i}/{len(drivers)}] Analyzing {driver_path.name}...")
            print(f"  Size: {driver_path.stat().st_size:,} bytes")
            
            result = self.analyze_driver(driver_path)
            self.results.append(result)
            
            # Print result summary
            if result.success:
                if result.vulnerability_count > 0:
                    print(f"  ✓ SUCCESS: Found {result.vulnerability_count} vulnerabilities")
                    for vtype in result.vulnerability_types:
                        count = sum(1 for v in result.vulnerabilities if v['type'] == vtype)
                        print(f"    - {vtype}: {count}")
                else:
                    print(f"  ✓ SUCCESS: Clean (no vulnerabilities)")
            elif result.timeout_occurred:
                print(f"  ⏱ TIMEOUT: Analysis exceeded {self.timeout}s")
            else:
                print(f"  ✗ FAILED: {result.error_type}: {result.error}")
                
            print(f"  Time: {result.performance_metrics.get('elapsed_time', 0):.2f}s")
            print(f"  Memory: {result.performance_metrics.get('memory_peak_mb', 0):.1f} MB peak")
            
        self.end_time = datetime.now()
        
        # Generate summary
        summary = self.generate_summary()
        
        # Print summary
        self.print_summary(summary)
        
        return summary
        
    def generate_summary(self) -> Dict[str, Any]:
        """Generate comprehensive benchmark summary."""
        successful_results = [r for r in self.results if r.success]
        failed_results = [r for r in self.results if not r.success and not r.timeout_occurred]
        timeout_results = [r for r in self.results if r.timeout_occurred]
        
        # Calculate statistics
        vuln_counts = [r.vulnerability_count for r in successful_results]
        exec_times = [r.performance_metrics.get('elapsed_time', 0) for r in self.results if r.performance_metrics]
        memory_peaks = [r.performance_metrics.get('memory_peak_mb', 0) for r in self.results if r.performance_metrics]
        
        # Aggregate vulnerability types
        all_vuln_types = defaultdict(int)
        for r in successful_results:
            for vtype in r.vulnerability_types:
                all_vuln_types[vtype] += sum(1 for v in r.vulnerabilities if v['type'] == vtype)
                
        # Aggregate detector stats
        all_detector_stats = defaultdict(int)
        for r in successful_results:
            for detector, count in r.detector_stats.items():
                all_detector_stats[detector] += count
                
        # Error analysis
        error_types = defaultdict(int)
        for r in failed_results:
            error_types[r.error_type] += 1
            
        summary = {
            "metadata": {
                "benchmark_version": "1.0.0",
                "ioctlance_version": __version__,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "total_duration_seconds": (self.end_time - self.start_time).total_seconds(),
                "seed": self.seed,
                "profile": self.profile,
                "timeout": self.timeout,
                "driver_directory": str(self.driver_dir),
                "num_drivers": len(self.results)
            },
            "overall_stats": {
                "total_analyzed": len(self.results),
                "successful": len(successful_results),
                "failed": len(failed_results),
                "timeout": len(timeout_results),
                "success_rate": len(successful_results) / len(self.results) * 100 if self.results else 0,
                "drivers_with_vulnerabilities": sum(1 for r in successful_results if r.vulnerability_count > 0),
                "total_vulnerabilities": sum(vuln_counts)
            },
            "vulnerability_stats": {
                "average_per_driver": sum(vuln_counts) / len(successful_results) if successful_results else 0,
                "max_in_single_driver": max(vuln_counts) if vuln_counts else 0,
                "min_in_single_driver": min(vuln_counts) if vuln_counts else 0,
                "by_type": dict(all_vuln_types),
                "by_detector": dict(all_detector_stats)
            },
            "performance_stats": {
                "average_time_seconds": sum(exec_times) / len(exec_times) if exec_times else 0,
                "max_time_seconds": max(exec_times) if exec_times else 0,
                "min_time_seconds": min(exec_times) if exec_times else 0,
                "total_time_seconds": sum(exec_times),
                "average_memory_mb": sum(memory_peaks) / len(memory_peaks) if memory_peaks else 0,
                "max_memory_mb": max(memory_peaks) if memory_peaks else 0,
                "min_memory_mb": min(memory_peaks) if memory_peaks else 0
            },
            "error_analysis": {
                "error_types": dict(error_types),
                "timeout_count": len(timeout_results),
                "most_common_error": max(error_types.items(), key=lambda x: x[1])[0] if error_types else None
            },
            "top_problematic_drivers": [
                {
                    "name": r.driver_name,
                    "path": str(r.driver_path),
                    "error": r.error_type,
                    "message": r.error
                }
                for r in failed_results[:10]  # Top 10 problematic drivers
            ],
            "top_vulnerable_drivers": [
                {
                    "name": r.driver_name,
                    "path": str(r.driver_path),
                    "vulnerability_count": r.vulnerability_count,
                    "types": list(r.vulnerability_types)
                }
                for r in sorted(successful_results, key=lambda x: x.vulnerability_count, reverse=True)[:10]
            ],
            "results": [r.to_dict() for r in self.results]
        }
        
        return summary
        
    def print_summary(self, summary: Dict[str, Any]):
        """Print benchmark summary to console."""
        print(f"\n{'='*60}")
        print(f"Benchmark Summary")
        print(f"{'='*60}")
        
        overall = summary["overall_stats"]
        print(f"\nOverall Results:")
        print(f"  Total drivers: {overall['total_analyzed']}")
        print(f"  Successful: {overall['successful']} ({overall['success_rate']:.1f}%)")
        print(f"  Failed: {overall['failed']}")
        print(f"  Timeout: {overall['timeout']}")
        print(f"  Drivers with vulnerabilities: {overall['drivers_with_vulnerabilities']}")
        print(f"  Total vulnerabilities: {overall['total_vulnerabilities']}")
        
        vuln_stats = summary["vulnerability_stats"]
        print(f"\nVulnerability Statistics:")
        print(f"  Average per driver: {vuln_stats['average_per_driver']:.2f}")
        print(f"  Max in single driver: {vuln_stats['max_in_single_driver']}")
        
        if vuln_stats["by_type"]:
            print(f"\n  By Type:")
            for vtype, count in sorted(vuln_stats["by_type"].items(), key=lambda x: x[1], reverse=True):
                print(f"    - {vtype}: {count}")
                
        if vuln_stats["by_detector"]:
            print(f"\n  By Detector:")
            for detector, count in sorted(vuln_stats["by_detector"].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    - {detector}: {count}")
                
        perf_stats = summary["performance_stats"]
        print(f"\nPerformance Statistics:")
        print(f"  Total time: {perf_stats['total_time_seconds']:.1f}s")
        print(f"  Average time: {perf_stats['average_time_seconds']:.2f}s")
        print(f"  Max time: {perf_stats['max_time_seconds']:.2f}s")
        print(f"  Average memory: {perf_stats['average_memory_mb']:.1f} MB")
        print(f"  Max memory: {perf_stats['max_memory_mb']:.1f} MB")
        
        error_analysis = summary["error_analysis"]
        if error_analysis["error_types"]:
            print(f"\nError Analysis:")
            for error_type, count in sorted(error_analysis["error_types"].items(), key=lambda x: x[1], reverse=True):
                print(f"  - {error_type}: {count}")
                
        print(f"\n{'='*60}\n")
        
    def save_results(self, output_path: Optional[Path] = None):
        """Save benchmark results to file."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            output_path = Path(__file__).parent / f"benchmark_{timestamp}.json"
            
        summary = self.generate_summary()
        
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            
        print(f"[*] Results saved to {output_path}")
        return output_path
        
    def compare_with_previous(self, previous_path: Path) -> Dict[str, Any]:
        """Compare with previous benchmark results."""
        with open(previous_path, 'r') as f:
            previous = json.load(f)
            
        current = self.generate_summary()
        
        comparison = {
            "current_run": current["metadata"]["start_time"],
            "previous_run": previous["metadata"]["start_time"],
            "changes": {
                "success_rate": {
                    "current": current["overall_stats"]["success_rate"],
                    "previous": previous["overall_stats"]["success_rate"],
                    "delta": current["overall_stats"]["success_rate"] - previous["overall_stats"]["success_rate"]
                },
                "average_time": {
                    "current": current["performance_stats"]["average_time_seconds"],
                    "previous": previous["performance_stats"]["average_time_seconds"],
                    "delta": current["performance_stats"]["average_time_seconds"] - previous["performance_stats"]["average_time_seconds"]
                },
                "total_vulnerabilities": {
                    "current": current["overall_stats"]["total_vulnerabilities"],
                    "previous": previous["overall_stats"]["total_vulnerabilities"],
                    "delta": current["overall_stats"]["total_vulnerabilities"] - previous["overall_stats"]["total_vulnerabilities"]
                }
            },
            "improvements": [],
            "regressions": []
        }
        
        # Check for improvements/regressions
        if comparison["changes"]["success_rate"]["delta"] > 5:
            comparison["improvements"].append(f"Success rate improved by {comparison['changes']['success_rate']['delta']:.1f}%")
        elif comparison["changes"]["success_rate"]["delta"] < -5:
            comparison["regressions"].append(f"Success rate decreased by {abs(comparison['changes']['success_rate']['delta']):.1f}%")
            
        if comparison["changes"]["average_time"]["delta"] < -5:
            comparison["improvements"].append(f"Average analysis time improved by {abs(comparison['changes']['average_time']['delta']):.1f}s")
        elif comparison["changes"]["average_time"]["delta"] > 5:
            comparison["regressions"].append(f"Average analysis time increased by {comparison['changes']['average_time']['delta']:.1f}s")
            
        return comparison


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="IOCTLance Benchmark Runner")
    parser.add_argument("--driver-dir", type=Path, default=Path("/nas4/data/drivers/"),
                       help="Directory containing drivers")
    parser.add_argument("--num-drivers", type=int, default=100,
                       help="Number of drivers to analyze")
    parser.add_argument("--timeout", type=int, default=120,
                       help="Timeout per driver in seconds")
    parser.add_argument("--seed", type=int, default=None,
                       help="Random seed for reproducibility")
    parser.add_argument("--profile", choices=["fast", "balanced", "thorough", "paranoid"],
                       default="balanced", help="Analysis profile")
    parser.add_argument("--output", type=Path, default=None,
                       help="Output file path")
    parser.add_argument("--compare", type=Path, default=None,
                       help="Compare with previous benchmark results")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Check if driver directory exists
    if not args.driver_dir.exists():
        print(f"Error: Driver directory {args.driver_dir} does not exist")
        sys.exit(1)
        
    # Create benchmark runner
    runner = BenchmarkRunner(
        driver_dir=args.driver_dir,
        num_drivers=args.num_drivers,
        timeout=args.timeout,
        seed=args.seed,
        profile=args.profile,
        verbose=args.verbose
    )
    
    # Run benchmark
    try:
        runner.run_benchmark()
        
        # Save results
        output_path = runner.save_results(args.output)
        
        # Compare with previous if specified
        if args.compare and args.compare.exists():
            print(f"\n[*] Comparing with previous results from {args.compare}")
            comparison = runner.compare_with_previous(args.compare)
            
            print(f"\nComparison with Previous Run:")
            print(f"  Previous: {comparison['previous_run']}")
            print(f"  Current: {comparison['current_run']}")
            
            if comparison["improvements"]:
                print(f"\n  Improvements:")
                for improvement in comparison["improvements"]:
                    print(f"    ✓ {improvement}")
                    
            if comparison["regressions"]:
                print(f"\n  Regressions:")
                for regression in comparison["regressions"]:
                    print(f"    ✗ {regression}")
                    
            # Save comparison
            comparison_path = output_path.with_suffix(".comparison.json")
            with open(comparison_path, 'w') as f:
                json.dump(comparison, f, indent=2, default=str)
            print(f"\n[*] Comparison saved to {comparison_path}")
            
    except KeyboardInterrupt:
        print("\n[!] Benchmark interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Benchmark failed: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()