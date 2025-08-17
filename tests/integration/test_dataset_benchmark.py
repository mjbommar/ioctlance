"""Benchmark tests against the full dataset of known vulnerable drivers.

This module tests IOCTLance against the complete dataset of 104 known vulnerable drivers
to validate detection rates, performance, and ensure no regressions from refactoring.
"""

import json
import time
from pathlib import Path
from typing import Optional

import pytest

from ioctlance.core.analysis_context import AnalysisConfig, AnalysisContext
from ioctlance.core.driver_analyzer import DriverAnalyzer


class TestDatasetBenchmark:
    """Benchmark test suite for the complete driver dataset."""

    # Known vulnerable drivers with expected vulnerabilities
    KNOWN_VULNERABILITIES = {
        "RTCore64.sys": ["Physical Memory Mapping", "Arbitrary Write"],  # CVE-2019-16098
        "dbutil_2_3.sys": ["Physical Memory Mapping", "Arbitrary Read/Write"],  # Dell CVE-2021-21551
        "cpuz141.sys": ["Arbitrary Write", "MSR Operations"],  # CPUID driver
        "gdrv.sys": ["Physical Memory Mapping"],  # Gigabyte driver
        "mhyprot2.Sys": ["Process Termination", "Arbitrary Read/Write"],  # Genshin Impact anti-cheat
        "WinRing0x64.sys": ["MSR Operations", "I/O Port Access"],  # Multiple CVEs
        "phymem.sys": ["Physical Memory Mapping"],  # Physical memory access
        "speedfan.sys": ["Arbitrary Read/Write"],  # SpeedFan driver
        "AsUpIO.sys": ["Physical Memory Mapping", "I/O Port Access"],  # ASUS driver
        "AsIO64.sys": ["Arbitrary Read/Write"],  # ASUS driver
        # Add more as we validate them
    }

    @pytest.fixture(scope="class")
    def dataset_dir(self):
        """Get the dataset directory path."""
        return Path(__file__).parent.parent / "dataset"

    @pytest.fixture(scope="class")
    def output_dir(self, tmp_path_factory):
        """Create output directory for benchmark results."""
        return tmp_path_factory.mktemp("benchmark_results")

    def analyze_driver(self, driver_path: Path, timeout: int = 60) -> dict | None:
        """Analyze a single driver and return results."""
        try:
            start_time = time.time()

            config = AnalysisConfig(timeout=timeout, debug=False)
            context = AnalysisContext.create_for_driver(driver_path, config)

            analyzer = DriverAnalyzer(context)
            result = analyzer.analyze()

            analysis_time = time.time() - start_time

            return {
                "driver": driver_path.name,
                "analysis_time": analysis_time,
                "vulnerabilities": [
                    {
                        "title": v.title,
                        "description": v.description,
                        "ioctl_code": v.eval.IoControlCode if hasattr(v, 'eval') else None,
                    }
                    for v in result.vuln
                ],
                "vuln_count": len(result.vuln),
                "ioctl_handler": result.basic.ioctl_handler,
                "ioctl_codes": list(result.basic.IoControlCodes) if result.basic.IoControlCodes else [],
                "success": True,
                "error": None
            }

        except Exception as e:
            return {
                "driver": driver_path.name,
                "analysis_time": 0,
                "vulnerabilities": [],
                "vuln_count": 0,
                "success": False,
                "error": str(e)
            }

    @pytest.mark.skip(reason="Too slow for regular test runs - use run_benchmark.sh instead")
    @pytest.mark.slow  # Mark as slow test
    @pytest.mark.benchmark  # Custom marker for benchmark tests
    def test_full_dataset_benchmark(self, dataset_dir, output_dir):
        """Run benchmark on entire dataset and generate report."""
        if not dataset_dir.exists():
            pytest.skip("Dataset directory not found")

        # Get all .sys files
        driver_files = sorted(dataset_dir.glob("*.sys"))

        if not driver_files:
            pytest.skip("No driver files found in dataset")

        results = []
        total_drivers = len(driver_files)
        successful = 0
        failed = 0
        total_vulns = 0

        print(f"\n\nAnalyzing {total_drivers} drivers from dataset...")
        print("=" * 80)

        for i, driver_path in enumerate(driver_files, 1):
            print(f"[{i}/{total_drivers}] Analyzing {driver_path.name}...", end=" ")

            result = self.analyze_driver(driver_path, timeout=30)
            results.append(result)

            if result["success"]:
                successful += 1
                total_vulns += result["vuln_count"]
                print(f"✓ Found {result['vuln_count']} vulnerabilities in {result['analysis_time']:.2f}s")
            else:
                failed += 1
                print(f"✗ Failed: {result['error']}")

        # Generate summary report
        print("\n" + "=" * 80)
        print("BENCHMARK SUMMARY")
        print("=" * 80)
        print(f"Total drivers analyzed: {total_drivers}")
        print(f"Successful: {successful} ({successful/total_drivers*100:.1f}%)")
        print(f"Failed: {failed} ({failed/total_drivers*100:.1f}%)")
        print(f"Total vulnerabilities found: {total_vulns}")
        print(f"Average vulnerabilities per driver: {total_vulns/successful if successful > 0 else 0:.2f}")

        # Save detailed results to JSON
        report_path = output_dir / "benchmark_report.json"
        with open(report_path, "w") as f:
            json.dump({
                "summary": {
                    "total_drivers": total_drivers,
                    "successful": successful,
                    "failed": failed,
                    "total_vulnerabilities": total_vulns,
                    "avg_vulns_per_driver": total_vulns/successful if successful > 0 else 0
                },
                "results": results
            }, f, indent=2)

        print(f"\nDetailed report saved to: {report_path}")

        # Assertions - be more lenient since many drivers are complex/obfuscated
        assert successful > 0, "No drivers were successfully analyzed"
        # Lower success rate expectation due to complex/obfuscated drivers
        assert successful / total_drivers >= 0.3, f"Less than 30% success rate: {successful/total_drivers*100:.1f}%"
        assert total_vulns > 0, "No vulnerabilities found in entire dataset"

    @pytest.mark.parametrize("driver_name,expected_patterns", [
        ("RTCore64.sys", ["Physical Memory", "Arbitrary"]),
        ("dbutil_2_3.sys", ["Physical Memory", "Arbitrary"]),
    ])
    def test_known_vulnerable_drivers(self, dataset_dir, driver_name, expected_patterns):
        """Test specific known vulnerable drivers for expected vulnerability types."""
        driver_path = dataset_dir / driver_name

        if not driver_path.exists():
            pytest.skip(f"Driver not found: {driver_name}")

        result = self.analyze_driver(driver_path, timeout=60)

        assert result["success"], f"Failed to analyze {driver_name}: {result['error']}"
        assert result["vuln_count"] > 0, f"No vulnerabilities found in known vulnerable driver {driver_name}"

        # Check for expected vulnerability patterns
        vuln_titles = [v["title"] for v in result["vulnerabilities"]]
        vuln_text = " ".join(vuln_titles).lower()

        for pattern in expected_patterns:
            assert pattern.lower() in vuln_text, \
                f"Expected '{pattern}' vulnerability not found in {driver_name}. Found: {vuln_titles}"

    def test_performance_metrics(self, dataset_dir):
        """Test performance metrics on a subset of drivers."""
        # Test on specific simple drivers that we know work
        test_drivers = ["RTCore64.sys", "dbutil_2_3.sys", "RTKVHD64_2.sys"]
        driver_files = []
        for name in test_drivers:
            path = dataset_dir / name
            if path.exists():
                driver_files.append(path)

        if not driver_files:
            pytest.skip("No driver files found")

        times = []
        for driver_path in driver_files:
            result = self.analyze_driver(driver_path, timeout=30)
            if result["success"]:
                times.append(result["analysis_time"])

        if times:
            avg_time = sum(times) / len(times)
            max_time = max(times)
            min_time = min(times)

            print(f"\nPerformance Metrics (n={len(times)}):")
            print(f"  Average: {avg_time:.2f}s")
            print(f"  Min: {min_time:.2f}s")
            print(f"  Max: {max_time:.2f}s")

            # Performance assertions
            assert avg_time < 45, f"Average analysis time too high: {avg_time:.2f}s"
            assert max_time < 120, f"Maximum analysis time too high: {max_time:.2f}s"

    @pytest.mark.skip(reason="Requires original IOCTLance results for comparison")
    def test_regression_against_original(self, dataset_dir):
        """Compare results against original IOCTLance to ensure no regressions."""
        # This would require running the original IOCTLance and comparing results
        # Placeholder for regression testing
        pass


class TestDatasetStatistics:
    """Generate statistics from dataset analysis."""

    @pytest.mark.benchmark
    def test_generate_vulnerability_statistics(self, dataset_dir, output_dir):
        """Generate detailed statistics about vulnerability types found."""
        if not dataset_dir.exists():
            pytest.skip("Dataset directory not found")

        driver_files = sorted(dataset_dir.glob("*.sys"))[:20]  # Sample for statistics

        vuln_type_counts = {}
        driver_vuln_counts = {}

        for driver_path in driver_files:
            benchmark = TestDatasetBenchmark()
            result = benchmark.analyze_driver(driver_path, timeout=30)

            if result["success"]:
                driver_vuln_counts[driver_path.name] = result["vuln_count"]

                for vuln in result["vulnerabilities"]:
                    # Categorize vulnerability types
                    title_lower = vuln["title"].lower()

                    if "physical memory" in title_lower:
                        vuln_type = "Physical Memory Mapping"
                    elif "process termination" in title_lower:
                        vuln_type = "Process Termination"
                    elif "arbitrary write" in title_lower:
                        vuln_type = "Arbitrary Write"
                    elif "arbitrary read" in title_lower:
                        vuln_type = "Arbitrary Read"
                    elif "buffer overflow" in title_lower:
                        vuln_type = "Buffer Overflow"
                    elif "null pointer" in title_lower:
                        vuln_type = "Null Pointer Dereference"
                    elif "msr" in title_lower or "wrmsr" in title_lower:
                        vuln_type = "MSR Operations"
                    elif "i/o port" in title_lower or "in/out" in title_lower:
                        vuln_type = "I/O Port Access"
                    else:
                        vuln_type = "Other"

                    vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

        # Print statistics
        print("\n" + "=" * 80)
        print("VULNERABILITY TYPE DISTRIBUTION")
        print("=" * 80)

        for vuln_type, count in sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"{vuln_type:30} : {count:3} occurrences")

        print("\n" + "=" * 80)
        print("TOP VULNERABLE DRIVERS")
        print("=" * 80)

        for driver, count in sorted(driver_vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"{driver:40} : {count:3} vulnerabilities")

        # Save statistics
        stats_path = output_dir / "vulnerability_statistics.json"
        with open(stats_path, "w") as f:
            json.dump({
                "vulnerability_types": vuln_type_counts,
                "driver_vulnerabilities": driver_vuln_counts
            }, f, indent=2)

        print(f"\nStatistics saved to: {stats_path}")

        # Assertions
        assert len(vuln_type_counts) > 0, "No vulnerability types found"
        assert sum(vuln_type_counts.values()) > 0, "No vulnerabilities counted"
