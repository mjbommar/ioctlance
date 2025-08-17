#!/bin/bash
# Run benchmark tests against the full dataset
# This can take a long time (30+ minutes for full dataset)

echo "=========================================="
echo "IOCTLance Dataset Benchmark Test Suite"
echo "=========================================="
echo ""
echo "This will analyze all drivers in the tests/dataset/ folder."
echo "Expected runtime: 30-60 minutes for full dataset"
echo ""

# Create results directory
mkdir -p benchmark_results

# Run benchmark tests with detailed output
echo "Starting benchmark tests..."
uv run pytest tests/integration/test_dataset_benchmark.py \
    -v \
    -s \
    -m benchmark \
    --tb=short \
    --html=benchmark_results/report.html \
    --self-contained-html \
    --json-report \
    --json-report-file=benchmark_results/report.json \
    2>&1 | tee benchmark_results/benchmark_log.txt

echo ""
echo "=========================================="
echo "Benchmark complete!"
echo "Results saved to benchmark_results/"
echo "=========================================="
echo ""
echo "Files generated:"
echo "  - benchmark_results/report.html         (HTML test report)"
echo "  - benchmark_results/report.json         (JSON test results)"
echo "  - benchmark_results/benchmark_log.txt   (Full console output)"
echo "  - benchmark_results/benchmark_report.json (Detailed vulnerability analysis)"
echo ""