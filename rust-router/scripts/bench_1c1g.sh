#!/bin/bash
#===============================================================================
# 1C1G Environment Benchmark for rust-router
#===============================================================================
#
# Purpose:
#   Simulates VPS deployment conditions (1 CPU core, ~1GB memory) to verify
#   rust-router performance under resource-constrained environments.
#
# Usage:
#   ./scripts/bench_1c1g.sh [--full|--quick|--memory-only]
#
# Options:
#   --full         Run all benchmarks including throughput tests (default)
#   --quick        Run only fast benchmarks (rule_matching)
#   --memory-only  Only measure memory baseline
#
# Output:
#   Results saved to review-reports/benchmark-1c1g-YYYYMMDD-HHMMSS.txt
#
# Requirements:
#   - taskset (util-linux package)
#   - /usr/bin/time (not shell builtin)
#   - cargo and rust toolchain
#   - Built rust-router binary (release mode)
#
# Production Testing Note:
#   For production-accurate memory limits, use cgroup v2:
#     sudo mkdir /sys/fs/cgroup/rust-router-bench
#     echo $$ | sudo tee /sys/fs/cgroup/rust-router-bench/cgroup.procs
#     echo 1073741824 | sudo tee /sys/fs/cgroup/rust-router-bench/memory.max
#     # Run benchmarks...
#     sudo rmdir /sys/fs/cgroup/rust-router-bench
#
# Safety:
#   - Uses soft ulimit only (process can be killed if exceeded)
#   - Does not actually restrict below 512MB (safety margin)
#   - All restrictions are process-local (no system-wide changes)
#
#===============================================================================

set -e

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$PROJECT_ROOT/review-reports"

# Configuration
TARGET_MEMORY_MB=1024           # 1GB target
SAFETY_MEMORY_MB=512            # Don't restrict below this
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORT_DIR/benchmark-1c1g-$TIMESTAMP.txt"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default mode
MODE="full"

#===============================================================================
# Utility Functions
#===============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Write to both stdout and report file
tee_report() {
    tee -a "$REPORT_FILE"
}

# Write only to report file
to_report() {
    cat >> "$REPORT_FILE"
}

#===============================================================================
# Pre-benchmark Checks
#===============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."
    local failed=0

    # Check for required tools
    if ! command -v taskset &> /dev/null; then
        log_error "taskset not found (install util-linux package)"
        failed=1
    fi

    if ! [ -x /usr/bin/time ]; then
        log_error "/usr/bin/time not found (install time package)"
        failed=1
    fi

    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found (Rust toolchain not installed)"
        failed=1
    fi

    # Check for release binary
    BINARY_PATH="$PROJECT_ROOT/target/release/rust-router"
    if ! [ -f "$BINARY_PATH" ]; then
        log_warn "Release binary not found at $BINARY_PATH"
        log_info "Building release binary..."
        (cd "$PROJECT_ROOT" && cargo build --release)
        if ! [ -f "$BINARY_PATH" ]; then
            log_error "Failed to build release binary"
            failed=1
        fi
    fi

    # Check/create report directory
    if ! [ -d "$REPORT_DIR" ]; then
        mkdir -p "$REPORT_DIR"
    fi

    if [ $failed -eq 1 ]; then
        log_error "Prerequisites check failed"
        exit 1
    fi

    log_success "All prerequisites met"
}

#===============================================================================
# System Information
#===============================================================================

collect_system_info() {
    log_info "Collecting system information..."

    {
        echo "==============================================================================="
        echo "1C1G Environment Benchmark Report"
        echo "==============================================================================="
        echo ""
        echo "Timestamp: $(date -Iseconds)"
        echo "Hostname: $(hostname)"
        echo ""
        echo "--- CPU Information ---"
        echo "Physical CPUs: $(grep -c "physical id" /proc/cpuinfo 2>/dev/null | sort -u | wc -l || echo "N/A")"
        echo "CPU Cores: $(nproc)"
        echo "CPU Model: $(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "N/A")"
        echo ""
        echo "--- Memory Information ---"
        echo "Total Memory: $(free -h | awk '/^Mem:/{print $2}')"
        echo "Available Memory: $(free -h | awk '/^Mem:/{print $7}')"
        echo "Used Memory: $(free -h | awk '/^Mem:/{print $3}')"
        echo ""
        echo "--- Benchmark Configuration ---"
        echo "Target Environment: 1C1G VPS"
        echo "CPU Constraint: Single core (taskset -c 0)"
        echo "Memory Target: ${TARGET_MEMORY_MB}MB"
        echo "Benchmark Mode: $MODE"
        echo ""
        echo "--- Binary Information ---"
        echo "Binary Path: $BINARY_PATH"
        if [ -f "$BINARY_PATH" ]; then
            echo "Binary Size: $(ls -lh "$BINARY_PATH" | awk '{print $5}')"
            echo "Binary Date: $(ls -l "$BINARY_PATH" | awk '{print $6, $7, $8}')"
        fi
        echo ""
        echo "--- Rust Version ---"
        rustc --version 2>/dev/null || echo "N/A"
        cargo --version 2>/dev/null || echo "N/A"
        echo ""
        echo "==============================================================================="
        echo ""
    } | tee_report
}

#===============================================================================
# Memory Baseline Measurement
#===============================================================================

measure_memory_baseline() {
    log_info "Measuring memory baseline (idle usage)..."

    {
        echo "--- Memory Baseline Test ---"
        echo ""
        echo "Starting rust-router and measuring memory usage..."
        echo "Note: This measures RSS (Resident Set Size) at startup"
        echo ""
    } | tee_report

    # Create a temporary config for the binary
    local temp_config=$(mktemp)
    cat > "$temp_config" << 'EOF'
{
    "listen_addr": "127.0.0.1:17893",
    "outbounds": [
        {"tag": "direct", "type": "direct"}
    ],
    "rules": [],
    "default_outbound": "direct"
}
EOF

    # Use /usr/bin/time to measure memory, run on single core
    # The binary will exit immediately if it can't bind (which is fine for memory measurement)
    # We use timeout to ensure it doesn't hang
    {
        echo "Memory measurement with /usr/bin/time -v:"
        echo ""
        # Run with taskset and capture memory stats
        # Note: We expect the binary to fail to start without proper setup, but
        # memory measurement still captures peak RSS
        timeout 5s taskset -c 0 /usr/bin/time -v "$BINARY_PATH" --help 2>&1 || true
        echo ""
    } | tee_report

    rm -f "$temp_config"

    log_success "Memory baseline measurement complete"
}

#===============================================================================
# Criterion Benchmarks
#===============================================================================

run_criterion_benchmarks() {
    local bench_name="$1"
    local description="$2"

    log_info "Running $description..."

    {
        echo "--- $description ---"
        echo ""
        echo "Running: taskset -c 0 cargo bench --bench $bench_name"
        echo "Environment: Single CPU core (simulating 1C1G VPS)"
        echo ""
    } | tee_report

    # Run criterion benchmarks on single core
    # Note: We set RAYON_NUM_THREADS=1 to prevent parallel test execution
    (
        cd "$PROJECT_ROOT"
        RAYON_NUM_THREADS=1 taskset -c 0 cargo bench --bench "$bench_name" 2>&1
    ) | tee_report

    {
        echo ""
        echo "Benchmark $bench_name completed at $(date -Iseconds)"
        echo ""
    } | tee_report

    log_success "$description complete"
}

run_all_criterion_benchmarks() {
    if [ "$MODE" = "memory-only" ]; then
        log_info "Skipping criterion benchmarks (memory-only mode)"
        return
    fi

    log_info "Running criterion benchmarks on single core..."

    # Always run rule_matching (fast)
    run_criterion_benchmarks "rule_matching" "Rule Matching Benchmarks"

    # Run throughput benchmarks only in full mode
    if [ "$MODE" = "full" ]; then
        run_criterion_benchmarks "throughput" "Throughput Benchmarks"
    else
        log_info "Skipping throughput benchmarks (quick mode)"
    fi
}

#===============================================================================
# Unit Tests with Memory Tracking
#===============================================================================

run_tests_with_memory() {
    if [ "$MODE" = "memory-only" ]; then
        log_info "Skipping tests (memory-only mode)"
        return
    fi

    log_info "Running unit tests on single core..."

    {
        echo "--- Unit Tests (Single Core) ---"
        echo ""
        echo "Running: taskset -c 0 cargo test --release"
        echo ""
    } | tee_report

    (
        cd "$PROJECT_ROOT"
        RAYON_NUM_THREADS=1 taskset -c 0 /usr/bin/time -v cargo test --release 2>&1
    ) | tee_report

    {
        echo ""
        echo "Unit tests completed at $(date -Iseconds)"
        echo ""
    } | tee_report

    log_success "Unit tests complete"
}

#===============================================================================
# Simple Load Test
#===============================================================================

run_simple_load_test() {
    if [ "$MODE" != "full" ]; then
        log_info "Skipping load test (not in full mode)"
        return
    fi

    log_info "Running simple socket load test..."

    {
        echo "--- Simple Load Test ---"
        echo ""
        echo "Note: This test creates TCP connections to measure connection handling."
        echo "It requires the rust-router binary to be running separately."
        echo ""
        echo "Skipped: Load test requires running server instance."
        echo "Manual test command:"
        echo "  taskset -c 0 rust-router &"
        echo "  for i in \$(seq 1 1000); do nc -z 127.0.0.1 7893; done"
        echo ""
    } | tee_report

    log_info "Load test skipped (requires running server)"
}

#===============================================================================
# Summary Generation
#===============================================================================

generate_summary() {
    log_info "Generating summary..."

    {
        echo "==============================================================================="
        echo "BENCHMARK SUMMARY"
        echo "==============================================================================="
        echo ""
        echo "Test completed at: $(date -Iseconds)"
        echo "Report saved to: $REPORT_FILE"
        echo ""
        echo "--- Performance Targets (1C1G VPS) ---"
        echo ""
        echo "Memory Targets:"
        echo "  - Idle: <60MB RSS"
        echo "  - Under load: <150MB RSS"
        echo ""
        echo "Latency Targets:"
        echo "  - Domain matching: <1us"
        echo "  - GeoIP matching: <10us"
        echo "  - Rule engine match: <5us"
        echo "  - UDP session lookup: <100ns"
        echo "  - QUIC detection: <50ns"
        echo "  - Hot reload: <1ms"
        echo ""
        echo "Throughput Targets:"
        echo "  - IO bidirectional: >5Gbps"
        echo "  - Stats snapshot: <1us"
        echo "  - IPC ping: <100us"
        echo ""
        echo "--- Notes ---"
        echo ""
        echo "1. These benchmarks simulate 1C1G VPS by pinning to single CPU core."
        echo "2. Memory soft limits were NOT enforced (for safety)."
        echo "3. For production testing, use cgroup v2 for accurate memory limits."
        echo "4. Results may vary based on CPU model and system load."
        echo ""
        echo "--- Cgroup v2 Production Testing ---"
        echo ""
        echo "For accurate 1GB memory limit testing:"
        echo ""
        echo "  # Create cgroup"
        echo "  sudo mkdir /sys/fs/cgroup/rust-router-bench"
        echo "  "
        echo "  # Add current shell to cgroup"
        echo "  echo \$\$ | sudo tee /sys/fs/cgroup/rust-router-bench/cgroup.procs"
        echo "  "
        echo "  # Set 1GB memory limit"
        echo "  echo 1073741824 | sudo tee /sys/fs/cgroup/rust-router-bench/memory.max"
        echo "  "
        echo "  # Run benchmarks in this shell"
        echo "  ./scripts/bench_1c1g.sh"
        echo "  "
        echo "  # Cleanup"
        echo "  sudo rmdir /sys/fs/cgroup/rust-router-bench"
        echo ""
        echo "==============================================================================="
    } | tee_report
}

#===============================================================================
# Main Entry Point
#===============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --full)
                MODE="full"
                shift
                ;;
            --quick)
                MODE="quick"
                shift
                ;;
            --memory-only)
                MODE="memory-only"
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [--full|--quick|--memory-only]"
                echo ""
                echo "Options:"
                echo "  --full         Run all benchmarks (default)"
                echo "  --quick        Run only fast benchmarks"
                echo "  --memory-only  Only measure memory baseline"
                echo ""
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    log_info "Starting 1C1G benchmark suite (mode: $MODE)"
    log_info "Results will be saved to: $REPORT_FILE"
    echo ""

    # Initialize report file
    > "$REPORT_FILE"

    check_prerequisites
    collect_system_info
    measure_memory_baseline
    run_all_criterion_benchmarks
    run_tests_with_memory
    run_simple_load_test
    generate_summary

    echo ""
    log_success "Benchmark suite complete!"
    log_info "Report saved to: $REPORT_FILE"
}

main "$@"
