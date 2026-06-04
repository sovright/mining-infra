#!/bin/bash
set -e

echo "============================================"
echo "Fiber-Zcash Test Suite"
echo "============================================"
echo ""

# Track results
passed=0
failed=0

run_test() {
    local name=$1
    shift
    local cmd="$@"

    printf "Running %-30s " "$name..."
    if $cmd > /tmp/test_output.txt 2>&1; then
        echo "PASSED"
        ((passed++)) || true
    else
        echo "FAILED"
        echo "  Last 10 lines of output:"
        tail -10 /tmp/test_output.txt | sed 's/^/    /'
        ((failed++)) || true
    fi
}

echo "=== Layer 0: Unit Tests ==="
run_test "Unit tests" cargo test --lib

echo ""
echo "=== Layer 1: Integration Tests ==="
run_test "Compact block integration" cargo test --test integration
run_test "FEC integration" cargo test --test fec_integration
run_test "Relay integration" cargo test --test relay_integration

echo ""
echo "=== Layer 2: E2E Tests ==="
run_test "E2E pipeline" cargo test --test e2e_test

echo ""
echo "=== Layer 3: Stress Tests ==="
run_test "Stress tests" cargo test --test stress_test

echo ""
echo "=== Layer 4: Pre-deployment Gates ==="
run_test "Pre-deploy gates" cargo test --test predeploy_test

echo ""
echo "=== Additional Tests ==="
run_test "Fixtures tests" cargo test --test fixtures_test
run_test "Harness tests" cargo test --test harness_test

echo ""
echo "============================================"
echo "Summary"
echo "============================================"
echo "Passed: $passed"
echo "Failed: $failed"
echo ""

if [ $failed -gt 0 ]; then
    echo "TEST SUITE FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
