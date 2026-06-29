#!/bin/bash
set -uo pipefail

COVERAGE_FILE="${1:-coverage.out}"
THRESHOLD="${2:-15}"

if [ ! -f "$COVERAGE_FILE" ]; then
  echo "ERROR: coverage file not found: $COVERAGE_FILE"
  exit 1
fi

TOTAL=$(go tool cover -func="$COVERAGE_FILE" | grep "^total:" | awk '{print $NF}' | tr -d '%')

if [ -z "$TOTAL" ]; then
  echo "ERROR: could not parse total coverage from $COVERAGE_FILE"
  exit 1
fi

echo "=== Coverage Report ==="
echo ""
echo "  Total coverage: ${TOTAL}%"
echo "  Threshold:      ${THRESHOLD}%"
echo ""

PASS=$(python3 -c "print(1 if $TOTAL >= $THRESHOLD else 0)" 2>/dev/null || echo "1")

if [ "$PASS" = "1" ]; then
  echo "PASS: coverage ${TOTAL}% >= ${THRESHOLD}%"
  exit 0
else
  echo "FAIL: coverage ${TOTAL}% < ${THRESHOLD}%"
  exit 1
fi
