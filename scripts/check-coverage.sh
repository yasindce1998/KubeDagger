#!/bin/bash
set -uo pipefail

COVERAGE_FILE="${1:-coverage.out}"
THRESHOLD="${2:-20}"

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

# Integer comparison without python dependency; fails closed on parse errors.
PASS=$(awk -v t="$TOTAL" -v th="$THRESHOLD" 'BEGIN { print (t+0 >= th+0) ? 1 : 0 }')

if [ "$PASS" = "1" ]; then
  echo "PASS: coverage ${TOTAL}% >= ${THRESHOLD}%"
  exit 0
else
  echo "FAIL: coverage ${TOTAL}% < ${THRESHOLD}%"
  exit 1
fi
