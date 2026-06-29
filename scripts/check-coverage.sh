#!/bin/bash
set -euo pipefail

COVERAGE_FILE="${1:-coverage.out}"
THRESHOLD="${2:-60}"

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
go tool cover -func="$COVERAGE_FILE" | grep -v "^total:" | awk '$NF != "0.0%" {print "  " $0}' | head -50
echo ""
echo "  Total coverage: ${TOTAL}%"
echo "  Threshold:      ${THRESHOLD}%"
echo ""

PASS=$(echo "$TOTAL >= $THRESHOLD" | bc -l 2>/dev/null || python3 -c "print(1 if $TOTAL >= $THRESHOLD else 0)")

if [ "$PASS" = "1" ]; then
  echo "PASS: coverage ${TOTAL}% >= ${THRESHOLD}%"
  exit 0
else
  echo "FAIL: coverage ${TOTAL}% < ${THRESHOLD}%"
  exit 1
fi
