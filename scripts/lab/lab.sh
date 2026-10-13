#!/usr/bin/env bash
# KubeDagger kind-based test lab (see docs/LAB.md).
#
# up   - create the "kubedagger-lab" kind cluster and apply stand-in targets
#        that match the tool's real cloudevasion detection signatures
# down - delete the lab cluster
# test - run cloudevasion detection against the lab cluster and verify the
#        stand-ins are detected (expects at least 6 ACTIVE detections)
set -euo pipefail

CLUSTER_NAME="kubedagger-lab"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Generic detection names every stand-in must trigger (see docs/LAB.md).
EXPECTED_DETECTIONS=(
  cnative-sensor
  cnative-policy
  cnative-net
  cnative-probe
  cnative-registry
  cnative-backup
  cnative-audit
  cnative-scanner
)
MIN_DETECTIONS=6

# Temp kubeconfig used by cmd_test; cleaned up by the EXIT trap (a global is
# required because local variables are gone by the time the trap runs).
TMP_KUBECONFIG=""

cleanup() {
  if [ -n "$TMP_KUBECONFIG" ]; then
    rm -f "$TMP_KUBECONFIG"
  fi
}
trap cleanup EXIT

log() { printf '[lab] %s\n' "$*"; }
err() { printf '[lab] ERROR: %s\n' "$*" >&2; }

require_tools() {
  local tool
  for tool in kind kubectl go; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      err "$tool is required but not installed (see docs/LAB.md for prerequisites)"
      exit 1
    fi
  done
}

cluster_exists() {
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"
}

cmd_up() {
  require_tools

  if cluster_exists; then
    log "kind cluster '$CLUSTER_NAME' already exists, reusing it"
  else
    log "creating kind cluster '$CLUSTER_NAME'"
    kind create cluster --config "$SCRIPT_DIR/kind-config.yaml"
  fi

  log "applying stand-in targets"
  # Freshly created namespaces may not have their default ServiceAccount yet,
  # which makes pod creation fail with "error looking up service account";
  # retrying the (idempotent) apply once resolves it.
  if ! kubectl apply -f "$SCRIPT_DIR/manifests/targets.yaml"; then
    log "retrying apply (waiting for namespace service accounts)"
    sleep 5
    kubectl apply -f "$SCRIPT_DIR/manifests/targets.yaml"
  fi

  log "waiting for pods to become Ready (timeout 120s)"
  kubectl wait --for=condition=Ready pods --all -A --timeout=120s

  log "stand-in pods running:"
  kubectl get pods -A -l kubedagger.lab/standin=true

  log "lab cluster is up; run 'make lab-test' to verify detection"
}

cmd_down() {
  require_tools
  kind delete cluster --name "$CLUSTER_NAME"
}

cmd_test() {
  require_tools

  if ! cluster_exists; then
    err "kind cluster '$CLUSTER_NAME' is not running; run 'make lab-up' first"
    exit 1
  fi

  log "running cloudevasion detection against the lab cluster"
  local report active missing name
  TMP_KUBECONFIG="$(mktemp)"
  kind get kubeconfig --name "$CLUSTER_NAME" > "$TMP_KUBECONFIG"

  report="$(cd "$REPO_ROOT" && go run ./scripts/lab/detect -kubeconfig "$TMP_KUBECONFIG")"
  printf '%s\n' "$report"

  active="$(printf '%s\n' "$report" | grep -c '\[ACTIVE\]' || true)"
  log "$active detection(s) reported ACTIVE"

  missing=0
  for name in "${EXPECTED_DETECTIONS[@]}"; do
    if ! printf '%s\n' "$report" | grep -q "\[ACTIVE\] $name "; then
      err "expected detection '$name' was not reported ACTIVE"
      missing=$((missing + 1))
    fi
  done

  if [ "$active" -lt "$MIN_DETECTIONS" ]; then
    err "expected at least $MIN_DETECTIONS ACTIVE detections, found $active"
    exit 1
  fi
  if [ "$missing" -gt 0 ]; then
    err "$missing expected detection(s) missing from the report"
    exit 1
  fi

  log "OK: all stand-in targets detected"
}

usage() {
  cat <<EOF
Usage: $0 {up|down|test}

  up    create the kind lab cluster and apply stand-in targets
  down  delete the kind lab cluster
  test  verify the stand-ins are detected by cloudevasion detection
EOF
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  test) cmd_test ;;
  *)
    usage
    exit 1
    ;;
esac
