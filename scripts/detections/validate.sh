#!/usr/bin/env bash
# Compile/evaluate detection artifacts only; never load a kernel driver or run
# a KubeDagger technique. Python dependencies must be installed beforehand.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
source scripts/detections/retry.sh
python=${PYTHON:-python3}
"$python" -m unittest discover -s scripts/detections -p 'test_*.py'
falco_image=falcosecurity/falco:0.45.2@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e
plugin=ghcr.io/falcosecurity/plugins/plugin/k8saudit@sha256:ca794b24fee51095579b63b4e8a57030de6e3a8489bcd11d1960aa26a021308f # 0.18.0

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
    echo "Falco validation currently requires Linux x86_64 and Docker" >&2
    exit 1
fi

temp_base=${TMPDIR:-/tmp}
if [[ -d /tmp/opencode && -z ${TMPDIR:-} ]]; then
    temp_base=/tmp/opencode
fi
work=$(mktemp -d "$temp_base/kubedagger-detections.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rules" "$work/plugins" "$work/results"
retry_network curl --fail --silent --show-error --location \
    https://raw.githubusercontent.com/SigmaHQ/sigma-specification/ba9251aa834b11a70dbf80836b453dba99c5159e/json-schema/sigma-detection-rule-schema.json \
    --output "$work/rules/sigma-schema.json"
echo "eb95ddb1bc2503145a6e84511e38990f74fe9a843067065a23d3763457fb2d95  $work/rules/sigma-schema.json" | sha256sum --check
go run ./scripts/detections/export -out "$work/rules"
"$python" scripts/detections/validate.py --rules "$work/rules"

retry_network curl --fail --silent --show-error --location \
    https://github.com/falcosecurity/falcoctl/releases/download/v0.14.3/falcoctl_0.14.3_linux_amd64.tar.gz \
    --output "$work/falcoctl.tar.gz"
echo "263a6c773b4d24af1e6827ea2f63ac7c50678becf58e607390eb8976dee08af1  $work/falcoctl.tar.gz" | sha256sum --check
tar -xzf "$work/falcoctl.tar.gz" -C "$work" falcoctl
retry_network "$work/falcoctl" --config "$work/falcoctl.yaml" artifact install "$plugin" \
    --plugins-dir "$work/plugins" --rulesfiles-dir "$work/rules" \
    --assets-dir "$work/assets" --state-dir "$work/state" --resolve-deps=false

# Fetch artifacts with network access; run validation/replay without network,
# capabilities, host namespaces, host filesystem mounts, or runtime sockets.
retry_network docker pull "$falco_image"
falco=(docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges
    --user "$(id -u):$(id -g)"
    --entrypoint /usr/bin/falco
    --volume "$work/rules:/rules:ro" --volume "$work/plugins:/plugins:ro"
    --volume "$work/results:/results"
    --volume "$PWD/scripts/detections/falco.yaml:/validation.yaml:ro"
    "$falco_image" -c /validation.yaml)
"${falco[@]}" -V /rules/syscall.yaml -V /rules/k8s_audit.yaml > "$work/validation.json"
# Regular-file input terminates at EOF; -M provides a defensive runtime cap.
if ! "${falco[@]}" --enable-source k8s_audit -r /rules/k8s_audit.yaml -M 10 \
    -o stdout_output.enabled=false -o file_output.enabled=true \
    -o file_output.filename=/results/alerts.jsonl \
    > "$work/replay.log" 2>&1; then
    cat "$work/replay.log" >&2
    exit 1
fi
if [[ ! -f "$work/results/alerts.jsonl" ]]; then
    cat "$work/replay.log" >&2
    echo "Falco did not write an alert output file" >&2
    exit 1
fi
"$python" scripts/detections/validate.py --rules "$work/rules" \
    --falco-validation "$work/validation.json" --falco-alerts "$work/results/alerts.jsonl"
