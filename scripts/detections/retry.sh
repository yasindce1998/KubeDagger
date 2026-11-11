#!/usr/bin/env bash
# Retry artifact acquisition only, never rule compilation or fixture assertions.
# Keep digest/checksum/signature verification intact on every attempt.
retry_network() {
    local attempt status log
    log=$(mktemp "${TMPDIR:-/tmp}/kubedagger-network.XXXXXX") || return 1
    for attempt in 1 2 3 4; do
        if "$@" > "$log" 2>&1; then
            cat "$log"
            rm -f -- "$log"
            return 0
        else
            status=$?
        fi
        cat "$log" >&2
        # Match transport diagnostics, not generic failures or verification errors.
        if [[ $attempt == 4 ]] || ! grep -Eiq \
            'response status code (408|429|5[0-9]{2})|returned error: (408|429|5[0-9]{2})|toomanyrequests|Too Many Requests|TLS handshake timeout|connection (reset|timed out)|i/o timeout|net/http: timeout' "$log"; then
            rm -f -- "$log"
            return "$status"
        fi
        echo "Transient artifact download failure; retry $attempt/3 after $((2 ** attempt)) seconds" >&2
        sleep "$((2 ** attempt))"
    done
}
