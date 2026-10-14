# Changelog

## v0.5.0

Purple-team platform release: safety guardrails, structured telemetry, and a full
engagement-reporting pipeline. This is the largest release since the initial
public launch — 101 files changed, ~10,000 lines added.

### Breaking changes

- **Generic `cnative-*` codenames**: vendor and CNCF product names have been
  replaced with generic codenames throughout code, docs, and module arguments
  (`cloud_evasion` action values such as `falco` → `cnative-sensor`,
  `tetragon` → `cnative-probe`, etc.). Scripts that pass the old vendor names
  as module arguments must be updated. Detection signatures (label selectors,
  namespaces, CRD groups) are unchanged, so detection of real deployments
  still works.
- CI coverage gate raised from 14% to 20%.

### New platform features

- **Event telemetry** (`kubedagger-server -events events.jsonl`): structured
  JSONL record of every checkin, task, and result — the authoritative
  engagement record.
- **Scope enforcement** (`-scope scope.yaml`): allow-lists for namespaces,
  domains, and CIDRs; out-of-scope tasks are rejected with a violation list.
- **Malleable C2 profiles** (`-malleable profile.yaml`): configurable beacon
  sleep, jitter, and User-Agent rotation. Jitter and UA selection use
  `crypto/rand`.
- **Operator Web UI** (`-webui 127.0.0.1:8080 -webui-token <tok>`): live
  campaign timeline (`/campaign`), step-through replay (`/replay`), and
  dashboard.
- **Dead-man switch** (`kubedagger-agent -deadman 24h`): agents self-terminate
  if no C2 checkin succeeds within the configured window.
- **Dry-run task argument** (`dryrun=true`): rehearse shell and module tasks
  without side effects.
- **New agent modules**: `sandbox_detect` (gVisor/Kata/container
  fingerprinting), `mesh` (P2P relay — child agents route egress via a parent),
  `hotload` (execute in-memory payloads, with operator-controlled `argv0`).
- **Cloud metadata awareness**: `cloud_evasion` gains cloud provider
  detection (IMDSv2, Azure/GCP endpoints) to inform technique selection.
- **New client technique — `vap_backdoor`**: persistent admission via
  validating admission policy abuse.
- **Detection rule generation** (`kubedagger-client detection generate`):
  emits an 18-technique catalog of detection rules mapped to executed
  techniques — the blue-team deliverable.
- **Engagement reports** (`kubedagger-client report generate`): markdown and
  HTML reports with MITRE mapping and per-agent statistics from the event log.
- **Test lab** (`make lab-up` / `lab-test` / `lab-down`): kind cluster with
  signature-matching stand-ins; `lab-test` asserts all 8 generic detections
  fire. See `docs/LAB.md`.

### Improvements

- Binaries now report their version: `-version` (server, operator, agent) and
  `--version` (kubedagger, kubedagger-client). Release builds are stamped via
  ldflags; previously the stamp was silently dropped.
- `hotload` module: operator-controlled `argv0` argument (plausible process
  name in `ps` output), and non-zero payload exit codes are now reported in
  the task error instead of an empty string.
- Research finding: coreutils on Ubuntu 26.04+ rejects execution from memfd
  (`Security violation: Requested utility ... /memfd: (deleted)`) regardless
  of argv[0] — a userspace anti-fileless-execution control that does not
  affect non-coreutils payloads. The rejection message is added to the
  generated detection catalog as a memfd-exec indicator.
- CI: lint config verification no longer depends on the `golangci-lint.run`
  schema endpoint; Ubuntu 26 runner compatibility verified ahead of the
  October 2026 `ubuntu-latest` migration.
- Coverage 14.0% → 22.2%.

### Documentation

- New: `docs/LAB.md` (lab guide), Use Case 12 (Purple-Team Validation
  Engagement), "Platform Features" section in `USAGE.md`.
- Updated: architecture diagram now depicts the web UI, P2P mesh relay, and
  event stream; all vendor references genericized.

---

## v0.4.0

See the [GitHub release](https://github.com/yasindce1998/KubeDagger/releases) for prior release notes.
