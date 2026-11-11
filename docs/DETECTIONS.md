# Detection catalog validation

All catalog rules are **experimental hunting signals**, not production-certified
detections. A rule compiling or matching a synthetic event does not prove it will
detect a KubeDagger technique, establish malicious intent, or have an acceptable
false-positive rate in your environment. ATT&CK mappings are research context,
not evidence that every behavior in a technique is covered.

## Run the checks

On Linux x86_64, install Go (the version in `go.mod`), Python 3.11+, Docker,
`curl`, `tar`, and `sha256sum`:

```shell
python3 -m venv .venv-detections
.venv-detections/bin/python -m pip install -r scripts/detections/requirements.txt
PYTHON=.venv-detections/bin/python make test-detections
```

The independent `Detection rules` CI workflow runs the same command. No cluster,
root privileges, eBPF driver, offensive module execution, host PID namespace, or
runtime socket mounts are needed. Docker access is needed to start the offline
validator, but the Falco containers themselves drop all capabilities, disable
network access, and mount only generated rules, fixtures, plugin, config and
a temporary results directory. They run as the invoking user's UID/GID.
Artifact downloads happen before those containers start.

### What is checked

1. `scripts/detections/export` exports the public Go catalog, not a separate copy
   of the rules. It emits individual Sigma/Falco YAML and source-grouped Falco
   rules. Existing client report generation continues to use the same catalog.
2. **Sigma:** the commit/checksum-pinned upstream Sigma JSON schema validates
   metadata, UUIDs and ISO dates. pySigma 2.1.0 parses all 18 rules, including
   condition/modifier syntax. Its SQLite backend 2.1.1 converts each rule to SQL.
   SQLite executes that SQL against all 76 positive/negative fixture cases; no custom
   Sigma evaluator is used. Missing fields become SQL NULL. These checks validate
   the selected backend, not every SIEM backend or its processing pipeline.
3. **Falco:** Falco 0.45.2 compiles all 18 rules, including field names, event
   names, output fields, sources and schema. Compiler/schema warnings fail the check.
   The image is digest-pinned and the k8saudit 0.18.0 artifact is digest-pinned
   and signature-verified by checksum-pinned falcoctl 0.14.3. The container plugin
   bundled with the image supplies `container.*` fields.
4. **Audit replay:** all 24 fixtures for the six Kubernetes audit rules are
   replayed through the real k8saudit source plugin and Falco engine. The exact
   alerts (including unexpected alerts and duplicates) are checked by audit ID.
   Positive and negative cases use the same raw Kubernetes events as Sigma.
5. Normal Go tests enforce source declarations, experimental status and fixture
   coverage, and test exports. They do **not** replace the external checks.

`pkg/detectgen/testdata/events.json` is the fixture source. Kubernetes entries are
synthetic `audit.k8s.io/v1` event fragments; replay adds only envelope metadata.
Other entries are explicitly normalized/enriched source records, not raw auditd
text or syscall captures. Expected matches are recorded next to each event.

## Telemetry contract

The exporter/validator does not ingest or normalize production telemetry. Before
deployment, configure the correct data source, map your fields, and test with
events from your own collectors.

| Source | Required representation / enrichment |
|---|---|
| Kubernetes audit | Preserve `verb`, `stage`, `objectRef.resource`, `objectRef.subresource`, `objectRef.namespace`, and `user.username`. Sigma uses flattened dotted paths; the fixture harness flattens nested objects without renaming fields. Falco uses `source: k8s_audit` and `ka.*` plugin fields. |
| Linux auditd (Sigma) | Decode numeric syscall IDs using the event's architecture into names such as `setns`/`execveat`; normalize `success` to boolean. Supply `exe`, `process_name`, and, where needed, the **target** process name (`target_process`) using external enrichment. `container: "true"`/`"false"` is an enrichment field, not guaranteed in raw audit records. Raw signal arguments need syscall-aware decoding to numeric `signal`. |
| DNS | Supply numeric `query_length` and `source_type: container`. This catalog does not implement rate/entropy aggregation or a DNS parser. |
| File events | Supply absolute `file.path` and `process_name` from actual change events. The rule does not establish whether a file change is malicious. |
| Network events | Supply numeric `destination_port`, `process_name`, `source_namespace`, and `source_type` where referenced. Container/namespace attribution requires enrichment. |
| Proxy | Supply `dst_ip` and path-only `c-uri`. These fields are not Kubernetes audit fields. |
| Firewall | Supply `protocol` and `source_type`; container attribution is external enrichment. |
| Falco syscall | Requires a correctly configured driver and container plugin in production. `proc.is_exe_from_memfd` comes from Falco's executable tracking; it is not equivalent to arbitrary path matching. No live driver is used by CI. |

For audit events, `ResponseComplete` avoids matching the same request again at
`RequestReceived`. Discovery also accepts `ResponseStarted` for long-running
watches. None of these rules filters on a successful response code, so completed
denied requests can match: treat them as **requests/attempts**, not proof that an
object was changed or a token was issued. Audit coverage depends on API-server
audit policy; `Metadata` is sufficient for the implemented audit predicates.

## Evidence and blind spots

| Rules | Evidence in CI | Important limit |
|---|---|---|
| `sa_token`, `k8s_discovery`, `daemonset`, `webhook_deploy`, `crd_backdoor`, `k8s_c2` | Sigma fixture execution **and** real Falco audit replay | Single-event predicates only. Token requests use `resource=serviceaccounts`, `subresource=token`. `k8s_c2` excludes only usernames beginning with `system:`; it does not establish beacon cadence. CRD/webhook creation can be legitimate. |
| Other 12 rules | Sigma normalized-event fixtures; Falco schema/compiler checks | **No syscall trace replay or end-to-end sensor test yet.** Falco and Sigma are complementary views, not guaranteed equivalent predicates. |

Specific limits worth retaining when interpreting reports:

- `escape`: `nsenter` is a userspace command, not a syscall. `setns`/`unshare`
  activity is not itself proof of a successful container escape.
- `dns_exfil`: Sigma selects long names; Falco observes sends to DNS ports.
  Neither implements a volume threshold or proves data exfiltration.
- `memexec`: successful memfd-backed execution is selected; there is no
  `memfd_create` → `execveat` sequence correlation. The Sigma `exe` field requires
  normalization and may not be available in that form from every audit source.
- `cloud_evasion`: Falco's `proc.name` on a kill syscall is the **caller**, and
  `proc.sname` is its session leader, not the target. The Falco rule instead
  observes a security-agent process exiting on SIGKILL/SIGTERM. Sigma's signal
  predicate requires target-process enrichment. Planned restarts can match.
- `antiforensics`: Falco covers deletion/rename only; timestamp syscalls in the
  selected Falco event model do not supply the result/path required by the old
  predicate. Sigma uses a separate normalized audit source for timestamp calls.
- `cicd_poison`: filename and workflow-directory selectors are ORed, not ANDed.
  Write-capable opens (Falco) and file changes (Sigma) are not proof of poisoning.
- `polymorph` and `covert_channel`: bpf()/ICMP activity does not establish
  polymorphism or covert encoding. Bytecode/payload analysis is not implemented.
- `log_tamper`: Falco selects write-capable opens, not every write, truncation,
  or deletion. Path boundaries prevent `/var/log-backup` matching `/var/log/`.

The report's “Additional telemetry / hunting ideas” section is **not executable
rules**. It includes possible cross-source investigations, some requiring
correlation or enriched telemetry. Do not count those ideas as validated coverage.

## Adding or changing a rule

1. Edit `pkg/detectgen/detectgen.go` and provide an explicit Falco source.
2. Add positive and negative fixture cases for the technique, including boundaries
   and missing enrichment. Existing cases should remain unless the intended
   behavior changes and the reason is documented.
3. Run `go test ./pkg/detectgen ./scripts/detections/export` and
   `make test-detections` with the validation virtualenv.
4. Keep `status: experimental`. Production promotion requires real collector
   telemetry, syscall trace replay where applicable, version-specific integration
   testing, false-positive measurement, and documented blind spots beyond this CI.
