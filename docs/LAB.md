# KubeDagger Test Lab

A local [kind](https://kind.sigs.k8s.io/) cluster seeded with lightweight
stand-in workloads that match KubeDagger's **real** cloud-native security
product detection signatures (`pkg/cloudevasion`). It lets you exercise
detection and evasion workflows against a live cluster without installing any
actual security products.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (kind runs the cluster in a container)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
- [Go](https://go.dev/dl/) (for the detection runner, Go >= module version in `go.mod`)

## Quickstart

```shell
make lab-up     # create the "kubedagger-lab" kind cluster + apply stand-ins
make lab-test   # run detection against the cluster, verify stand-ins are found
make lab-down   # delete the cluster
```

`make lab-up` creates a single control-plane node kind cluster named
`kubedagger-lab`, applies `scripts/lab/manifests/targets.yaml`, and waits for
all pods to become Ready.

`make lab-test` runs the detection report against the lab cluster's kubeconfig
and exits non-zero if fewer than 6 detections report ACTIVE or any expected
detection is missing.

Both targets delegate to `scripts/lab/lab.sh`, which also supports direct
invocation: `scripts/lab/lab.sh {up|down|test}`.

## What the stand-ins trigger

Each stand-in is a busybox `sleep infinity` pod whose namespace and labels
match the exact selector a `pkg/cloudevasion` `detect*` function queries:

| Stand-in (namespace / pod name)                             | Generic detection name | Detection signature matched                                        |
| ----------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------ |
| `falco` / `falco-sensor-standin` (label `app=falco`)         | `cnative-sensor`       | `detectCnativeSensor`: pods in ns `falco` with `app=falco`          |
| `kyverno` / `kyverno-standin` (`app.kubernetes.io/name=kyverno`) | `cnative-policy`  | `detectCnativePolicy`: pods in ns `kyverno` with `app.kubernetes.io/name=kyverno` |
| `cilium` / `cilium-agent-standin` (`k8s-app=cilium`)         | `cnative-net`          | `detectCnativeNet`: pods in ns `cilium` with `k8s-app=cilium`       |
| `kube-system` / `tetragon-standin` (`app.kubernetes.io/name=tetragon`) | `cnative-probe` | `detectCnativeProbe`: pods in ns `kube-system` with `app.kubernetes.io/name=tetragon` |
| `harbor` / `harbor-core-standin` (`app=harbor`)              | `cnative-registry`     | `detectCnativeRegistry`: pods in ns `harbor` with `app=harbor`      |
| `velero` / `velero-standin` (`component=velero`)             | `cnative-backup`       | `detectCnativeBackup`: pods in ns `velero` with `component=velero`  |
| `kubescape` / `kubescape-standin` (`app.kubernetes.io/name=kubescape`) | `cnative-audit` | `detectCnativeAudit`: pods in ns `kubescape` with `app.kubernetes.io/name=kubescape` |
| `trivy-system` / `trivy-operator-standin` (`app.kubernetes.io/name=trivy-operator`) | `cnative-scanner` | `detectCnativeScanner`: pods in ns `trivy-system` with `app.kubernetes.io/name=trivy-operator` |

> **Note:** the stand-ins mimic *deployment signatures only* (namespace +
> labels + pod presence). No actual security product runs in the lab cluster,
> so detections fire but there is nothing to evade against. The lab validates
> detection coverage and command plumbing, not evasion effectiveness against
> a real product.

## How detection is invoked

`cloudevasion.DetectSystems` is normally reached through the agent module
system, i.e. via the operator against a connected agent:

```shell
./bin/kubedagger-operator -key $KEY module <agent-id> cloud_evasion action=detect
```

That path requires the full C2 server/operator/agent chain and in-cluster
credentials. To keep the lab lightweight, `make lab-test` runs
`scripts/lab/detect` (via `go run`), a minimal runner that builds kube and
dynamic clients from the lab cluster's kubeconfig and calls the same
`cloudevasion.DetectSystems` + `cloudevasion.FormatSystems` used by the
`cloud_evasion` module, producing the same report:

```shell
kind get kubeconfig --name kubedagger-lab > /tmp/lab-kubeconfig
go run ./scripts/lab/detect -kubeconfig /tmp/lab-kubeconfig
```

Expected output (excerpt):

```
Detection Systems:
  [ACTIVE] cnative-sensor (ns=falco) — 1 pods running
  [ACTIVE] cnative-policy (ns=kyverno) — 1 cnative-policy pods
  ...
```

## Files

| Path                              | Purpose                                                        |
| --------------------------------- | -------------------------------------------------------------- |
| `scripts/lab/kind-config.yaml`    | kind cluster config (name `kubedagger-lab`, 1 control-plane)   |
| `scripts/lab/manifests/targets.yaml` | Stand-in namespaces + pods matching detection signatures    |
| `scripts/lab/lab.sh`              | `up` / `down` / `test` helpers used by the `make lab-*` targets |
| `scripts/lab/detect/main.go`      | Minimal kubeconfig-based runner for `cloudevasion.DetectSystems` |
