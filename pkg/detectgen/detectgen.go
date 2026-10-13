/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package detectgen provides a purple-team catalog that maps KubeDagger
// techniques to the detection artifacts that would catch them: Falco rules,
// Sigma rules, and Kubernetes audit event descriptions. Technique keys match
// events.Event.Technique values emitted by the C2 server.
package detectgen

import (
	"fmt"
	"sort"
	"strings"
)

// Detection describes how a single KubeDagger technique can be detected.
type Detection struct {
	// Technique is the agent module name; it matches events.Event.Technique.
	Technique string
	// MITRE is the ATT&CK technique ID.
	MITRE string
	// Name is a short human-readable detection name.
	Name string
	// Description explains what the detection looks for.
	Description string
	// FalcoRule is a complete, valid Falco rule (YAML).
	FalcoRule string
	// SigmaRule is a complete, valid Sigma rule (YAML).
	SigmaRule string
	// AuditEvents lists Kubernetes audit event descriptions.
	AuditEvents []string
}

// catalog maps technique keys to detection artifacts. Keys must match
// events.Event.Technique values.
var catalog = []Detection{
	{
		Technique:   "sa_token",
		MITRE:       "T1552.001",
		Name:        "ServiceAccount Token Minting",
		Description: "Detects minting of Kubernetes service account tokens via the token request API, used for credential theft and pod identity impersonation.",
		FalcoRule: `- rule: KubeDagger ServiceAccount Token Minting
  desc: Detect creation of service account tokens via the token request API
  condition: ka.verb=create and ka.target.resource=serviceaccounts/token
  output: "ServiceAccount token minted (user=%ka.user.name object=%ka.target.name namespace=%ka.target.namespace)"
  priority: WARNING
  tags: [k8s, credential_access, T1552.001]
`,
		SigmaRule: `title: Kubernetes ServiceAccount Token Minting
id: 3a1c7d92-4b8e-4f2a-9c6d-1e2f3a4b5c6d
status: experimental
description: Detects creation of service account tokens via the token request API
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1552/001/
logsource:
  category: cloud
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: serviceaccounts/token
  condition: selection
falsepositives:
  - Legitimate CI/CD pipelines requesting short-lived tokens
level: medium
tags:
  - attack.credential_access
  - attack.t1552.001
  - attack.execution
`,
		AuditEvents: []string{
			"verb=create resource=serviceaccounts/token user!=system:apiserver",
			"verb=create resource=pods volumeMounts contains serviceaccount-token projected=true",
		},
	},
	{
		Technique:   "k8s_discovery",
		MITRE:       "T1613",
		Name:        "Kubernetes Cluster Discovery",
		Description: "Detects broad enumeration of pods, secrets, nodes, and namespaces that precedes targeting decisions.",
		FalcoRule: `- rule: KubeDagger Kubernetes Cluster Discovery
  desc: Detect bulk enumeration of cluster resources
  condition: (ka.verb=list or ka.verb=watch) and ka.target.resource in (pods, secrets, nodes, namespaces, serviceaccounts)
  output: "Cluster resource enumeration (user=%ka.user.name verb=%ka.verb resource=%ka.target.resource)"
  priority: NOTICE
  tags: [k8s, discovery, T1613]
`,
		SigmaRule: `title: Kubernetes Cluster Resource Enumeration
id: 5b2d8e13-6c9f-4a3b-8d7e-2f3a4b5c6d7e
status: experimental
description: Detects bulk listing or watching of sensitive cluster resources
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1613/
logsource:
  category: cloud
  product: kubernetes
  service: audit
detection:
  selection:
    verb:
      - list
      - watch
    objectRef.resource:
      - pods
      - secrets
      - nodes
      - namespaces
      - serviceaccounts
  condition: selection
falsepositives:
  - Operators and dashboards legitimately listing cluster resources
level: low
tags:
  - attack.discovery
  - attack.t1613
`,
		AuditEvents: []string{
			"verb=list resource in (pods,secrets,nodes,namespaces) response count unusually high",
			"verb=watch resource=secrets user non-system",
		},
	},
	{
		Technique:   "escape",
		MITRE:       "T1611",
		Name:        "Container Escape to Host",
		Description: "Detects namespace/syscall escape primitives executed from inside a container (nsenter, setns, unshare, privileged mounts).",
		FalcoRule: `- rule: KubeDagger Container Escape Attempt
  desc: Detect container breakout primitives executed inside a container
  condition: container and evt.type in (nsenter, setns, unshare)
  output: "Container escape primitive used (proc=%proc.name exe=%proc.exepath type=%evt.type user=%user.name)"
  priority: CRITICAL
  tags: [container, privilege_escalation, T1611]
`,
		SigmaRule: `title: Linux Container Escape Syscalls
id: 7c3e9f24-8d1a-4b5c-9e8f-3a4b5c6d7e8f
status: experimental
description: Detects nsenter, setns, or unshare syscalls executed inside a container
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1611/
logsource:
  category: auditd
  product: linux
detection:
  selection:
    syscall:
      - nsenter
      - setns
      - unshare
    container: "true"
  condition: selection
falsepositives:
  - Container runtimes and sandboxes legitimately entering namespaces
level: high
tags:
  - attack.privilege_escalation
  - attack.t1611
`,
		AuditEvents: []string{
			"verb=create resource=pods privileged=true hostPID=true hostNetwork=true",
			"verb=create resource=pods hostPath volume mount of / or /var/run/docker.sock",
		},
	},
	{
		Technique:   "daemonset",
		MITRE:       "T1610",
		Name:        "Malicious DaemonSet Deployment",
		Description: "Detects creation of DaemonSets, which schedule a pod on every node and are commonly abused for cluster-wide rootkit droppers.",
		FalcoRule: `- rule: KubeDagger Malicious DaemonSet Deployment
  desc: Detect DaemonSet creation outside of expected system namespaces or users
  condition: ka.verb=create and ka.target.resource=daemonsets and not ka.target.namespace in (kube-system, cattle-system)
  output: "DaemonSet created (user=%ka.user.name object=%ka.target.name namespace=%ka.target.namespace)"
  priority: WARNING
  tags: [k8s, persistence, T1610]
`,
		SigmaRule: `title: Kubernetes DaemonSet Creation
id: 9d4f1a35-2e6b-4c7d-8f9a-4b5c6d7e8f9a
status: experimental
description: Detects creation of a DaemonSet outside expected system namespaces
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1610/
logsource:
  category: cloud
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: daemonsets
  filter:
    objectRef.namespace:
      - kube-system
      - cattle-system
  condition: selection and not filter
falsepositives:
  - Daemon installers and node agents deployed by platform teams
level: medium
tags:
  - attack.persistence
  - attack.t1610
`,
		AuditEvents: []string{
			"verb=create resource=daemonsets privileged=true tolerations=Exists",
			"verb=create resource=daemonsets namespace!=kube-system",
		},
	},
	{
		Technique:   "webhook_deploy",
		MITRE:       "T1098",
		Name:        "Admission Webhook Backdoor",
		Description: "Detects creation or modification of mutating/validating webhook configurations, which can inject containers into new pods.",
		FalcoRule: `- rule: KubeDagger Admission Webhook Modification
  desc: Detect creation or modification of admission webhook configurations
  condition: (ka.verb=create or ka.verb=update or ka.verb=patch) and ka.target.resource in (mutatingwebhookconfigurations, validatingwebhookconfigurations)
  output: "Admission webhook configuration modified (user=%ka.user.name object=%ka.target.name resource=%ka.target.resource)"
  priority: CRITICAL
  tags: [k8s, persistence, T1098]
`,
		SigmaRule: `title: Kubernetes Admission Webhook Configuration Change
id: 1e5a2b46-3f7c-4d8e-9a0b-5c6d7e8f9a0b
status: experimental
description: Detects creation or modification of mutating or validating webhook configurations
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1098/
logsource:
  category: cloud
  product: kubernetes
  service: audit
detection:
  selection:
    verb:
      - create
      - update
      - patch
    objectRef.resource:
      - mutatingwebhookconfigurations
      - validatingwebhookconfigurations
  condition: selection
falsepositives:
  - Platform operators installing admission controllers
level: high
tags:
  - attack.persistence
  - attack.t1098
  - attack.defense_evasion
`,
		AuditEvents: []string{
			"verb=create resource=mutatingwebhookconfigurations",
			"verb=patch resource=validatingwebhookconfigurations failurePolicy changed to Ignore",
		},
	},
	{
		Technique:   "crd_backdoor",
		MITRE:       "T1098",
		Name:        "CRD-Based Persistence",
		Description: "Detects registration of custom resource definitions with controller deployments, a persistence mechanism that executes payloads on custom resource events.",
		FalcoRule: `- rule: KubeDagger Custom Resource Definition Backdoor
  desc: Detect CRD creation with unusual group names or broad RBAC
  condition: ka.verb=create and ka.target.resource=customresourcedefinitions
  output: "CustomResourceDefinition created (user=%ka.user.name object=%ka.target.name group=%ka.target.name)"
  priority: WARNING
  tags: [k8s, persistence, T1098]
`,
		SigmaRule: `title: Kubernetes Custom Resource Definition Creation
id: 2f6b3c57-4a8d-4e9f-0b1c-6d7e8f9a0b1c
status: experimental
description: Detects registration of new custom resource definitions that may host backdoor controllers
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1098/
logsource:
  category: cloud
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: customresourcedefinitions
  condition: selection
falsepositives:
  - Operators deploying new CRDs for legitimate controllers
level: medium
tags:
  - attack.persistence
  - attack.t1098
`,
		AuditEvents: []string{
			"verb=create resource=customresourcedefinitions group non-standard",
			"verb=create resource=clusterroles rules wildcard verbs for custom API group",
		},
	},
	{
		Technique:   "dns_exfil",
		MITRE:       "T1048.003",
		Name:        "DNS Exfiltration",
		Description: "Detects unusually large or high-volume DNS traffic from containers, indicating data encoded in query names.",
		FalcoRule: `- rule: KubeDagger DNS Exfiltration
  desc: Detect high-volume DNS traffic from containers
  condition: evt.type in (sendto, sendmsg) and fd.rport in (53, 5353) and container
  output: "DNS traffic from container (proc=%proc.name container=%container.name rip=%fd.rip rport=%fd.rport)"
  priority: WARNING
  tags: [network, exfiltration, T1048.003]
`,
		SigmaRule: `title: High Volume DNS Queries From Container
id: 3a7c4d68-5b9e-4f0a-1c2d-7e8f9a0b1c2d
status: experimental
description: Detects unusually frequent or large DNS queries originating from container workloads
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1048/003/
logsource:
  category: dns
  product: kubernetes
detection:
  selection:
    query_length|gte: 60
    source_type: container
  condition: selection | count(source_ip) > 100 in 1m
falsepositives:
  - Service discovery traffic in large microservice deployments
level: medium
tags:
  - attack.exfiltration
  - attack.t1048.003
`,
		AuditEvents: []string{
			"verb=networkFlow destination port=53 bytes per flow exceeds baseline",
			"CoreDNS log query name length > 60 with high entropy subdomains",
		},
	},
	{
		Technique:   "k8s_c2",
		MITRE:       "T1071.004",
		Name:        "Kubernetes Event C2 Beaconing",
		Description: "Detects beacons hidden in Kubernetes events, configmaps, or container logs used as a DNS/application-layer C2 channel.",
		FalcoRule: `- rule: KubeDagger Kubernetes Event C2 Beacon
  desc: Detect non-system users repeatedly patching events or configmaps
  condition: (ka.verb=create or ka.verb=patch) and ka.target.resource in (events, configmaps) and not ka.user.name startswith system
  output: "Possible C2 over k8s API objects (user=%ka.user.name verb=%ka.verb object=%ka.target.name resource=%ka.target.resource)"
  priority: WARNING
  tags: [k8s, command_and_control, T1071.004]
`,
		SigmaRule: `title: Kubernetes API Object C2 Beaconing
id: 4b8d5e79-6c0f-4a1b-2d3e-8f9a0b1c2d3e
status: experimental
description: Detects repeated create or patch operations on events or configmaps by non-system users
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1071/004/
logsource:
  category: cloud
  product: kubernetes
  service: audit
detection:
  selection:
    verb:
      - create
      - patch
    objectRef.resource:
      - events
      - configmaps
  filter:
    user:
      - system:*
  condition: selection and not filter | count(user) > 30 in 5m
falsepositives:
  - Operators and controllers frequently updating configmaps
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.004
`,
		AuditEvents: []string{
			"verb=patch resource=configmaps high frequency per user",
			"verb=create resource=events reason non-standard with embedded commands",
		},
	},
	{
		Technique:   "memexec",
		MITRE:       "T1055",
		Name:        "Fileless Execution via memfd",
		Description: "Detects anonymous-memory execution using memfd_create and execveat, which leaves no disk artifact.",
		FalcoRule: `- rule: KubeDagger Fileless Execution via memfd
  desc: Detect execveat targeting memfd-backed file descriptors
  condition: 'evt.type in (memfd_create, execveat) and (fd.name startswith memfd: or proc.exepath contains memfd:)'
  output: "Fileless execution (proc=%proc.name exe=%proc.exepath parent=%proc.pname user=%user.name)"
  priority: CRITICAL
  tags: [process, defense_evasion, T1055]
`,
		SigmaRule: `title: Linux memfd_create Fileless Execution
id: 5c9e6f8a-7d1a-4b2c-3e4f-9a0b1c2d3e4f
status: experimental
description: Detects memfd_create followed by execveat, indicating execution from anonymous memory
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1055/
logsource:
  category: auditd
  product: linux
detection:
  selection:
    syscall:
      - memfd_create
      - execveat
    exe|contains: "memfd:"
  condition: selection
falsepositives:
  - Rare legitimate loaders using memfd for in-memory artifacts
level: critical
tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1055
`,
		AuditEvents: []string{
			"auditd syscall=execveat fd points to memfd: backing",
			"auditd syscall=memfd_create followed by execveat same process",
		},
	},
	{
		Technique:   "log_tamper",
		MITRE:       "T1070.002",
		Name:        "Log Tampering",
		Description: "Detects writes, truncation, or deletion of system and container log files to destroy forensic evidence.",
		FalcoRule: `- rule: KubeDagger System Log Tampering
  desc: Detect writes or truncation of system log files
  condition: evt.is_open_write=true and (fd.name startswith /var/log or fd.name startswith /var/lib/docker/containers) and not proc.name in (rsyslogd, journald, docker, containerd)
  output: "Log file tampering (proc=%proc.name file=%fd.name user=%user.name)"
  priority: CRITICAL
  tags: [filesystem, defense_evasion, T1070.002]
`,
		SigmaRule: `title: Linux System Log File Modification
id: 6d0f7a9b-8e2b-4c3d-4f5a-0b1c2d3e4f5a
status: experimental
description: Detects writes to system or container log files by unexpected processes
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1070/002/
logsource:
  category: file_event
  product: linux
detection:
  selection:
    file.path|startswith:
      - /var/log/
      - /var/lib/docker/containers/
  filter:
    process_name:
      - rsyslogd
      - journald
      - docker
      - containerd
  condition: selection and not filter
falsepositives:
  - Log rotation tooling (logrotate, newsyslog)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.002
`,
		AuditEvents: []string{
			"auditd syscall=openat flags=O_TRUNC path under /var/log",
			"auditd syscall=unlink path under /var/log by non-root or unexpected uid",
		},
	},
	{
		Technique:   "antiforensics",
		MITRE:       "T1070",
		Name:        "Anti-Forensics Activity",
		Description: "Detects timestamp manipulation and evidence removal such as unlink, rename, and utimensat against artifacts.",
		FalcoRule: `- rule: KubeDagger Anti-Forensics Artifact Removal
  desc: Detect deletion or timestamp manipulation of files by shell processes
  condition: (evt.type in (unlink, unlinkat, rename, renameat, utimes, utimensat)) and proc.name in (bash, sh, zsh, rm, mv, touch)
  output: "Possible anti-forensics (proc=%proc.name type=%evt.type file=%fd.name user=%user.name)"
  priority: WARNING
  tags: [filesystem, defense_evasion, T1070]
`,
		SigmaRule: `title: Linux File Deletion or Timestomp by Shell
id: 7e1a8b0c-9f3c-4d4e-5a6b-1c2d3e4f5a6b
status: experimental
description: Detects unlink, rename, or timestamp-changing syscalls issued by shell utilities
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1070/
logsource:
  category: auditd
  product: linux
detection:
  selection:
    syscall:
      - unlink
      - unlinkat
      - rename
      - renameat
      - utimensat
    process_name:
      - bash
      - sh
      - zsh
      - rm
      - mv
      - touch
  condition: selection
falsepositives:
  - Routine cleanup scripts deleting temporary files
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070
`,
		AuditEvents: []string{
			"auditd syscall=utimensat followed by no file content change",
			"auditd syscall=unlinkat on files not in temp directories",
		},
	},
	{
		Technique:   "honeypot_detect",
		MITRE:       "T1580",
		Name:        "Honeypot / Deception Fingerprinting",
		Description: "Detects reconnaissance of deception infrastructure such as kubelet read-only port probes and canary token access.",
		FalcoRule: `- rule: KubeDagger Honeypot Reconnaissance
  desc: Detect connections to kubelet ports and canary token paths
  condition: (evt.type=connect and fd.rport in (10250, 10255)) or (evt.is_open_read=true and fd.name contains canary)
  output: "Possible deception-layer recon (proc=%proc.name rip=%fd.rip rport=%fd.rport file=%fd.name)"
  priority: NOTICE
  tags: [network, reconnaissance, T1580]
`,
		SigmaRule: `title: Kubernetes Kubelet Read-Only Port Probe
id: 8f2b9c1d-0a4d-4e5f-6b7c-2d3e4f5a6b7c
status: experimental
description: Detects connections to kubelet ports from unexpected sources, typical of honeypot or cluster fingerprinting
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1580/
logsource:
  category: network_connection
  product: kubernetes
detection:
  selection:
    destination_port:
      - 10250
      - 10255
  filter:
    source_namespace:
      - kube-system
  condition: selection and not filter
falsepositives:
  - Monitoring agents scraping kubelet metrics endpoints
level: low
tags:
  - attack.reconnaissance
  - attack.t1580
`,
		AuditEvents: []string{
			"networkFlow destination port=10255 from non-monitoring pod",
			"verb=get resource=secrets canary token accessed by unexpected user",
		},
	},
	{
		Technique:   "cloud_metadata",
		MITRE:       "T1552.005",
		Name:        "Cloud Metadata Credential Access",
		Description: "Detects access to the cloud instance metadata service (IMDS) at 169.254.169.254 from workloads.",
		FalcoRule: `- rule: KubeDagger Cloud Metadata Access
  desc: Detect connections to the cloud instance metadata service
  condition: evt.type=connect and (fd.rip=169.254.169.254 or fd.rip=fd00:ec2::254)
  output: "IMDS access (proc=%proc.name container=%container.name rip=%fd.rip user=%user.name)"
  priority: CRITICAL
  tags: [network, credential_access, T1552.005]
`,
		SigmaRule: `title: Cloud Instance Metadata Service Access
id: 9a3c0d2e-1b5e-4f6a-7c8d-3e4f5a6b7c8d
status: experimental
description: Detects HTTP requests to the cloud metadata endpoint 169.254.169.254
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1552/005/
logsource:
  category: proxy
detection:
  selection:
    dst_ip: 169.254.169.254
    c-uri|startswith:
      - /latest/meta-data/iam/
      - /computeMetadata/v1/instance/service-accounts/
      - /metadata/instance/
  condition: selection
falsepositives:
  - Cloud agents (AMI helpers) legitimately querying metadata
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
`,
		AuditEvents: []string{
			"networkFlow destination ip=169.254.169.254 from pod without metadata role",
			"egress proxy log uri contains /latest/meta-data/iam/security-credentials",
		},
	},
	{
		Technique:   "cloud_evasion",
		MITRE:       "T1562.001",
		Name:        "Security Tool Impairment",
		Description: "Detects termination or signal attacks against runtime security agents (sensors, probes, shields).",
		FalcoRule: `- rule: KubeDagger Security Agent Kill
  desc: Detect kill signals sent to runtime security agent processes
  condition: evt.type in (kill, tkill, tgkill) and evt.arg.sig in (9, 15) and (proc.name contains sensor or proc.name contains probe or proc.name contains shield or proc.name contains falco)
  output: "Security agent killed (proc=%proc.name target=%proc.exepath sig=%evt.arg.sig user=%user.name)"
  priority: CRITICAL
  tags: [process, defense_evasion, T1562.001]
`,
		SigmaRule: `title: Linux Security Agent Process Termination
id: 0b4d1e3f-2c6a-4a7b-8d9e-4f5a6b7c8d9e
status: experimental
description: Detects SIGKILL or SIGTERM sent to runtime security sensor processes
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  category: auditd
  product: linux
detection:
  selection:
    syscall:
      - kill
      - tkill
      - tgkill
    signal:
      - 9
      - 15
    target_process|contains:
      - sensor
      - probe
      - shield
      - falco
  condition: selection
falsepositives:
  - Planned agent restarts by orchestration tooling
level: critical
tags:
  - attack.defense_evasion
  - attack.t1562.001
`,
		AuditEvents: []string{
			"auditd syscall=kill sig=9 target process name contains sensor or falco",
			"verb=delete resource=daemonsets security agent namespace",
		},
	},
	{
		Technique:   "cicd_poison",
		MITRE:       "T1195",
		Name:        "CI/CD Pipeline Poisoning",
		Description: "Detects modifications to build files, workflows, and supply chain manifests that hijack pipeline execution.",
		FalcoRule: `- rule: KubeDagger CI/CD Pipeline Poisoning
  desc: Detect writes to CI/CD workflow and build definition files
  condition: evt.is_open_write=true and (fd.name endswith .gitlab-ci.yml or fd.name contains .github/workflows or fd.name endswith Dockerfile or fd.name endswith Jenkinsfile)
  output: "CI/CD definition modified (proc=%proc.name file=%fd.name user=%user.name)"
  priority: WARNING
  tags: [filesystem, initial_access, T1195]
`,
		SigmaRule: `title: CI/CD Pipeline Definition Modification
id: 1c5e2f4a-3d7b-4b8c-9e0f-5a6b7c8d9e0f
status: experimental
description: Detects writes to CI/CD workflow or container build definition files
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1195/
logsource:
  category: file_event
  product: linux
detection:
  selection:
    file.name|endswith:
      - .gitlab-ci.yml
      - Dockerfile
      - Jenkinsfile
    file.path|contains:
      - .github/workflows
      - .argo
      - flux
  condition: selection
falsepositives:
  - Developers committing legitimate build definition changes
level: medium
tags:
  - attack.initial_access
  - attack.t1195
  - attack.supply_chain_compromise
`,
		AuditEvents: []string{
			"git push modifying .github/workflows or .gitlab-ci.yml",
			"verb=create resource=customresourcedefinitions fluxcd or argocd application spec changed to attacker repo",
		},
	},
	{
		Technique:   "service_mesh",
		MITRE:       "T1550",
		Name:        "Service Mesh Abuse",
		Description: "Detects direct access to mesh sidecar admin ports or impersonation of mesh service identities.",
		FalcoRule: `- rule: KubeDagger Service Mesh Sidecar Abuse
  desc: Detect connections to service mesh sidecar admin and inbound ports
  condition: evt.type=connect and fd.rport in (15000, 15001, 15006, 15020, 15090) and container and not proc.name in (envoy, istio-proxy, pilot-agent)
  output: "Mesh sidecar port accessed (proc=%proc.name container=%container.name rport=%fd.rport rip=%fd.rip)"
  priority: WARNING
  tags: [network, credential_access, T1550]
`,
		SigmaRule: `title: Service Mesh Sidecar Admin Port Access
id: 2d6f3a5b-4e8c-4c9d-0f1a-6b7c8d9e0f1a
status: experimental
description: Detects connections to Envoy/Istio sidecar admin and inbound ports from unexpected processes
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1550/
logsource:
  category: network_connection
  product: kubernetes
detection:
  selection:
    destination_port:
      - 15000
      - 15001
      - 15006
      - 15090
  filter:
    process_name:
      - envoy
      - istio-proxy
      - pilot-agent
  condition: selection and not filter
falsepositives:
  - Mesh operators debugging sidecar state
level: medium
tags:
  - attack.credential_access
  - attack.t1550
  - attack.lateral_movement
`,
		AuditEvents: []string{
			"networkFlow destination port in (15000,15001,15090) from non-sidecar pod",
			"verb=create resource=customresourcedefinitions networking.istio.io EnvoyFilter modified",
		},
	},
	{
		Technique:   "covert_channel",
		MITRE:       "T1095",
		Name:        "Non-Application Layer Covert Channel",
		Description: "Detects ICMP messaging and other raw-IP encodings (IP ID, TTL, TCP urgent pointer) used for C2.",
		FalcoRule: `- rule: KubeDagger ICMP Covert Channel
  desc: Detect ICMP echo traffic from containers
  condition: evt.type in (sendto, sendmsg) and fd.l4proto=icmp and container
  output: "ICMP from container (proc=%proc.name container=%container.name rip=%fd.rip)"
  priority: WARNING
  tags: [network, command_and_control, T1095]
`,
		SigmaRule: `title: ICMP Traffic From Container Workload
id: 3e7a4b6c-5f9d-4d0e-1a2b-7c8d9e0f1a2b
status: experimental
description: Detects ICMP echo requests originating from container workloads, often abused as a covert C2 channel
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1095/
logsource:
  category: firewall
detection:
  selection:
    protocol: icmp
    source_type: container
  condition: selection
falsepositives:
  - Network diagnostics (ping) executed inside tooling containers
level: medium
tags:
  - attack.command_and_control
  - attack.t1095
`,
		AuditEvents: []string{
			"networkFlow protocol=icmp payload per packet exceeds 64 bytes",
			"firewall log repeated ICMP from single pod exceeding baseline rate",
		},
	},
	{
		Technique:   "polymorph",
		MITRE:       "T1027",
		Name:        "BPF Polymorphism",
		Description: "Detects direct bpf() syscalls and repeated BPF program loads from containers, indicating runtime code mutation to evade signatures.",
		FalcoRule: `- rule: KubeDagger Direct BPF Syscall From Container
  desc: Detect raw bpf syscalls issued inside containers
  condition: evt.type=bpf and container
  output: "Raw bpf syscall from container (proc=%proc.name container=%container.name cmd=%evt.args)"
  priority: CRITICAL
  tags: [syscall, defense_evasion, T1027]
`,
		SigmaRule: `title: Linux BPF Syscall From Container
id: 4f8b5c7d-6a0e-4e1f-2b3c-8d9e0f1a2b3c
status: experimental
description: Detects direct use of the bpf syscall from inside a container, indicating eBPF loading outside the runtime
author: KubeDagger
date: 2026/10/13
references:
  - https://attack.mitre.org/techniques/T1027/
logsource:
  category: auditd
  product: linux
detection:
  selection:
    syscall: bpf
    container: "true"
  condition: selection
falsepositives:
  - Observability agents loading legitimate eBPF programs
level: high
tags:
  - attack.defense_evasion
  - attack.t1027
`,
		AuditEvents: []string{
			"auditd syscall=bpf cmd=BPF_PROG_LOAD from containerized process",
			"auditd repeated bpf syscall with varying program tags same binary",
		},
	},
}

// Catalog returns the full detection catalog in a stable order.
func Catalog() []Detection {
	out := make([]Detection, len(catalog))
	copy(out, catalog)
	return out
}

// Lookup returns the detection mapping for a technique key.
func Lookup(technique string) (Detection, bool) {
	for _, d := range catalog {
		if d.Technique == technique {
			return d, true
		}
	}
	return Detection{}, false
}

// Techniques returns all catalog technique keys, sorted.
func Techniques() []string {
	keys := make([]string, 0, len(catalog))
	for _, d := range catalog {
		keys = append(keys, d.Technique)
	}
	sort.Strings(keys)
	return keys
}

// Generate renders a markdown detection coverage report for the given
// technique keys. Unknown techniques are collected in a gaps section listed
// as having no detection mapping. It returns an error when no techniques are
// requested.
func Generate(techniques []string) (string, error) {
	if len(techniques) == 0 {
		return "", fmt.Errorf("detectgen: no techniques requested")
	}

	var b strings.Builder
	b.WriteString("# KubeDagger Detection Coverage Report\n\n")
	b.WriteString("Purple-team mapping of executed techniques to Falco, Sigma, and Kubernetes audit detections.\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("| Technique | MITRE | Detection |\n")
	b.WriteString("|---|---|---|\n")

	var gaps []string
	for _, t := range techniques {
		d, ok := Lookup(t)
		if !ok {
			gaps = append(gaps, t)
			b.WriteString(fmt.Sprintf("| %s | - | no detection mapping |\n", t))
			continue
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", d.Technique, d.MITRE, d.Name))
	}
	b.WriteString("\n")

	for _, t := range techniques {
		d, ok := Lookup(t)
		if !ok {
			continue
		}
		b.WriteString(fmt.Sprintf("## %s — %s\n\n", d.Technique, d.MITRE))
		b.WriteString(fmt.Sprintf("**%s**\n\n", d.Name))
		b.WriteString(fmt.Sprintf("%s\n\n", d.Description))

		b.WriteString("### Falco rule\n\n")
		b.WriteString("```yaml\n")
		b.WriteString(d.FalcoRule)
		b.WriteString("```\n\n")

		b.WriteString("### Sigma rule\n\n")
		b.WriteString("```yaml\n")
		b.WriteString(d.SigmaRule)
		b.WriteString("```\n\n")

		if len(d.AuditEvents) > 0 {
			b.WriteString("### Kubernetes audit events\n\n")
			for _, a := range d.AuditEvents {
				b.WriteString(fmt.Sprintf("- %s\n", a))
			}
			b.WriteString("\n")
		}
	}

	if len(gaps) > 0 {
		b.WriteString("## Detection gaps\n\n")
		b.WriteString("The following techniques have no detection mapping:\n\n")
		for _, g := range gaps {
			b.WriteString(fmt.Sprintf("- %s\n", g))
		}
		b.WriteString("\n")
	}

	return b.String(), nil
}
