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

package mitre

// Technique represents a single MITRE ATT&CK technique
type Technique struct {
	ID          string   `json:"techniqueID"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Score       int      `json:"score"`
	Color       string   `json:"color"`
	Comment     string   `json:"comment"`
	Enabled     bool     `json:"enabled"`
	Metadata    []string `json:"metadata,omitempty"`
}

// NavigatorLayer represents an ATT&CK Navigator layer file
type NavigatorLayer struct {
	Name        string      `json:"name"`
	Versions    Versions    `json:"versions"`
	Domain      string      `json:"domain"`
	Description string      `json:"description"`
	Filters     Filters     `json:"filters"`
	Sorting     int         `json:"sorting"`
	Layout      Layout      `json:"layout"`
	HideDisable bool        `json:"hideDisabled"`
	Techniques  []Technique `json:"techniques"`
	Gradient    Gradient    `json:"gradient"`
	LegendItems []Legend    `json:"legendItems"`
}

type Versions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

type Filters struct {
	Platforms []string `json:"platforms"`
}

type Layout struct {
	Layout       string `json:"layout"`
	AggregateF   string `json:"aggregateFunction"`
	ShowID       bool   `json:"showID"`
	ShowName     bool   `json:"showName"`
	ShowAggreg   bool   `json:"showAggregateScores"`
	CountUnscor  bool   `json:"countUnscored"`
}

type Gradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type Legend struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

var techniques = []Technique{
	{
		ID:          "T1525",
		Name:        "Implant Internal Image",
		Tactic:      "persistence",
		Description: "Docker image override, admission webhook injection, CRI-level image tampering",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1046",
		Name:        "Network Service Scanning",
		Tactic:      "discovery",
		Description: "Passive flow monitoring and active SYN scanning via XDP/TC",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1005",
		Name:        "Data from Local System",
		Tactic:      "collection",
		Description: "File content exfiltration via eBPF read hooks and fs_watch mechanism",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1055",
		Name:        "Process Injection",
		Tactic:      "privilege-escalation",
		Description: "Pipe program injection — intercepts stdin between processes via dup2/pipe hooks",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1071.004",
		Name:        "Application Layer Protocol: DNS",
		Tactic:      "command-and-control",
		Description: "DNS response manipulation and DNS-based data exfiltration",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1564.001",
		Name:        "Hide Artifacts: Hidden Files and Directories",
		Tactic:      "defense-evasion",
		Description: "Process and file hiding via getdents64 manipulation and /proc concealment",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1003",
		Name:        "OS Credential Dumping",
		Tactic:      "credential-access",
		Description: "PostgreSQL credential interception via uprobe on md5_crypt_verify",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1053.003",
		Name:        "Scheduled Task/Job: Cron",
		Tactic:      "persistence",
		Description: "Auto-reinstall via systemd service or cron @reboot entry",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1014",
		Name:        "Rootkit",
		Tactic:      "defense-evasion",
		Description: "eBPF-based rootkit — hides from /proc, manipulates syscall returns, blocks kmsg",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1205",
		Name:        "Traffic Signaling",
		Tactic:      "command-and-control",
		Description: "C2 commands encoded in HTTP User-Agent headers, intercepted by XDP",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1557",
		Name:        "Adversary-in-the-Middle",
		Tactic:      "collection",
		Description: "XDP ingress and TC egress packet interception and injection",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1611",
		Name:        "Escape to Host",
		Tactic:      "privilege-escalation",
		Description: "Container escape chaining — privileged nsenter, docker socket, cgroup release_agent, overlayFS",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1082",
		Name:        "System Information Discovery",
		Tactic:      "discovery",
		Description: "Process tree monitoring via sched_process_fork tracepoint",
		Score:       80,
		Color:       "#ff9933",
		Enabled:     true,
	},
	{
		ID:          "T1071.001",
		Name:        "Application Layer Protocol: Web Protocols",
		Tactic:      "command-and-control",
		Description: "HTTP-based C2 with custom routing and response injection",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1562.001",
		Name:        "Impair Defenses: Disable or Modify Tools",
		Tactic:      "defense-evasion",
		Description: "Runtime evasion — hides from Falco/Tetragon/KubeArmor, blocks kmsg readers",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1106",
		Name:        "Native API",
		Tactic:      "execution",
		Description: "Direct BPF syscall usage for program loading and map operations",
		Score:       80,
		Color:       "#ff9933",
		Enabled:     true,
	},
	{
		ID:          "T1552.005",
		Name:        "Unsecured Credentials: Cloud Instance Metadata API",
		Tactic:      "credential-access",
		Description: "Queries IMDS endpoints (169.254.169.254) to steal IAM/GCP/Azure credentials",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1078.004",
		Name:        "Valid Accounts: Cloud Accounts",
		Tactic:      "privilege-escalation",
		Description: "K8s API abuse using stolen service account tokens — RBAC enumeration and escalation",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1552.001",
		Name:        "Unsecured Credentials: Credentials In Files",
		Tactic:      "credential-access",
		Description: "Harvests secrets from SA tokens, kubeconfig, cloud CLI configs, Vault tokens, env vars",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1528",
		Name:        "Steal Application Access Token",
		Tactic:      "credential-access",
		Description: "Steals K8s service account tokens, Docker registry auth, Vault tokens",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1599.001",
		Name:        "Network Boundary Bridging: Network Address Translation Traversal",
		Tactic:      "defense-evasion",
		Description: "XDP-level packet rewriting bypasses CNI network policies (Calico/Cilium TC enforcement)",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1090.004",
		Name:        "Proxy: Domain Fronting",
		Tactic:      "command-and-control",
		Description: "Service mesh bypass — XDP direct send skips Istio/Envoy sidecar redirect",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1537",
		Name:        "Transfer Data to Cloud Account",
		Tactic:      "exfiltration",
		Description: "Exfiltrates data to attacker-controlled S3/GCS/Azure Blob using stolen credentials",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1565.002",
		Name:        "Data Manipulation: Transmitted Data Manipulation",
		Tactic:      "impact",
		Description: "Observability poisoning — injects false metrics/traces into Prometheus, OTel, StatsD",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1053.007",
		Name:        "Scheduled Task/Job: Container Orchestration Job",
		Tactic:      "persistence",
		Description: "DaemonSet dropper spreads rootkit across all cluster nodes via privileged pods",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1040",
		Name:        "Network Sniffing",
		Tactic:      "credential-access",
		Description: "TLS interception via SSL_read/SSL_write uprobes captures plaintext before encryption",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1552.004",
		Name:        "Unsecured Credentials: Private Keys",
		Tactic:      "credential-access",
		Description: "Etcd credential theft intercepts gRPC traffic to steal secrets, tokens, and client certificates",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1555.005",
		Name:        "Credentials from Password Stores: Password Managers",
		Tactic:      "credential-access",
		Description: "Kernel keyring theft steals encryption keys, Kerberos tickets, and eCryptfs keys via KEYCTL_READ interception",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1070.002",
		Name:        "Indicator Removal: Clear Linux or Mac System Logs",
		Tactic:      "defense-evasion",
		Description: "Log tampering hooks vfs_write and journald to drop, modify, or inject log entries in real-time",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1562.006",
		Name:        "Impair Defenses: Indicator Blocking",
		Tactic:      "defense-evasion",
		Description: "Syscall bypass hooks getdents64, stat, and /proc reads to hide PIDs, files, and network ports",
		Score:       100,
		Color:       "#ff6666",
		Enabled:     true,
	},
	{
		ID:          "T1620",
		Name:        "Reflective Code Loading",
		Tactic:      "execution",
		Description: "Fileless execution via memfd_create and execveat — no disk artifact, spoofed /proc/self/exe",
		Score:       95,
		Color:       "#ff3333",
		Enabled:     true,
	},
	{
		ID:          "T1572",
		Name:        "Protocol Tunneling",
		Tactic:      "command-and-control",
		Description: "Covert channels via ICMP payload, IPv4 ID field, TCP urgent pointer, or IP TTL encoding",
		Score:       90,
		Color:       "#ff9933",
		Enabled:     true,
	},
	{
		ID:          "T1557.002",
		Name:        "ARP Cache Poisoning",
		Tactic:      "credential-access",
		Description: "XDP-based gratuitous ARP injection to MITM pod-to-pod traffic within the cluster network",
		Score:       85,
		Color:       "#ff6633",
		Enabled:     true,
	},
	{
		ID:          "T1609",
		Name:        "Container Administration Command",
		Tactic:      "execution",
		Description: "Kubelet API abuse via stolen node credentials to exec in pods and dump secrets",
		Score:       90,
		Color:       "#ff3366",
		Enabled:     true,
	},
	{
		ID:          "T1195.002",
		Name:        "Compromise Software Supply Chain",
		Tactic:      "initial-access",
		Description: "OCI manifest manipulation and layer injection to compromise container image supply chain",
		Score:       95,
		Color:       "#cc0000",
		Enabled:     true,
	},
	{
		ID:          "T1550.001",
		Name:        "Use Alternate Authentication Material: Application Access Token",
		Tactic:      "credential-access",
		Description: "Service account token minting and pod identity theft via projected volume stealing",
		Score:       85,
		Color:       "#ff6600",
		Enabled:     true,
	},
	{
		ID:          "T1553.006",
		Name:        "Code Signing Policy Modification",
		Tactic:      "defense-evasion",
		Description: "Bypass Sigstore/Cosign image signature verification via policy modification or signature injection",
		Score:       80,
		Color:       "#ff9900",
		Enabled:     true,
	},
}

// GetTechniques returns all mapped MITRE ATT&CK techniques
func GetTechniques() []Technique {
	return techniques
}
