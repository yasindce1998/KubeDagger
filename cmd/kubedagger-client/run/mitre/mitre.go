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
		Description: "Docker image override via eBPF LPM trie — replaces container images at runtime",
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
		Description: "Container-aware file watching with in-container path resolution",
		Score:       80,
		Color:       "#ff9933",
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
		Description: "Blocks kmsg readers to prevent kernel log visibility of eBPF activity",
		Score:       80,
		Color:       "#ff9933",
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
}

// GetTechniques returns all mapped MITRE ATT&CK techniques
func GetTechniques() []Technique {
	return techniques
}
