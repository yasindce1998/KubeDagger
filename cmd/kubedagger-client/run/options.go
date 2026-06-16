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

package run

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	LogLevel logrus.Level
	Target   string
	From     string
	To       string
	// fs_watch options
	InContainer bool
	Active      bool
	Output      string
	// pipe_prog options
	Backup bool
	// docker options
	Override int
	Ping     int
	// postgres options
	Role   string
	Secret string
	// network discovery scan
	IP               string
	Port             string
	Range            string
	ActiveDiscovery  bool
	PassiveDiscovery bool
	// mitre options
	MitreFormat string
	// dashboard options
	RefreshRate int
	// dns exfil options
	ExfilFile   string
	ExfilDomain string
	DNSServer   string
	// k8s options
	K8sNamespace string
	// cloud meta options
	CloudProvider string
	// k8s abuse options
	K8sAction string
	K8sToken  string
	// secret harvest options
	SecretSources string
	// escape options
	EscapeAction    string
	EscapeTechnique string
	// evasion options
	EvasionMode string
	// network bypass options
	BypassMode string
	DestIP     string
	DestPort   string
	// mesh bypass options
	MeshBypassMode string
	MeshTarget     string
	// cloud exfil options
	ExfilProvider  string
	ExfilBucket    string
	ExfilPath      string
	ExfilCredsFrom string
	// observability poisoning options
	PoisonTarget   string
	PoisonEndpoint string
	PoisonStrategy string
	// webhook backdoor options
	WebhookAction    string
	WebhookNamespace string
	WebhookImage     string
	// CRI tamper options
	CRIRuntime      string
	CRIMode         string
	CRITargetImage  string
	CRIInjectBinary string
	// DaemonSet dropper options
	DaemonSetAction string
	DaemonSetImage  string
	DaemonSetName   string
	// kernel keyring theft options
	KeyringMode    string
	KeyringKeyType string
	// TLS interception options
	TLSAction    string
	TLSTargetPID string
	TLSLib       string
	// etcd theft options
	EtcdMode      string
	EtcdKeyPrefix string
	// log tamper options
	LogTamperMode    string
	LogTamperPattern string
	LogTamperTarget  string
	// syscall bypass options
	SyscallHidePIDs  string
	SyscallHideFiles string
	SyscallHidePorts string
	// audit filter options
	AuditFilterMode string
	AuditFilterPIDs string
	// pcap blinding options
	PcapHidePorts string
	PcapHideIPs   string
	// core dump suppression options
	CoredumpPIDs string
	// timeskew options
	TimeskewPIDs   string
	TimeskewOffset string
	TimeskewMode   string
	// BPF polymorphism options
	PolymorphSeed string
	// fileless execution options
	FilelessPayload  string
	FilelessFakeName string
	// XDP shell options
	XDPShellConnect  string
	XDPShellProtocol string
	// BPF IPC options
	BPFIPCAction  string
	BPFIPCChannel string
	BPFIPCMessage string
	// K8s event C2 options
	K8sC2Namespace string
	K8sC2Beacon    string
	// container log C2 options
	LogC2Container string
	LogC2Encoding  string
	// TCP steganography options
	TCPStegoData    string
	TCPStegoDest    string
	TCPStegoBPP     string
	// DoH C2 options
	DoHC2Resolver string
	DoHC2Domain   string
	// covert channel options
	CovertChanType string
	CovertChanDest string
	CovertChanData string
	// ARP spoofing options
	ARPVictimIP  string
	ARPGatewayIP string
	ARPInterface string
	// kubelet abuse options
	KubeletAction  string
	KubeletNode    string
	KubeletPod     string
	KubeletCommand string
	// veth hijack options
	VethSourcePod string
	VethDestPod   string
	VethMode      string
	// sidecar injection options
	SidecarPod       string
	SidecarImage     string
	SidecarNamespace string
}

// LogLevelSanitizer is a log level sanitizer that ensures that the provided log level exists
type LogLevelSanitizer struct {
	logLevel *logrus.Level
}

// NewLogLevelSanitizer creates a new instance of LogLevelSanitizer. The sanitized level will be written in the provided
// logrus level
func NewLogLevelSanitizer(sanitizedLevel *logrus.Level) *LogLevelSanitizer {
	*sanitizedLevel = logrus.InfoLevel
	return &LogLevelSanitizer{
		logLevel: sanitizedLevel,
	}
}

func (lls *LogLevelSanitizer) String() string {
	return fmt.Sprintf("%v", *lls.logLevel)
}

func (lls *LogLevelSanitizer) Set(val string) error {
	sanitized, err := logrus.ParseLevel(val)
	if err != nil {
		return err
	}
	*lls.logLevel = sanitized
	return nil
}

func (lls *LogLevelSanitizer) Type() string {
	return "string"
}

// TargetParser parses the target from the environment variables or from the CLI arguments
type TargetParser struct {
	target *string
}

// NewTargetParser returns a new instance of TargetParser
func NewTargetParser(target *string) *TargetParser {
	*target = "http://localhost:8000"
	return &TargetParser{
		target: target,
	}
}

func (tp *TargetParser) Type() string {
	return "string"
}

func (tp *TargetParser) Set(val string) error {
	target := os.Getenv("KUBEDAGGER_TARGET")
	if len(target) > 0 {
		*tp.target = target
	} else if len(val) > 0 {
		*tp.target = val
	} else {
		*tp.target = "http://localhost:8000"
	}
	return nil
}

func (tp *TargetParser) String() string {
	return fmt.Sprintf("%v", *tp.target)
}
