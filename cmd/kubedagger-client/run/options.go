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

// CLIOptions holds all command-line flags, organized by domain via embedded sub-structs.
type CLIOptions struct {
	LogLevel logrus.Level
	Target   string
	Output   string
	From     string
	To       string

	FSWatchOpts
	DockerOpts
	PostgresOpts
	NetworkOpts
	K8sOpts
	EvasionOpts
	CredentialOpts
	C2Opts
	CloudOpts
	DisruptionOpts
	MiscOpts
}

type FSWatchOpts struct {
	InContainer bool
	Active      bool
	Backup      bool
}

type DockerOpts struct {
	Override int
	Ping     int
}

type PostgresOpts struct {
	Role   string
	Secret string
}

type NetworkOpts struct {
	IP               string
	Port             string
	Range            string
	ActiveDiscovery  bool
	PassiveDiscovery bool
	BypassMode       string
	DestIP           string
	DestPort         string
	MeshBypassMode   string
	MeshTarget       string
	ARPVictimIP      string
	ARPGatewayIP     string
	ARPInterface     string
	KubeletAction    string
	KubeletNode      string
	KubeletPod       string
	KubeletCommand   string
	VethSourcePod    string
	VethDestPod      string
	VethMode         string
	CovertChanType   string
	CovertChanDest   string
	CovertChanData   string
	TCPStegoData     string
	TCPStegoDest     string
	TCPStegoBPP      string
}

type K8sOpts struct {
	K8sNamespace     string
	K8sAction        string
	K8sToken         string
	SecretSources    string
	EscapeAction     string
	EscapeTechnique  string
	WebhookAction    string
	WebhookNamespace string
	WebhookImage     string
	DaemonSetAction  string
	DaemonSetImage   string
	DaemonSetName    string
	SidecarPod       string
	SidecarImage     string
	SidecarNamespace string
}

type EvasionOpts struct {
	EvasionMode      string
	LogTamperMode    string
	LogTamperPattern string
	LogTamperTarget  string
	SyscallHidePIDs  string
	SyscallHideFiles string
	SyscallHidePorts string
	AuditFilterMode  string
	AuditFilterPIDs  string
	PcapHidePorts    string
	PcapHideIPs      string
	CoredumpPIDs     string
	TimeskewPIDs     string
	TimeskewOffset   string
	TimeskewMode     string
	PolymorphSeed    string
}

type CredentialOpts struct {
	TLSAction          string
	TLSTargetPID       string
	TLSLib             string
	EtcdMode           string
	EtcdKeyPrefix      string
	KeyringMode        string
	KeyringKeyType     string
	KeyringMITMType    string
	KeyringMITMReplace string
	SATokenAction      string
	SATokenName        string
	SATokenNS          string
	SATokenAudience    string
	PodIDTargetPod     string
	PodIDNamespace     string
	PodIDAction        string
}

type C2Opts struct {
	XDPShellConnect  string
	XDPShellProtocol string
	BPFIPCAction     string
	BPFIPCChannel    string
	BPFIPCMessage    string
	K8sC2Namespace   string
	K8sC2Beacon      string
	LogC2Container   string
	LogC2Encoding    string
	DoHC2Resolver    string
	DoHC2Domain      string
}

type CloudOpts struct {
	CloudProvider     string
	ExfilProvider     string
	ExfilBucket       string
	ExfilPath         string
	ExfilCredsFrom    string
	SupplyChainMode   string
	SupplyTargetImage string
	SupplyPayload     string
	GitOpsRepo        string
	GitOpsTargetPath  string
	GitOpsInjectImg   string
	SigBypassMode     string
	SigBypassImage    string
	CRDAction         string
	CRDName           string
}

type DisruptionOpts struct {
	SchedTargetCgroup  string
	SchedIntensity     string
	FaultTargetPIDs    string
	FaultSyscalls      string
	FaultErrorRate     string
	FaultErrno         string
	CgroupTargetPod    string
	CgroupResource     string
	CgroupAction       string
	ElectionTarget     string
	ElectionMode       string
	CertSabotageMode   string
	CertSabotageTarget string
}

type MiscOpts struct {
	MitreFormat      string
	RefreshRate      int
	ExfilFile        string
	ExfilDomain      string
	DNSServer        string
	PoisonTarget     string
	PoisonEndpoint   string
	PoisonStrategy   string
	CRIRuntime       string
	CRIMode          string
	CRITargetImage   string
	CRIInjectBinary  string
	FilelessPayload  string
	FilelessFakeName string
	HoneypotChecks   string
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
