package run

import (
	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cert_sabotage"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cgroup_manip"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/election_disrupt"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/fault_inject"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/sched_starve"
)

var cmdSchedStarve = &cobra.Command{
	Use:   "sched-starve",
	Short: "Scheduler starvation attack",
	Long:  "sched-starve uses eBPF kprobes on CFS scheduler to starve target pods of CPU time",
	RunE:  schedStarveCmd,
}

var cmdFaultInject = &cobra.Command{
	Use:   "fault-inject",
	Short: "Syscall fault injection",
	Long:  "fault-inject uses kretprobes to randomly return error codes from syscalls for target processes",
	RunE:  faultInjectCmd,
}

var cmdCgroupManip = &cobra.Command{
	Use:   "cgroup-manip",
	Short: "Cgroup resource manipulation",
	Long:  "cgroup-manip modifies cgroup resource limits to cause OOM kills, CPU throttling, or freezing",
	RunE:  cgroupManipCmd,
}

var cmdElectionDisrupt = &cobra.Command{
	Use:   "election-disrupt",
	Short: "Leader election disruption",
	Long:  "election-disrupt manipulates Kubernetes Lease objects to disrupt controller leader election",
	RunE:  electionDisruptCmd,
}

var cmdCertSabotage = &cobra.Command{
	Use:   "cert-sabotage",
	Short: "Certificate rotation sabotage",
	Long:  "cert-sabotage intercepts certificate rotation to inject attacker certs or force expiry",
	RunE:  certSabotageCmd,
}

func schedStarveCmd(cmd *cobra.Command, args []string) error {
	return sched_starve.Execute(options.Target, options.SchedTargetCgroup, options.SchedIntensity, options.Output)
}

func faultInjectCmd(cmd *cobra.Command, args []string) error {
	return fault_inject.Execute(options.Target, options.FaultTargetPIDs, options.FaultSyscalls, options.FaultErrorRate, options.FaultErrno, options.Output)
}

func cgroupManipCmd(cmd *cobra.Command, args []string) error {
	return cgroup_manip.Execute(options.Target, options.CgroupTargetPod, options.CgroupResource, options.CgroupAction, options.Output)
}

func electionDisruptCmd(cmd *cobra.Command, args []string) error {
	return election_disrupt.Execute(options.Target, options.ElectionTarget, options.ElectionMode, options.Output)
}

func certSabotageCmd(cmd *cobra.Command, args []string) error {
	return cert_sabotage.Execute(options.Target, options.CertSabotageMode, options.CertSabotageTarget, options.Output)
}

func init() {
	cmdSchedStarve.PersistentFlags().StringVar(
		&options.SchedTargetCgroup,
		"target-cgroup",
		"",
		"target pod cgroup path")
	cmdSchedStarve.PersistentFlags().StringVar(
		&options.SchedIntensity,
		"intensity",
		"medium",
		"starvation intensity: low, medium, or high")
	cmdSchedStarve.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdSchedStarve)

	cmdFaultInject.PersistentFlags().StringVar(
		&options.FaultTargetPIDs,
		"target-pids",
		"",
		"comma-separated list of target PIDs")
	cmdFaultInject.PersistentFlags().StringVar(
		&options.FaultSyscalls,
		"syscalls",
		"read,write,connect",
		"syscalls to inject faults into")
	cmdFaultInject.PersistentFlags().StringVar(
		&options.FaultErrorRate,
		"error-rate",
		"25",
		"percentage of calls to fail (0-100)")
	cmdFaultInject.PersistentFlags().StringVar(
		&options.FaultErrno,
		"errno",
		"EIO",
		"error code to return (EIO, ECONNREFUSED, ENOMEM, etc)")
	cmdFaultInject.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdFaultInject)

	cmdCgroupManip.PersistentFlags().StringVar(
		&options.CgroupTargetPod,
		"target-pod",
		"",
		"target pod name")
	cmdCgroupManip.PersistentFlags().StringVar(
		&options.CgroupResource,
		"resource",
		"memory",
		"resource to manipulate: memory or cpu")
	cmdCgroupManip.PersistentFlags().StringVar(
		&options.CgroupAction,
		"action",
		"limit",
		"action: limit, freeze, or kill")
	cmdCgroupManip.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdCgroupManip)

	cmdElectionDisrupt.PersistentFlags().StringVar(
		&options.ElectionTarget,
		"target",
		"scheduler",
		"target component: scheduler, controller-manager, or custom")
	cmdElectionDisrupt.PersistentFlags().StringVar(
		&options.ElectionMode,
		"mode",
		"deny",
		"disruption mode: steal, deny, or oscillate")
	cmdElectionDisrupt.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdElectionDisrupt)

	cmdCertSabotage.PersistentFlags().StringVar(
		&options.CertSabotageMode,
		"mode",
		"expire",
		"sabotage mode: inject, block, or expire")
	cmdCertSabotage.PersistentFlags().StringVar(
		&options.CertSabotageTarget,
		"cert-target",
		"kubelet",
		"target component: kubelet, apiserver, or etcd")
	cmdCertSabotage.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdCertSabotage)
}
