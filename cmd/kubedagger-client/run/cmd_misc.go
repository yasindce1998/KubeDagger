package run

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cri_tamper"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/dashboard"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/fileless"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/honeypot_detect"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/mitre"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/obs_poison"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/proctree"
)

var cmdMitreExport = &cobra.Command{
	Use:   "export",
	Short: "export ATT&CK mapping",
	Long:  "export generates an ATT&CK Navigator layer or markdown report",
	RunE:  mitreExportCmd,
}

var cmdDashboard = &cobra.Command{
	Use:   "dashboard",
	Short: "real-time TUI dashboard",
	Long:  "dashboard launches an interactive terminal UI showing live KubeDagger activity",
	RunE:  dashboardCmd,
}

var cmdProcTreeGet = &cobra.Command{
	Use:   "get",
	Short: "get process tree",
	Long:  "get retrieves the current process tree from the target",
	RunE:  procTreeGetCmd,
}

var cmdObsPoison = &cobra.Command{
	Use:   "obs-poison",
	Short: "observability poisoning",
	Long:  "obs-poison injects false metrics/traces into Prometheus, OpenTelemetry, or StatsD pipelines",
	RunE:  obsPoisonCmd,
}

var cmdCRITamper = &cobra.Command{
	Use:   "cri-tamper",
	Short: "CRI-level image tampering",
	Long:  "cri-tamper hooks containerd/CRI-O to inject code into container images at the runtime layer",
	RunE:  criTamperCmd,
}

var cmdFileless = &cobra.Command{
	Use:   "fileless-exec",
	Short: "Fileless execution",
	Long:  "fileless-exec uses memfd_create + execveat for disk-free payload execution",
	RunE:  filelessCmd,
}

var cmdHoneypotDetect = &cobra.Command{
	Use:   "honeypot-detect",
	Short: "Honeypot/deception detection",
	Long:  "honeypot-detect fingerprints environment inconsistencies to detect honeypot/deception clusters",
	RunE:  honeypotDetectCmd,
}

func mitreExportCmd(cmd *cobra.Command, args []string) error {
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
	return dashboard.Run(options.Target, options.RefreshRate)
}

func procTreeGetCmd(cmd *cobra.Command, args []string) error {
	entries, err := proctree.FetchProcessTree(options.Target)
	if err != nil {
		return err
	}
	proctree.PrintTree(entries)
	return nil
}

func obsPoisonCmd(cmd *cobra.Command, args []string) error {
	return obs_poison.Execute(options.Target, options.PoisonTarget, options.PoisonEndpoint, options.PoisonStrategy, options.Output)
}

func criTamperCmd(cmd *cobra.Command, args []string) error {
	return cri_tamper.Execute(options.Target, options.CRIRuntime, options.CRIMode, options.CRITargetImage, options.CRIInjectBinary, options.Output)
}

func filelessCmd(cmd *cobra.Command, args []string) error {
	return fileless.Execute(options.Target, options.FilelessPayload, options.FilelessFakeName, options.Output)
}

func honeypotDetectCmd(cmd *cobra.Command, args []string) error {
	return honeypot_detect.Execute(options.Target, options.HoneypotChecks, options.Output)
}

func init() {
	cmdMitreExport.PersistentFlags().StringVar(
		&options.MitreFormat,
		"format",
		"json",
		"output format: json or markdown")
	cmdMitreExport.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	cmdMitre.AddCommand(cmdMitreExport)
	KUBEDaggerClient.AddCommand(cmdMitre)

	cmdDashboard.PersistentFlags().IntVar(
		&options.RefreshRate,
		"refresh",
		2,
		"dashboard refresh interval in seconds")
	KUBEDaggerClient.AddCommand(cmdDashboard)

	cmdProcTree.AddCommand(cmdProcTreeGet)
	KUBEDaggerClient.AddCommand(cmdProcTree)

	cmdObsPoison.PersistentFlags().StringVar(
		&options.PoisonTarget,
		"poison-target",
		"prometheus",
		"observability target: prometheus, otel, or statsd")
	cmdObsPoison.PersistentFlags().StringVar(
		&options.PoisonEndpoint,
		"endpoint",
		"",
		"target endpoint URL")
	cmdObsPoison.PersistentFlags().StringVar(
		&options.PoisonStrategy,
		"strategy",
		"inject",
		"poisoning strategy: inject, replay, or corrupt")
	cmdObsPoison.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdObsPoison)

	cmdCRITamper.PersistentFlags().StringVar(
		&options.CRIRuntime,
		"runtime",
		"containerd",
		"container runtime: containerd or crio")
	cmdCRITamper.PersistentFlags().StringVar(
		&options.CRIMode,
		"mode",
		"layer-inject",
		"tamper mode: layer-inject, entrypoint-hook, or env-inject")
	cmdCRITamper.PersistentFlags().StringVar(
		&options.CRITargetImage,
		"target-image",
		"",
		"image name pattern to tamper with")
	cmdCRITamper.PersistentFlags().StringVar(
		&options.CRIInjectBinary,
		"inject-binary",
		"",
		"path to binary to inject into targeted containers")
	cmdCRITamper.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdCRITamper)

	cmdFileless.PersistentFlags().StringVar(
		&options.FilelessPayload,
		"payload",
		"",
		"ELF payload path or base64 content")
	cmdFileless.PersistentFlags().StringVar(
		&options.FilelessFakeName,
		"fake-name",
		"[kworker/0:1]",
		"fake process name shown in /proc")
	cmdFileless.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdFileless)

	cmdHoneypotDetect.PersistentFlags().StringVar(
		&options.HoneypotChecks,
		"checks",
		"all",
		"checks to run: all, kubelet, metrics, or tokens")
	cmdHoneypotDetect.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdHoneypotDetect)
}
