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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/detection"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/report"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/vap_backdoor"
)

// KUBEDaggerClient represents the base command of the kubeDaggerClient
var KUBEDaggerClient = &cobra.Command{
	Use: "kubedagger-client",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		logrus.SetLevel(options.LogLevel)
		return nil
	},
}

var cmdFSWatch = &cobra.Command{
	Use:   "fs_watch",
	Short: "file system watches",
	Long:  "fs_watch can be used to exfiltrate file content",
}

var cmdPipeProg = &cobra.Command{
	Use:   "pipe_prog",
	Short: "piped programs configuration",
	Long:  "pipe_prog can be used to intercept and control pipes between two processes",
}

var cmdDockerProg = &cobra.Command{
	Use:   "docker",
	Short: "Docker image override configuration",
	Long:  "the docker command can be used to configure how Docker images are overridden at runtime",
}

var cmdPostgresProg = &cobra.Command{
	Use:   "postgres",
	Short: "postgresql authentication control",
	Long:  "the postgres command can be used to exfiltrate Postgresql password hashes and change them at runtime",
}

var cmdNetworkDiscoveryProg = &cobra.Command{
	Use:   "network_discovery",
	Short: "network discovery configuration",
	Long:  "network_discovery can be used to scan the network of the target system",
}

var cmdK8s = &cobra.Command{
	Use:   "k8s",
	Short: "Kubernetes cluster discovery",
	Long:  "k8s enumerates cluster resources and identifies attack targets",
}

var cmdSecrets = &cobra.Command{
	Use:   "secrets",
	Short: "secret harvesting",
	Long:  "secrets scrapes credentials from environment, mounted volumes, cloud configs, and kubeconfig",
}

var cmdProcTree = &cobra.Command{
	Use:   "proctree",
	Short: "process tree visualization",
	Long:  "proctree retrieves and displays the process tree from the target system",
}

var cmdCloud = &cobra.Command{
	Use:   "cloud",
	Short: "cloud provider attack tools",
	Long:  "cloud provides tools for attacking cloud provider infrastructure (AWS, GCP, Azure)",
}

var cmdMitre = &cobra.Command{
	Use:   "mitre",
	Short: "MITRE ATT&CK mapping",
	Long:  "mitre generates MITRE ATT&CK technique mappings for KubeDagger capabilities",
}

var cmdDetection = &cobra.Command{
	Use:   "detection",
	Short: "detection rule generation for executed techniques",
	Long:  "detection generates Falco, Sigma, and Kubernetes audit detection rules for KubeDagger techniques",
}

var cmdDetectionList = &cobra.Command{
	Use:   "list",
	Short: "list detection catalog",
	Long:  "list prints all catalog techniques with their MITRE ATT&CK IDs",
	RunE:  detectionListCmd,
}

var cmdDetectionGenerate = &cobra.Command{
	Use:   "generate",
	Short: "generate detection coverage report",
	Long:  "generate produces a markdown detection coverage report with Falco, Sigma, and audit rules for the given techniques",
	RunE:  detectionGenerateCmd,
}

var cmdReport = &cobra.Command{
	Use:   "report",
	Short: "engagement report generation",
	Long:  "report builds markdown or HTML engagement reports from recorded event JSONL files",
}

var cmdReportGenerate = &cobra.Command{
	Use:   "generate",
	Short: "generate engagement report",
	Long:  "generate reads an events.jsonl file and renders a markdown or HTML engagement report",
	RunE:  reportGenerateCmd,
}

var cmdVAPBackdoor = &cobra.Command{
	Use:   "vap_backdoor",
	Short: "ValidatingAdmissionPolicy backdoor",
	Long:  "vap_backdoor deploys a ValidatingAdmissionPolicy that denies deletion of backdoor-labeled workloads (requires Kubernetes >= 1.30)",
	RunE:  vapBackdoorCmd,
}

var options CLIOptions

// Flag storage for the detection, report, and vap_backdoor commands.
var (
	detectionTechniques string
	detectionOut        string
	reportEvents        string
	reportOut           string
	reportHTML          bool
	reportTitle         string
	reportOperator      string
	reportClientName    string
	reportStart         string
	reportEnd           string
	reportScope         string
	vapNamespace        string
	vapLabel            string
	vapKubeconfig       string
	vapToken            string
)

func detectionListCmd(cmd *cobra.Command, args []string) error {
	return detection.List("")
}

func detectionGenerateCmd(cmd *cobra.Command, args []string) error {
	return detection.Generate(detectionTechniques, detectionOut)
}

func reportGenerateCmd(cmd *cobra.Command, args []string) error {
	return report.Generate(
		reportEvents,
		reportOut,
		reportHTML,
		reportTitle,
		reportOperator,
		reportClientName,
		reportStart,
		reportEnd,
		reportScope)
}

func vapBackdoorCmd(cmd *cobra.Command, args []string) error {
	return vap_backdoor.Execute(vapKubeconfig, vapToken, vapNamespace, vapLabel)
}

func init() {
	KUBEDaggerClient.PersistentFlags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")
	KUBEDaggerClient.PersistentFlags().VarP(
		NewTargetParser(&options.Target),
		"target",
		"t",
		"target application URL")

	cmdDetectionGenerate.PersistentFlags().StringVar(
		&detectionTechniques,
		"techniques",
		"all",
		"comma-separated technique keys (default: all)")
	cmdDetectionGenerate.PersistentFlags().StringVar(
		&detectionOut,
		"out",
		"",
		"output file path (stdout if not set)")
	cmdDetection.AddCommand(cmdDetectionList)
	cmdDetection.AddCommand(cmdDetectionGenerate)
	KUBEDaggerClient.AddCommand(cmdDetection)

	cmdReportGenerate.PersistentFlags().StringVar(
		&reportEvents,
		"events",
		"",
		"path to events.jsonl file (required)")
	cmdReportGenerate.PersistentFlags().StringVar(
		&reportOut,
		"out",
		"",
		"output file path (stdout if not set)")
	cmdReportGenerate.PersistentFlags().BoolVar(
		&reportHTML,
		"html",
		false,
		"generate HTML instead of markdown")
	cmdReportGenerate.PersistentFlags().StringVar(
		&reportTitle,
		"title",
		"",
		"report title")
	cmdReportGenerate.PersistentFlags().StringVar(
		&reportOperator,
		"operator",
		"",
		"operator name")
	cmdReportGenerate.PersistentFlags().StringVar(
		&reportClientName,
		"client",
		"",
		"client name")
	cmdReportGenerate.PersistentFlags().StringVar(
		&reportStart,
		"start",
		"",
		"engagement start date (free-form)")
	cmdReportGenerate.PersistentFlags().StringVar(
		&reportEnd,
		"end",
		"",
		"engagement end date (free-form)")
	cmdReportGenerate.PersistentFlags().StringVar(
		&reportScope,
		"scope",
		"",
		"engagement scope note")
	cmdReport.AddCommand(cmdReportGenerate)
	KUBEDaggerClient.AddCommand(cmdReport)

	cmdVAPBackdoor.PersistentFlags().StringVar(
		&vapNamespace,
		"namespace",
		"default",
		"namespace to protect (or 'all' for cluster-wide)")
	cmdVAPBackdoor.PersistentFlags().StringVar(
		&vapLabel,
		"label",
		"kubedagger-backdoor=true",
		"label key=value protecting resources from deletion")
	cmdVAPBackdoor.PersistentFlags().StringVar(
		&vapKubeconfig,
		"kubeconfig",
		"",
		"path to kubeconfig file (in-cluster or ~/.kube/config if not set)")
	cmdVAPBackdoor.PersistentFlags().StringVar(
		&vapToken,
		"token",
		"",
		"service account token (auto-detected if not specified)")
	KUBEDaggerClient.AddCommand(cmdVAPBackdoor)
}
