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

var options CLIOptions

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
}
