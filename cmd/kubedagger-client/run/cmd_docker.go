package run

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/docker"
)

var cmdGetImagesList = &cobra.Command{
	Use:   "list",
	Short: "list container images",
	Long:  "list returns the list of Docker images detected",
	RunE:  getImagesListCmd,
}

var cmdPutDockerImageOverride = &cobra.Command{
	Use:   "put",
	Short: "put sends an image override request",
	Long:  "put is used to request that a Docker image is overridden on the target system",
	RunE:  putDockerImageOverrideCmd,
}

var cmdDelDockerImageOverride = &cobra.Command{
	Use:   "delete",
	Short: "delete removes a Docker image override request",
	Long:  "delete is used to stop overriding the provided Docker image on the target system",
	RunE:  delDockerImageOverrideCmd,
}

func getImagesListCmd(cmd *cobra.Command, args []string) error {
	return docker.SendGetImagesListRequest(options.Target, options.Output)
}

func putDockerImageOverrideCmd(cmd *cobra.Command, args []string) error {
	if len(options.From) == 0 {
		return fmt.Errorf("'from' image is required")
	}
	if len(options.To) >= 64 || len(options.From) >= 64 {
		return fmt.Errorf("'from' and 'to' image names must be at most 63 characters long: %s, %s", options.From, options.To)
	}
	if strings.Contains(options.From, "#") || strings.Contains(options.To, "#") {
		return fmt.Errorf("'from' and 'to' image names cannot contain '#': %s, %s", options.From, options.To)
	}
	return docker.SendPutImageOverrideRequest(options.Target, options.From, options.To, options.Override, options.Ping)
}

func delDockerImageOverrideCmd(cmd *cobra.Command, args []string) error {
	if len(options.From) == 0 {
		return fmt.Errorf("'from' image is required")
	}
	if len(options.From) >= 64 {
		return fmt.Errorf("'from' image name must be at most 63 characters long: %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return fmt.Errorf("'from' image name cannot contain '#': %s", options.From)
	}
	return docker.SendDelImageOverrideRequest(options.Target, options.From)
}

func init() {
	cmdGetImagesList.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file to write into")
	cmdPutDockerImageOverride.PersistentFlags().StringVar(
		&options.From,
		"from",
		"",
		"defines the Docker image to override")
	cmdPutDockerImageOverride.PersistentFlags().StringVar(
		&options.To,
		"to",
		"",
		"defines the Docker image to override with")
	cmdPutDockerImageOverride.PersistentFlags().IntVar(
		&options.Override,
		"override",
		0,
		"defines the action to take: 0 for nop, 1 for replace")
	cmdPutDockerImageOverride.PersistentFlags().IntVar(
		&options.Ping,
		"ping",
		0,
		"defines the answer to give on a ping from the input Docker image: 0 for nop, 1 for crash, 2 for run and 3 for hide")
	cmdDelDockerImageOverride.PersistentFlags().StringVar(
		&options.From,
		"from",
		"",
		"defines the Docker image")

	cmdDockerProg.AddCommand(cmdGetImagesList)
	cmdDockerProg.AddCommand(cmdPutDockerImageOverride)
	cmdDockerProg.AddCommand(cmdDelDockerImageOverride)
	KUBEDaggerClient.AddCommand(cmdDockerProg)
}
