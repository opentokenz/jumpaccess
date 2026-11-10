package cli

import (
	"fmt"

	connectapp "github.com/cmstar/jumpaccess/internal/application/connect"
	"github.com/cmstar/jumpaccess/internal/target"
	"github.com/spf13/cobra"
)

func newWebSSHCommand(deps Dependencies) *cobra.Command {
	var profile string
	var organization string
	var account string
	var options WebSSHOptions
	command := &cobra.Command{
		Use:   "webssh <target>",
		Short: "Open an interactive terminal through the JumpServer web terminal",
		Long: `Open an interactive terminal through KoKo's HTTP WebSocket terminal.

This path does not use the JumpServer SSH port. It requires an imported browser
cookie session ("jumpctl auth import-cookie") and an interactive local terminal.
Terminal bytes are bridged to KoKo and the local terminal state is restored on exit.

ZMODEM is recognized on the terminal stream like "jumpctl ssh": run rz on the
remote host to upload and sz <file> to download. Progress and file prompts are
written to the terminal.`,
		Example: `  jumpctl auth import-cookie --profile work
  jumpctl webssh web-01 --account root --profile work`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if deps.WebTerminal == nil || deps.RunWebTerminal == nil {
				return fmt.Errorf("web terminal service is unavailable")
			}
			prepared, err := deps.WebTerminal.PrepareWebTerminal(cmd.Context(), connectapp.Options{
				Target: target.Input{
					Target:       args[0],
					Profile:      profile,
					Organization: organization,
					Account:      account,
				},
				SelectAccount: deps.SelectAccount,
			})
			if err != nil {
				return err
			}
			return deps.RunWebTerminal(cmd.Context(), prepared, options)
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	command.Flags().StringVar(&organization, "organization", "", "JumpServer organization ID")
	command.Flags().StringVar(&account, "account", "", "account ID, alias, name, or username")
	command.Flags().StringVar(&options.DownloadDirectory, "download-dir", "", "local ZMODEM download directory (defaults to the system Downloads folder)")
	return command
}
