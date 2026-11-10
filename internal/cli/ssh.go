package cli

import (
	"fmt"

	connectapp "github.com/cmstar/jumpaccess/internal/application/connect"
	"github.com/cmstar/jumpaccess/internal/target"
	"github.com/spf13/cobra"
)

func newSSHCommand(deps Dependencies) *cobra.Command {
	var profile string
	var organization string
	var account string
	var options SSHOptions
	command := &cobra.Command{
		Use:   "ssh <target>",
		Short: "Open an interactive SSH session through JumpServer",
		Long: `Open an interactive SSH session to an asset through the JumpServer SSH gateway.

The target is a profile alias first, then an asset ID, name, or address. Unknown
gateway host keys are confirmed once and stored in known_hosts. Without --account,
multiple permitted accounts prompt for a choice.`,
		Example: `  jumpctl ssh web --profile work
  jumpctl ssh 10.0.0.10 --account root --profile work`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if deps.Connect == nil || deps.RunSSH == nil {
				return fmt.Errorf("SSH service is unavailable")
			}
			prepared, err := deps.Connect.Prepare(cmd.Context(), connectapp.Options{
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
			return deps.RunSSH(cmd.Context(), prepared, options)
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	command.Flags().StringVar(&organization, "organization", "", "JumpServer organization ID")
	command.Flags().StringVar(&account, "account", "", "account ID, alias, name, or username")
	command.Flags().StringVar(&options.DownloadDirectory, "download-dir", "", "local ZMODEM download directory (defaults to the system Downloads folder)")
	return command
}
