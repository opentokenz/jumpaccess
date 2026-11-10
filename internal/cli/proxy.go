package cli

import (
	"fmt"

	connectapp "github.com/cmstar/jumpaccess/internal/application/connect"
	"github.com/cmstar/jumpaccess/internal/target"
	"github.com/spf13/cobra"
)

func newProxyCommand(deps Dependencies) *cobra.Command {
	var profile string
	var organization string
	var account string
	command := &cobra.Command{
		Use:   "proxy <target>",
		Short: "Serve an SSH ProxyCommand connection over standard I/O",
		Long: `Serve one SSH connection for a client ProxyCommand over standard I/O.

stdout carries only SSH protocol bytes; diagnostics go to stderr. This mode never
prompts: resolve the account with an alias or --account, and confirm an unknown
gateway host key once with "jumpctl ssh".`,
		Example: `  # ~/.ssh/config
  Host production-web
      HostName web
      User jumpaccess
      ProxyCommand jumpctl proxy %h`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if deps.Connect == nil || deps.RunProxy == nil {
				return fmt.Errorf("ProxyCommand service is unavailable")
			}
			prepared, err := deps.Connect.Prepare(cmd.Context(), connectapp.Options{
				Target: target.Input{
					Target:       args[0],
					Profile:      profile,
					Organization: organization,
					Account:      account,
				},
				NonInteractive: true,
			})
			if err != nil {
				return err
			}
			return deps.RunProxy(cmd.Context(), prepared)
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	command.Flags().StringVar(&organization, "organization", "", "JumpServer organization ID")
	command.Flags().StringVar(&account, "account", "", "account ID, alias, name, or username")
	return command
}
