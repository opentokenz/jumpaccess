package cli

import (
	"fmt"

	"github.com/cmstar/jumpaccess/internal/application/settings"
	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/spf13/cobra"
)

func newAliasCommand(deps Dependencies) *cobra.Command {
	command := &cobra.Command{
		Use:   "alias",
		Short: "Manage profile-scoped asset aliases",
		Long: `Manage short local names for assets.

An alias maps a name to an asset and an optional account, scoped to one profile.
Connection commands resolve aliases before treating the target as an asset ID,
name, or address.`,
	}

	var profileName string
	var asset string
	var account string
	var organization string
	command.PersistentFlags().StringVar(&profileName, "profile", "", "profile name (defaults to current profile)")
	set := &cobra.Command{
		Use:     "set <name>",
		Short:   "Create or replace an asset alias",
		Example: `  jumpctl alias set web --asset 3f2a1c9e-8b7d-4c6a-9f0e-1a2b3c4d5e6f --account root --profile work`,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return (settings.Service{Store: deps.Store}).SetAlias(profileName, args[0], projectconfig.Alias{
				Asset:        asset,
				Account:      account,
				Organization: organization,
			})
		},
	}
	set.Flags().StringVar(&asset, "asset", "", "asset ID, name, or address")
	set.Flags().StringVar(&account, "account", "", "account ID, alias, name, or username")
	set.Flags().StringVar(&organization, "organization", "", "JumpServer organization ID")
	_ = set.MarkFlagRequired("asset")
	command.AddCommand(set)
	var long bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List asset aliases",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			value, err := deps.Store.Load()
			if err != nil {
				return err
			}
			selectedProfile := profileName
			if selectedProfile == "" {
				selectedProfile = value.CurrentProfile
			}
			profile, ok := value.Profiles[selectedProfile]
			if !ok {
				return fmt.Errorf("profile %q does not exist", selectedProfile)
			}
			entries, err := listAliases(cmd.Context(), deps, selectedProfile, profile)
			if err != nil {
				return err
			}
			return writeAliases(cmd.OutOrStdout(), entries, long)
		},
	}
	list.Flags().BoolVar(&long, "long", false, "Show each alias with full original references")
	command.AddCommand(list)
	return command
}
