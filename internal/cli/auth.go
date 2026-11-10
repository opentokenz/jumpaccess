package cli

import (
	"fmt"

	authapp "github.com/cmstar/jumpaccess/internal/application/auth"
	"github.com/spf13/cobra"
)

func newAuthCommand(deps Dependencies) *cobra.Command {
	command := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with JumpServer using OAuth or an imported cookie session",
		Long: `Authenticate with JumpServer using OAuth or an imported cookie session.

Use "login" when the server exposes OAuth discovery, or "import-cookie" when it
does not. A profile with an OAuth credential keeps using OAuth; the cookie session
is used only when no OAuth credential exists. The web terminal always requires a
cookie session.`,
	}
	command.AddCommand(newAuthLoginCommand(deps))
	command.AddCommand(newAuthImportCookieCommand(deps))
	command.AddCommand(newAuthCheckCommand(deps))
	command.AddCommand(newAuthStatusCommand(deps))
	command.AddCommand(newAuthRefreshCommand(deps))
	command.AddCommand(newAuthLogoutCommand(deps))
	return command
}

func newAuthLoginCommand(deps Dependencies) *cobra.Command {
	var profile string
	var manual bool
	var noBrowser bool
	command := &cobra.Command{
		Use:   "login",
		Short: "Authenticate the selected profile using browser authorization",
		Long: `Open the system browser and complete OAuth authorization code + PKCE.

The browser returns a jms:// callback. --manual pastes the callback URL instead
of using the registered protocol handler; --no-browser prints the authorization
URL and waits for a pasted callback without opening a browser.`,
		Example: `  jumpctl auth login --profile work
  jumpctl auth login --profile work --no-browser`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			service, err := requireAuth(deps)
			if err != nil {
				return err
			}
			status, err := service.Login(cmd.Context(), profile, authapp.LoginOptions{Manual: manual, NoBrowser: noBrowser})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "authenticated profile %s\n", status.Profile)
			return err
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	command.Flags().BoolVar(&manual, "manual", false, "paste the OAuth callback URL instead of using the registered protocol handler")
	command.Flags().BoolVar(&noBrowser, "no-browser", false, "print the authorization URL without opening a browser and wait for a pasted callback URL")
	return command
}

func newAuthCheckCommand(deps Dependencies) *cobra.Command {
	var profile string
	command := &cobra.Command{
		Use:   "check",
		Short: "Verify the stored session against JumpServer right now",
		Long: `Verify the stored session against JumpServer right now.

For OAuth profiles this refreshes the token if needed and calls the user profile
API. For cookie profiles it calls the same API with the imported cookie and
records the validation time shown by "auth status".`,
		Example: `  jumpctl auth check --profile work`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			service, err := requireAuth(deps)
			if err != nil {
				return err
			}
			result, err := service.Check(cmd.Context(), profile)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "profile: %s\nmode: %s\nuser: %s\n", result.Profile, result.Mode, result.User)
			return err
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	return command
}

func newAuthStatusCommand(deps Dependencies) *cobra.Command {
	var profile string
	command := &cobra.Command{
		Use:   "status",
		Short: "Show authentication status without revealing credentials",
		Long: `Show authentication status without revealing secrets.

OAuth profiles report token expiry and refresh availability. A profile with only
an imported cookie session reports the import time; cookie validity is checked by
"auth import-cookie" and by each API request.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			service, err := requireAuth(deps)
			if err != nil {
				return err
			}
			status, err := service.Status(profile)
			if err != nil {
				return err
			}
			return printAuthStatus(cmd, status)
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	return command
}

func newAuthRefreshCommand(deps Dependencies) *cobra.Command {
	var profile string
	command := &cobra.Command{
		Use:     "refresh",
		Short:   "Refresh OAuth credentials now",
		Example: `  jumpctl auth refresh --profile work`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			service, err := requireAuth(deps)
			if err != nil {
				return err
			}
			status, err := service.Refresh(cmd.Context(), profile)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "refreshed profile %s\n", status.Profile)
			return err
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	return command
}

func newAuthImportCookieCommand(deps Dependencies) *cobra.Command {
	var profile string
	command := &cobra.Command{
		Use:   "import-cookie",
		Short: "Store a browser session cookie for the selected profile",
		Long: `Read the browser Cookie header without echo and validate it against the selected profile.

Copy the Cookie request header from the browser developer tools while the JumpServer
web UI is logged in. It must include the session cookie and the CSRF cookie
(for example jms_sessionid and jms_csrftoken).

The input is hidden and requires an interactive terminal. The cookie is stored in
the protected credential store, never in config.toml, and is only sent to that
profile's origin. A failed validation saves nothing.`,
		Example: `  jumpctl auth import-cookie --profile work
  jumpctl webssh web-01 --account root --profile work`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if deps.Cookies == nil {
				return fmt.Errorf("cookie session service is unavailable")
			}
			if deps.ReadSecret == nil {
				return fmt.Errorf("hidden input is unavailable")
			}
			raw, err := deps.ReadSecret("Cookie header (input is hidden): ", cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			status, err := deps.Cookies.Import(cmd.Context(), profile, raw)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "cookie session saved for profile %s\nvalidated as %s on %s\n", status.Profile, status.User, status.Site); err != nil {
				return err
			}
			if !status.HasCSRF {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: no csrftoken cookie found; connection token requests may be rejected. Paste the full Cookie header from the browser.")
			}
			return nil
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	return command
}

func newAuthLogoutCommand(deps Dependencies) *cobra.Command {
	var profile string
	command := &cobra.Command{
		Use:   "logout",
		Short: "Revoke and remove OAuth credentials and the imported cookie session",
		Long: `Revoke and remove stored credentials for the profile.

OAuth credentials are revoked when the server allows it. The imported cookie
session is always deleted locally. Running this does not close existing sessions.`,
		Example: `  jumpctl auth logout --profile work`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			service, err := requireAuth(deps)
			if err != nil {
				return err
			}
			if err := service.Logout(cmd.Context(), profile); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "logged out")
			return err
		},
	}
	command.Flags().StringVar(&profile, "profile", "", "profile name (defaults to current profile)")
	return command
}

func requireAuth(deps Dependencies) (AuthService, error) {
	if deps.Auth == nil {
		return nil, fmt.Errorf("authentication service is unavailable")
	}
	return deps.Auth, nil
}

func printAuthStatus(cmd *cobra.Command, status authapp.Status) error {
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "profile: %s\n", status.Profile); err != nil {
		return err
	}
	if !status.LoggedIn {
		if status.CookieImported {
			if _, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				"status: cookie session imported\ncookie imported: %s\n",
				status.CookieImportedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			); err != nil {
				return err
			}
			if !status.CookieValidatedAt.IsZero() {
				_, err := fmt.Fprintf(
					cmd.OutOrStdout(),
					"cookie last validated: %s\n",
					status.CookieValidatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
				)
				return err
			}
			return nil
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "status: not authenticated")
		return err
	}
	state := "authenticated"
	if status.Expired {
		state = "access token expired"
	}
	refresh := "no"
	if status.RefreshAvailable {
		refresh = "yes"
	}
	_, err := fmt.Fprintf(
		cmd.OutOrStdout(),
		"status: %s\naccess token expires: %s\nrefresh available: %s\n",
		state,
		status.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		refresh,
	)
	return err
}
