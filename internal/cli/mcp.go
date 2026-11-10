package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cmstar/jumpaccess/internal/application/agentmcp"
	"github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/filelock"
	"github.com/spf13/cobra"
)

func newMCPCommand(deps Dependencies) *cobra.Command {
	command := &cobra.Command{
		Use:   "mcp",
		Short: "Run and manage the MCP server",
		Long: `Run and manage the shared Streamable HTTP MCP server.

The server uses the same profiles and credentials as other commands and requires a
completed login for the selected profile. MCP connections use the JumpServer SSH
gateway; a profile authenticated only by an imported cookie session is not supported.`,
	}
	command.AddCommand(newMCPServeCommand(deps))
	command.AddCommand(&cobra.Command{
		Use: "status", Short: "Show MCP server status", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			status, err := readMCPStatus(cmd.Context(), deps)
			if err != nil {
				return err
			}
			rows := [][]string{{"state", status.State}}
			if status.Instance != nil {
				rows = append(rows, []string{"host", status.Instance.Host}, []string{"url", status.Instance.URL}, []string{"started_at", status.Instance.StartedAt.Local().Format(time.RFC3339)})
			}
			rows = append(rows, []string{"restart_required", strconv.FormatBool(status.RestartRequired)})
			if status.State == "external" {
				rows = append(rows, []string{"statistics", "由其他宿主持有，当前不可读取"})
			}
			if status.Error != "" {
				rows = append(rows, []string{"error", status.Error})
			}
			if status.StopWarning != "" {
				rows = append(rows, []string{"warning", status.StopWarning})
			}
			return writeTable(cmd.OutOrStdout(), []string{"状态项", "值"}, rows)
		},
	})
	var values config.MCP
	var rotateToken, noTLS bool
	configuration := &cobra.Command{
		Use: "config", Short: "Show or change MCP settings (the access token is shown in clear text)", Args: cobra.NoArgs,
		Long: "Without options, print the current settings. With options, validate, save, and print all settings. The token is shown in clear text.",
		Example: `  jumpctl mcp config
  jumpctl mcp config --port 39287 --allow-lan=false
  jumpctl mcp config --rotate-token`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			modified := false
			for _, name := range []string{"listen-host", "port", "allow-lan", "tls-cert", "tls-key", "no-tls", "token", "rotate-token"} {
				if cmd.Flags().Changed(name) {
					modified = true
					break
				}
			}
			if !modified {
				return printMCPConfig(cmd.Context(), deps, cmd.OutOrStdout())
			}
			settings, err := cliMCPSettings(deps)
			if err != nil {
				return err
			}
			_, err = settings.UpdateConfig(cmd.Context(), func(current *config.MCP) error {
				if cmd.Flags().Changed("listen-host") {
					current.ListenHost = values.ListenHost
				}
				if cmd.Flags().Changed("port") {
					current.Port = values.Port
				}
				if cmd.Flags().Changed("allow-lan") {
					current.AllowLAN = values.AllowLAN
				}
				if cmd.Flags().Changed("tls-cert") {
					current.TLSCert = values.TLSCert
				}
				if cmd.Flags().Changed("tls-key") {
					current.TLSKey = values.TLSKey
				}
				if noTLS {
					current.TLSCert, current.TLSKey = "", ""
				}
				if cmd.Flags().Changed("token") {
					current.Token = values.Token
				}
				if rotateToken {
					token, err := settings.GenerateToken(cmd.Context())
					if err != nil {
						return err
					}
					current.Token = token
				}
				if current.Token == "" {
					return fmt.Errorf("尚未配置 MCP Token，请使用 --token 或 --rotate-token 一起保存")
				}
				return nil
			})
			if err != nil {
				return err
			}
			if err := printMCPConfig(cmd.Context(), deps, cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("MCP 配置已保存，但配置回显失败：%w", err)
			}
			return nil
		},
	}
	configuration.Flags().StringVar(&values.ListenHost, "listen-host", "127.0.0.1", "listen address (IP or localhost)")
	configuration.Flags().IntVar(&values.Port, "port", 39287, "listen port (1-65535)")
	configuration.Flags().BoolVar(&values.AllowLAN, "allow-lan", false, "allow LAN access (disable with --allow-lan=false)")
	configuration.Flags().StringVar(&values.TLSCert, "tls-cert", "", "TLS certificate path")
	configuration.Flags().StringVar(&values.TLSKey, "tls-key", "", "TLS private key path")
	configuration.Flags().BoolVar(&noTLS, "no-tls", false, "clear the TLS certificate and key settings")
	configuration.Flags().StringVar(&values.Token, "token", "", "set the MCP access token")
	configuration.Flags().BoolVar(&rotateToken, "rotate-token", false, "generate or replace the MCP access token")
	configuration.MarkFlagsMutuallyExclusive("token", "rotate-token")
	configuration.MarkFlagsMutuallyExclusive("no-tls", "tls-cert")
	configuration.MarkFlagsMutuallyExclusive("no-tls", "tls-key")
	command.AddCommand(configuration)
	return command
}

func cliMCPSettings(deps Dependencies) (agentmcp.Settings, error) {
	settings := deps.MCPSettings
	if settings.Store.Path == "" {
		settings.Store = deps.Store
	}
	if settings.Store.Path == "" {
		return settings, fmt.Errorf("MCP 配置服务不可用")
	}
	if settings.Locker.Dir == "" {
		settings.Locker = filelock.Locker{Dir: filepath.Join(filepath.Dir(settings.Store.Path), "locks")}
	}
	return settings, nil
}

func readMCPStatus(ctx context.Context, deps Dependencies) (agentmcp.Status, error) {
	if deps.MCP != nil {
		return deps.MCP.Status(ctx)
	}
	settings, err := cliMCPSettings(deps)
	if err != nil {
		return agentmcp.Status{}, err
	}
	return agentmcp.NewRuntime(settings, "cli", nil).Status(ctx)
}

func printMCPConfig(ctx context.Context, deps Dependencies, output io.Writer) error {
	status, err := readMCPStatus(ctx, deps)
	if err != nil {
		return err
	}
	cfg := status.Config
	optional := func(value string) string {
		if value == "" {
			return "未配置"
		}
		return value
	}
	rows := [][]string{
		{"listen-host", cfg.ListenHost}, {"port", strconv.Itoa(cfg.Port)}, {"allow-lan", strconv.FormatBool(cfg.AllowLAN)},
		{"tls-cert", optional(cfg.TLSCert)}, {"tls-key", optional(cfg.TLSKey)}, {"token", optional(cfg.Token)}, {"url", cfg.URL()},
	}
	if err := writeTable(output, []string{"配置项", "值"}, rows); err != nil {
		return err
	}
	if status.RestartRequired {
		_, err = fmt.Fprintln(output, "已保存配置与运行实例不同，重启 MCP 服务后生效。")
	}
	return err
}
