package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func helpText(t *testing.T, args ...string) string {
	t.Helper()
	var output bytes.Buffer
	root := NewRoot(Dependencies{Stdout: &output})
	root.SetArgs(append(args, "--help"))
	if err := root.Execute(); err != nil {
		t.Fatalf("help %v: %v", args, err)
	}
	// 说明文字会按固定宽度换行，断言前统一空白。
	return strings.Join(strings.Fields(output.String()), " ")
}

func TestRootHelpDocumentsAgentContract(t *testing.T) {
	text := helpText(t)
	for _, want := range []string{
		"Exit status: 0 on success, 1 on failure",
		"For scripts and agents, pass --profile, --organization, and --account explicitly",
		"Results go to stdout, diagnostics to stderr",
		"jumpctl auth import-cookie",
		"Examples:",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("root help is missing %q:\n%s", want, text)
		}
	}
}

func TestImportCookieHelpDocumentsHiddenInputAndPrerequisites(t *testing.T) {
	text := helpText(t, "auth", "import-cookie")
	for _, want := range []string{
		"interactive terminal",
		"jms_sessionid",
		"jms_csrftoken",
		"never in config.toml",
		"A failed validation saves nothing",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("import-cookie help is missing %q:\n%s", want, text)
		}
	}
}

func TestWebSSHHelpDocumentsCookieAndTerminalRequirements(t *testing.T) {
	text := helpText(t, "webssh")
	for _, want := range []string{
		"does not use the JumpServer SSH port",
		"imported browser cookie session",
		"interactive local terminal",
		"local terminal state is restored on exit",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("webssh help is missing %q:\n%s", want, text)
		}
	}
}

func TestProxyHelpDocumentsNonInteractiveContract(t *testing.T) {
	text := helpText(t, "proxy")
	for _, want := range []string{
		"stdout carries only SSH protocol bytes",
		"never prompts",
		"gateway host key",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("proxy help is missing %q:\n%s", want, text)
		}
	}
}

func TestResourceHelpShowsInvocableExamples(t *testing.T) {
	for _, command := range []string{"asset list", "account list", "alias set", "ssh"} {
		text := helpText(t, strings.Fields(command)...)
		if !strings.Contains(text, "Examples:") || !strings.Contains(text, "jumpctl ") {
			t.Fatalf("%s help has no example:\n%s", command, text)
		}
	}
}

func TestEveryVisibleCommandHasShortDescriptionAndHelp(t *testing.T) {
	var walk func(command *cobra.Command, path []string)
	walk = func(command *cobra.Command, path []string) {
		for _, child := range command.Commands() {
			if child.Hidden || child.Name() == "help" || child.Name() == "completion" {
				continue
			}
			if strings.TrimSpace(child.Short) == "" {
				t.Errorf("command %q has no Short description", strings.Join(append(path, child.Name()), " "))
			}
			next := append(append([]string{}, path...), child.Name())
			if text := helpText(t, next...); !strings.Contains(text, "Usage:") {
				t.Errorf("command %q has no usage output", strings.Join(next, " "))
			}
			walk(child, next)
		}
	}
	walk(NewRoot(Dependencies{}), nil)
}
