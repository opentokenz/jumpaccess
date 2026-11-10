package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	authapp "github.com/cmstar/jumpaccess/internal/application/auth"
	connectapp "github.com/cmstar/jumpaccess/internal/application/connect"
	"github.com/cmstar/jumpaccess/internal/jumpserver"
)

type fakeCookieImporter struct {
	profile string
	raw     string
	status  authapp.CookieStatus
	err     error
}

func (f *fakeCookieImporter) Import(_ context.Context, profile, raw string) (authapp.CookieStatus, error) {
	f.profile = profile
	f.raw = raw
	return f.status, f.err
}

func TestAuthImportCookieReadsHiddenInputWithoutPrintingSecrets(t *testing.T) {
	var stdout, stderr bytes.Buffer
	importer := &fakeCookieImporter{status: authapp.CookieStatus{Profile: "work", Site: "http://172.16.251.2", User: "root", HasCSRF: true}}
	var prompt string
	root := NewRoot(Dependencies{
		Cookies: importer,
		Stdout:  &stdout,
		Stderr:  &stderr,
		ReadSecret: func(promptText string, _ io.Writer) (string, error) {
			prompt = promptText
			return "jms_sessionid=session-secret; jms_csrftoken=csrf-secret", nil
		},
	})
	root.SetArgs([]string{"auth", "import-cookie", "--profile", "work"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if prompt == "" {
		t.Fatal("hidden input prompt was not shown")
	}
	if importer.profile != "work" || importer.raw != "jms_sessionid=session-secret; jms_csrftoken=csrf-secret" {
		t.Fatalf("import arguments = %q %q", importer.profile, importer.raw)
	}
	if !strings.Contains(stdout.String(), "cookie session saved for profile work") || !strings.Contains(stdout.String(), "validated as root") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "session-secret") || strings.Contains(stdout.String(), "csrf-secret") || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("cookie values leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAuthImportCookieWarnsWhenCSRFCookieIsMissing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	importer := &fakeCookieImporter{status: authapp.CookieStatus{Profile: "work", Site: "http://172.16.251.2", User: "root"}}
	root := NewRoot(Dependencies{
		Cookies: importer, Stdout: &stdout, Stderr: &stderr,
		ReadSecret: func(string, io.Writer) (string, error) { return "jms_sessionid=value", nil },
	})
	root.SetArgs([]string{"auth", "import-cookie", "--profile", "work"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "csrftoken") {
		t.Fatalf("missing CSRF warning: %q", stderr.String())
	}
}

func TestAuthImportCookieStopsWhenHiddenInputFails(t *testing.T) {
	importer := &fakeCookieImporter{}
	root := NewRoot(Dependencies{
		Cookies:    importer,
		ReadSecret: func(string, io.Writer) (string, error) { return "", fmt.Errorf("standard input is not a terminal") },
	})
	root.SetArgs([]string{"auth", "import-cookie"})

	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("error = %v", err)
	}
	if importer.profile != "" {
		t.Fatal("cookie was imported after a failed hidden read")
	}
}

func TestAuthImportCookieReportsValidationFailure(t *testing.T) {
	importer := &fakeCookieImporter{err: jumpserver.ErrCookieSessionInvalid}
	root := NewRoot(Dependencies{
		Cookies:    importer,
		ReadSecret: func(string, io.Writer) (string, error) { return "jms_sessionid=value", nil },
	})
	root.SetArgs([]string{"auth", "import-cookie"})

	if err := root.Execute(); !errors.Is(err, jumpserver.ErrCookieSessionInvalid) {
		t.Fatalf("error = %v", err)
	}
}

type fakeWebTerminal struct {
	prepared connectapp.WebTerminal
	options  connectapp.Options
	err      error
}

func (f *fakeWebTerminal) PrepareWebTerminal(_ context.Context, options connectapp.Options) (connectapp.WebTerminal, error) {
	f.options = options
	return f.prepared, f.err
}

func TestWebSSHResolvesTargetAndRunsPreparedSession(t *testing.T) {
	preparer := &fakeWebTerminal{prepared: connectapp.WebTerminal{
		Asset:   jumpserver.AssetDetail{Asset: jumpserver.Asset{ID: "asset-1", Name: "app-1"}},
		Account: jumpserver.Account{ID: "account-1", Username: "root"},
		TokenID: "token-1",
	}}
	var ran bool
	var received WebSSHOptions
	root := NewRoot(Dependencies{
		WebTerminal: preparer,
		RunWebTerminal: func(_ context.Context, prepared connectapp.WebTerminal, options WebSSHOptions) error {
			ran = true
			received = options
			if prepared.TokenID != "token-1" {
				t.Fatalf("prepared = %#v", prepared)
			}
			return nil
		},
	})
	root.SetArgs([]string{"webssh", "app-1", "--account", "root", "--profile", "work", "--organization", "org-1", "--download-dir", "/tmp/downloads"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("web terminal runner was not called")
	}
	if preparer.options.Target.Target != "app-1" || preparer.options.Target.Account != "root" ||
		preparer.options.Target.Profile != "work" || preparer.options.Target.Organization != "org-1" {
		t.Fatalf("options = %#v", preparer.options)
	}
	if received.DownloadDirectory != "/tmp/downloads" {
		t.Fatalf("download directory = %q", received.DownloadDirectory)
	}
}

func TestWebSSHRequiresService(t *testing.T) {
	root := NewRoot(Dependencies{})
	root.SetArgs([]string{"webssh", "app-1"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("error = %v", err)
	}
}

func TestAuthStatusReportsImportedCookieSession(t *testing.T) {
	var stdout bytes.Buffer
	imported := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	service := &fakeAuthService{status: authapp.Status{Profile: "work", CookieImported: true, CookieImportedAt: imported}}
	root := NewRoot(Dependencies{Auth: service, Stdout: &stdout})
	root.SetArgs([]string{"auth", "status"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	const want = "profile: work\nstatus: cookie session imported\ncookie imported: 2026-11-10T12:00:00Z\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestAuthCheckReportsModeUserAndProfile(t *testing.T) {
	var stdout bytes.Buffer
	service := &fakeAuthService{checkResult: authapp.CheckResult{Profile: "work", Mode: "cookie", User: "root"}}
	root := NewRoot(Dependencies{Auth: service, Stdout: &stdout})
	root.SetArgs([]string{"auth", "check", "--profile", "work"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if service.checkProfile != "work" {
		t.Fatalf("check profile = %q", service.checkProfile)
	}
	const want = "profile: work\nmode: cookie\nuser: root\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestAuthCheckReportsInvalidSession(t *testing.T) {
	service := &fakeAuthService{checkErr: jumpserver.ErrCookieSessionInvalid}
	root := NewRoot(Dependencies{Auth: service})
	root.SetArgs([]string{"auth", "check"})

	if err := root.Execute(); !errors.Is(err, jumpserver.ErrCookieSessionInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestAuthStatusShowsCookieValidationTime(t *testing.T) {
	var stdout bytes.Buffer
	imported := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	validated := imported.Add(time.Hour)
	service := &fakeAuthService{status: authapp.Status{
		Profile: "work", CookieImported: true, CookieImportedAt: imported, CookieValidatedAt: validated,
	}}
	root := NewRoot(Dependencies{Auth: service, Stdout: &stdout})
	root.SetArgs([]string{"auth", "status"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	const want = "profile: work\nstatus: cookie session imported\ncookie imported: 2026-11-10T12:00:00Z\ncookie last validated: 2026-11-10T13:00:00Z\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}
