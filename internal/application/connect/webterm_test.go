package connect

import (
	"context"
	"errors"
	"testing"

	authapp "github.com/cmstar/jumpaccess/internal/application/auth"
	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/credential"
	"github.com/cmstar/jumpaccess/internal/jumpserver"
	"github.com/cmstar/jumpaccess/internal/target"
)

type cookieSessions struct {
	session credential.CookieSession
	err     error
}

func (c cookieSessions) Ensure(context.Context, string, string) (credential.Session, error) {
	return credential.Session{Cookie: c.session}, c.err
}

func (c cookieSessions) Cookie(string, string) (credential.CookieSession, error) {
	if c.err != nil {
		return credential.CookieSession{}, c.err
	}
	return c.session, nil
}

func webTerminalFixture() (projectconfig.Config, *fakeAPI) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	api := &fakeAPI{
		page: jumpserver.AssetPage{Results: []jumpserver.Asset{{ID: "asset-1", Name: "app-1"}}},
		detail: jumpserver.AssetDetail{
			Asset:     jumpserver.Asset{ID: "asset-1", Name: "app-1"},
			Accounts:  []jumpserver.Account{{ID: "account-1", Username: "root"}},
			Protocols: []jumpserver.Protocol{{Name: "ssh", Port: 22}},
		},
	}
	return configuration, api
}

func TestPrepareWebTerminalRequestsWebCLITokenFromCookieSession(t *testing.T) {
	configuration, api := webTerminalFixture()
	cookie := credential.CookieSession{
		Site:      "http://172.16.251.2",
		Cookies:   []credential.Cookie{{Name: "jms_sessionid", Value: "session"}},
		CSRFToken: "csrf",
	}
	service := Service{
		Config:  staticConfig{value: configuration},
		Cookies: cookieSessions{session: cookie},
		NewAPI: func(site string, session credential.Session, organization string) (API, error) {
			if site != "http://172.16.251.2" || !session.IsCookie() {
				t.Fatalf("factory session = %q %#v", site, session)
			}
			return api, nil
		},
	}

	prepared, err := service.PrepareWebTerminal(context.Background(), Options{
		Target: target.Input{Target: "app-1", Account: "account-1"}, NonInteractive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !api.validated {
		t.Fatal("cookie session was not validated before requesting a connection token")
	}
	if prepared.TokenID != "connection-1" || prepared.Asset.ID != "asset-1" || prepared.Account.ID != "account-1" {
		t.Fatalf("prepared = %#v", prepared)
	}
	if prepared.Cookie.CSRFToken != "csrf" || len(prepared.Cookie.Cookies) != 1 {
		t.Fatalf("prepared cookie = %#v", prepared.Cookie)
	}
	if request := api.connectionRequest; request.ConnectMethod != "web_cli" || request.Protocol != "ssh" || request.Asset != "asset-1" || request.Account != "root" {
		t.Fatalf("connection request = %#v", request)
	}
}

func TestPrepareWebTerminalRequiresCookieSession(t *testing.T) {
	configuration, api := webTerminalFixture()
	service := Service{
		Config:  staticConfig{value: configuration},
		Cookies: cookieSessions{err: authapp.ErrCookieRequired},
		NewAPI:  func(string, credential.Session, string) (API, error) { return api, nil },
	}

	_, err := service.PrepareWebTerminal(context.Background(), Options{Target: target.Input{Target: "app-1", Account: "account-1"}})
	if !errors.Is(err, jumpserver.ErrCookieSessionRequired) {
		t.Fatalf("error = %v, want ErrCookieSessionRequired", err)
	}
	if api.connectionRequest.ConnectMethod != "" {
		t.Fatal("connection token was requested without a cookie session")
	}
}

func TestPrepareWebTerminalReportsInvalidCookieSession(t *testing.T) {
	configuration, api := webTerminalFixture()
	api.validateErr = jumpserver.ErrCookieSessionInvalid
	service := Service{
		Config:  staticConfig{value: configuration},
		Cookies: cookieSessions{session: credential.CookieSession{Site: "http://172.16.251.2", Cookies: []credential.Cookie{{Name: "a", Value: "b"}}}},
		NewAPI:  func(string, credential.Session, string) (API, error) { return api, nil },
	}

	_, err := service.PrepareWebTerminal(context.Background(), Options{Target: target.Input{Target: "app-1", Account: "account-1"}})
	if !errors.Is(err, jumpserver.ErrCookieSessionInvalid) {
		t.Fatalf("error = %v, want ErrCookieSessionInvalid", err)
	}
	if api.connectionRequest.ConnectMethod != "" {
		t.Fatal("connection token was requested with an invalid session")
	}
}

func TestPrepareWebTerminalUsesCookieEvenWhenOAuthCredentialExists(t *testing.T) {
	configuration, api := webTerminalFixture()
	cookie := credential.CookieSession{
		Site:    "http://172.16.251.2",
		Cookies: []credential.Cookie{{Name: "jms_sessionid", Value: "session"}},
	}
	service := Service{
		Config:   staticConfig{value: configuration},
		Sessions: staticSessions{token: credential.Token{AccessToken: "oauth-access", Site: "http://172.16.251.2"}},
		Cookies:  cookieSessions{session: cookie},
		NewAPI: func(_ string, session credential.Session, _ string) (API, error) {
			if !session.IsCookie() {
				t.Fatal("web terminal used the OAuth credential instead of the imported cookie")
			}
			return api, nil
		},
	}

	prepared, err := service.PrepareWebTerminal(context.Background(), Options{Target: target.Input{Target: "app-1", Account: "account-1"}, NonInteractive: true})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.TokenID != "connection-1" || api.connectionRequest.ConnectMethod != "web_cli" {
		t.Fatalf("prepared = %#v request = %#v", prepared, api.connectionRequest)
	}
}
