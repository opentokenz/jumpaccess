package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/credential"
)

type fakeTokens struct {
	token credential.Token
	err   error
}

func (f fakeTokens) EnsureFresh(context.Context, string) (credential.Token, error) {
	return f.token, f.err
}

type memoryCookies struct {
	sessions map[string]credential.CookieSession
}

func (m *memoryCookies) LoadCookie(profile string) (credential.CookieSession, error) {
	session, ok := m.sessions[profile]
	if !ok {
		return credential.CookieSession{}, credential.ErrNotFound
	}
	return session, nil
}

func (m *memoryCookies) SaveCookie(profile string, session credential.CookieSession) error {
	if m.sessions == nil {
		m.sessions = make(map[string]credential.CookieSession)
	}
	m.sessions[profile] = session
	return nil
}

func (m *memoryCookies) DeleteCookie(profile string) error {
	if _, ok := m.sessions[profile]; !ok {
		return credential.ErrNotFound
	}
	delete(m.sessions, profile)
	return nil
}

func sessionFixture() credential.CookieSession {
	return credential.CookieSession{
		Site:      "http://172.16.251.2",
		Cookies:   []credential.Cookie{{Name: "jms_sessionid", Value: "session"}},
		CSRFToken: "csrf",
	}
}

func TestSessionsUsesCookieOnlyWhenOAuthCredentialIsMissing(t *testing.T) {
	missing := fmt.Errorf("%w for profile %q", ErrLoginRequired, "work")
	cookies := &memoryCookies{sessions: map[string]credential.CookieSession{"work": sessionFixture()}}
	resolver := Sessions{Tokens: fakeTokens{err: missing}, Cookies: cookies}

	session, err := resolver.Ensure(context.Background(), "work", "http://172.16.251.2/")
	if err != nil {
		t.Fatal(err)
	}
	if !session.IsCookie() || len(session.Cookie.Cookies) != 1 {
		t.Fatalf("session = %#v", session)
	}

	token := credential.Token{AccessToken: "access", Site: "http://172.16.251.2"}
	session, err = (Sessions{Tokens: fakeTokens{token: token}, Cookies: cookies}).Ensure(context.Background(), "work", "http://172.16.251.2")
	if err != nil {
		t.Fatal(err)
	}
	if session.IsCookie() || session.Token.AccessToken != "access" {
		t.Fatalf("OAuth session was replaced by cookies: %#v", session)
	}
}

func TestSessionsReportsLoginRequiredWhenNeitherCredentialExists(t *testing.T) {
	missing := fmt.Errorf("%w for profile %q", ErrLoginRequired, "work")
	_, err := (Sessions{Tokens: fakeTokens{err: missing}, Cookies: &memoryCookies{}}).Ensure(context.Background(), "work", "http://jump.example.test")
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("Ensure error = %v", err)
	}
}

func TestSessionsRejectsCookieFromAnotherSite(t *testing.T) {
	missing := fmt.Errorf("%w for profile %q", ErrLoginRequired, "work")
	cookies := &memoryCookies{sessions: map[string]credential.CookieSession{"work": sessionFixture()}}
	_, err := (Sessions{Tokens: fakeTokens{err: missing}, Cookies: cookies}).Ensure(context.Background(), "work", "http://other.example.test")
	if err == nil {
		t.Fatal("cookie session from another site was accepted")
	}
}

func TestCookieServiceImportValidatesBeforeSaving(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	cookies := &memoryCookies{}
	validated := false
	service := CookieService{
		Config:  staticConfig{value: configuration},
		Cookies: cookies,
		Validate: func(_ context.Context, site string, session credential.CookieSession) (string, error) {
			validated = true
			if site != "http://172.16.251.2" || len(session.Cookies) != 2 || session.CSRFToken != "csrf" {
				t.Fatalf("validated session = %#v", session)
			}
			return "root", nil
		},
		Now: func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) },
	}

	status, err := service.Import(context.Background(), "", "jms_sessionid=session; jms_csrftoken=csrf")
	if err != nil {
		t.Fatal(err)
	}
	if !validated || status.User != "root" || !status.HasCSRF || status.Profile != "work" {
		t.Fatalf("status = %#v validated=%v", status, validated)
	}
	saved, ok := cookies.sessions["work"]
	if !ok || len(saved.Cookies) != 2 || saved.Site != "http://172.16.251.2" {
		t.Fatalf("saved session = %#v", saved)
	}
	if !saved.ValidatedAt.Equal(saved.ImportedAt) || saved.ValidatedAt.IsZero() {
		t.Fatalf("import did not record the validation time: %#v", saved)
	}
}

func TestCookieServiceRejectsInvalidCookieWithoutSaving(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	cookies := &memoryCookies{}
	service := CookieService{
		Config:  staticConfig{value: configuration},
		Cookies: cookies,
		Validate: func(context.Context, string, credential.CookieSession) (string, error) {
			return "", errors.New("HTTP 403")
		},
	}

	if _, err := service.Import(context.Background(), "work", "jms_sessionid=session"); err == nil {
		t.Fatal("invalid cookie session was accepted")
	}
	if len(cookies.sessions) != 0 {
		t.Fatalf("invalid cookie session was saved: %#v", cookies.sessions)
	}
}

func TestServiceLogoutDeletesCookieSession(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	cookies := &memoryCookies{sessions: map[string]credential.CookieSession{"work": sessionFixture()}}
	service := Service{
		Config:  staticConfig{value: configuration},
		Tokens:  &memoryTokens{tokens: map[string]credential.Token{}},
		Cookies: cookies,
		Manager: Manager{Locker: &mutexLocker{}},
	}

	if err := service.Logout(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if _, ok := cookies.sessions["work"]; ok {
		t.Fatal("logout kept the cookie session")
	}
}

func TestSessionsCookieRequiresImportedSession(t *testing.T) {
	sessions := Sessions{Cookies: &memoryCookies{}}
	if _, err := sessions.Cookie("work", "http://jump.example.test"); !errors.Is(err, ErrCookieRequired) {
		t.Fatalf("Cookie error = %v, want ErrCookieRequired", err)
	}
	sessions.Cookies = &memoryCookies{sessions: map[string]credential.CookieSession{"work": sessionFixture()}}
	cookie, err := sessions.Cookie("work", "http://172.16.251.2")
	if err != nil || len(cookie.Cookies) != 1 {
		t.Fatalf("Cookie = %#v, %v", cookie, err)
	}
	if _, err := sessions.Cookie("work", "http://other.example.test"); err == nil {
		t.Fatal("cookie session from another site was accepted")
	}
}

func TestStatusReportsCookieSessionWithoutOAuthCredential(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	cookie := sessionFixture()
	cookie.ImportedAt = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	service := Service{
		Config:  staticConfig{value: configuration},
		Tokens:  &memoryTokens{tokens: map[string]credential.Token{}},
		Cookies: &memoryCookies{sessions: map[string]credential.CookieSession{"work": cookie}},
	}

	status, err := service.Status("")
	if err != nil {
		t.Fatal(err)
	}
	if status.LoggedIn || !status.CookieImported || !status.CookieImportedAt.Equal(cookie.ImportedAt) || status.CookieSite != cookie.Site {
		t.Fatalf("status = %#v", status)
	}
}

func TestServiceCheckValidatesCookieAndRecordsTime(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	now := time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)
	cookies := &memoryCookies{sessions: map[string]credential.CookieSession{"work": sessionFixture()}}
	tokens := &memoryTokens{tokens: map[string]credential.Token{}}
	service := Service{
		Config:  staticConfig{value: configuration},
		Tokens:  tokens,
		Cookies: cookies,
		Manager: Manager{Tokens: tokens, Locker: &mutexLocker{}},
		Validate: func(_ context.Context, site string, session credential.Session) (string, error) {
			if site != "http://172.16.251.2" || !session.IsCookie() {
				t.Fatalf("validated session = %q %#v", site, session)
			}
			return "operator", nil
		},
		Now: func() time.Time { return now },
	}

	result, err := service.Check(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != "work" || result.Mode != "cookie" || result.User != "operator" {
		t.Fatalf("result = %#v", result)
	}
	if !cookies.sessions["work"].ValidatedAt.Equal(now) {
		t.Fatalf("validated at = %v, want %v", cookies.sessions["work"].ValidatedAt, now)
	}
	status, err := service.Status("work")
	if err != nil {
		t.Fatal(err)
	}
	if !status.CookieValidatedAt.Equal(now) {
		t.Fatalf("status validated at = %v", status.CookieValidatedAt)
	}
}

func TestServiceCheckDoesNotRecordFailedCookieValidation(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	cookies := &memoryCookies{sessions: map[string]credential.CookieSession{"work": sessionFixture()}}
	tokens := &memoryTokens{tokens: map[string]credential.Token{}}
	service := Service{
		Config:  staticConfig{value: configuration},
		Tokens:  tokens,
		Cookies: cookies,
		Manager: Manager{Tokens: tokens},
		Validate: func(context.Context, string, credential.Session) (string, error) {
			return "", errors.New("HTTP 401")
		},
	}

	if _, err := service.Check(context.Background(), "work"); err == nil {
		t.Fatal("invalid session accepted")
	}
	if !cookies.sessions["work"].ValidatedAt.IsZero() {
		t.Fatal("validation time was recorded for a failed check")
	}
}

func TestServiceCheckUsesOAuthWhenCredentialExists(t *testing.T) {
	configuration := projectconfig.Default()
	configuration.CurrentProfile = "work"
	configuration.Profiles["work"] = projectconfig.Profile{URL: "http://172.16.251.2"}
	now := time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)
	token := credential.Token{AccessToken: "access", Site: "http://172.16.251.2", ExpiresAt: now.Add(time.Hour)}
	tokens := &memoryTokens{tokens: map[string]credential.Token{"work": token}}
	service := Service{
		Config:  staticConfig{value: configuration},
		Tokens:  tokens,
		Cookies: &memoryCookies{sessions: map[string]credential.CookieSession{"work": sessionFixture()}},
		Manager: Manager{Tokens: tokens, Locker: &mutexLocker{}, Now: func() time.Time { return now }},
		Validate: func(_ context.Context, _ string, session credential.Session) (string, error) {
			if session.IsCookie() {
				t.Fatal("check used the cookie session although an OAuth credential exists")
			}
			return "admin", nil
		},
	}

	result, err := service.Check(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "oauth" || result.User != "admin" {
		t.Fatalf("result = %#v", result)
	}
}
