package credential

import (
	"errors"
	"testing"
	"time"
)

func TestParseCookieHeaderAcceptsBrowserFormats(t *testing.T) {
	for _, raw := range []string{
		"jms_sessionid=abc123; jms_csrftoken=csrf456",
		"Cookie: jms_sessionid=abc123; jms_csrftoken=csrf456",
		"  jms_sessionid=abc123 ;  jms_csrftoken=csrf456  ",
	} {
		cookies, err := ParseCookieHeader(raw)
		if err != nil {
			t.Fatalf("ParseCookieHeader(%q) error: %v", raw, err)
		}
		if len(cookies) != 2 || cookies[0].Name != "jms_sessionid" || cookies[0].Value != "abc123" {
			t.Fatalf("ParseCookieHeader(%q) = %#v", raw, cookies)
		}
		if token := CSRFTokenFromCookies(cookies); token != "csrf456" {
			t.Fatalf("CSRF token = %q", token)
		}
	}
}

func TestParseCookieHeaderKeepsLastDuplicateAndRejectsInvalidInput(t *testing.T) {
	cookies, err := ParseCookieHeader("a=1; a=2")
	if err != nil || len(cookies) != 1 || cookies[0].Value != "2" {
		t.Fatalf("duplicate cookies = %#v, %v", cookies, err)
	}
	for _, raw := range []string{"", "   ", "flag", "a=", "a=x\ny"} {
		if _, err := ParseCookieHeader(raw); err == nil {
			t.Fatalf("ParseCookieHeader(%q) error = nil", raw)
		}
	}
}

func TestRepositoryRoundTripsCookieSessionPerProfile(t *testing.T) {
	backend := &memoryBackend{values: make(map[string][]byte)}
	repository := Repository{Backend: backend}
	imported := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	want := CookieSession{
		Site:       "http://172.16.251.2",
		Cookies:    []Cookie{{Name: "jms_sessionid", Value: "secret-session"}, {Name: "jms_csrftoken", Value: "secret-csrf"}},
		CSRFToken:  "secret-csrf",
		ImportedAt: imported,
	}
	if err := repository.SaveCookie("work", want); err != nil {
		t.Fatal(err)
	}
	got, err := repository.LoadCookie("work")
	if err != nil {
		t.Fatal(err)
	}
	if got.Site != want.Site || len(got.Cookies) != 2 || got.CSRFToken != want.CSRFToken || !got.ImportedAt.Equal(imported) {
		t.Fatalf("loaded cookie session = %#v", got)
	}
	if header := got.Header(); header != "jms_sessionid=secret-session; jms_csrftoken=secret-csrf" {
		t.Fatalf("cookie header = %q", header)
	}
	if _, err := repository.LoadCookie("other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other profile error = %v", err)
	}
	if err := repository.DeleteCookie("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LoadCookie("work"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted cookie session error = %v", err)
	}
}

func TestCookieSessionRejectsUnsafeValues(t *testing.T) {
	for name, session := range map[string]CookieSession{
		"no site":   {Cookies: []Cookie{{Name: "a", Value: "b"}}},
		"no cookie": {Site: "http://jump.example.test"},
		"bad name":  {Site: "http://jump.example.test", Cookies: []Cookie{{Name: "a=b", Value: "c"}}},
		"newline":   {Site: "http://jump.example.test", Cookies: []Cookie{{Name: "a", Value: "b\nc"}}},
		"csrf":      {Site: "http://jump.example.test", Cookies: []Cookie{{Name: "a", Value: "b"}}, CSRFToken: "x\r\nY"},
	} {
		if err := session.Validate(); err == nil {
			t.Fatalf("%s: Validate() error = nil", name)
		}
	}
}
