package jumpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cmstar/jumpaccess/internal/credential"
)

func cookieSession() credential.CookieSession {
	return credential.CookieSession{
		Site: "http://jump.example.test",
		Cookies: []credential.Cookie{
			{Name: "jms_sessionid", Value: "session-value"},
			{Name: "jms_csrftoken", Value: "csrf-value"},
		},
		CSRFToken: "csrf-value",
	}
}

func TestSessionClientUsesCookieAndCSRFForWrites(t *testing.T) {
	var (
		getCookie  string
		getCSRF    string
		postCookie string
		postCSRF   string
		postBody   ConnectionRequest
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/users/profile/":
			getCookie = r.Header.Get("Cookie")
			getCSRF = r.Header.Get("X-CSRFToken")
			if r.Header.Get("Authorization") != "" {
				t.Error("cookie session must not send a bearer token")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"username": "root"})
		case "/api/v1/authentication/connection-token/":
			postCookie = r.Header.Get("Cookie")
			postCSRF = r.Header.Get("X-CSRFToken")
			if err := json.NewDecoder(r.Body).Decode(&postBody); err != nil {
				t.Errorf("decode request: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"connection-token-1","value":"secret"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewSessionClient(server.URL, credential.Session{Cookie: cookieSession()}, "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	user, err := client.ValidateSession(context.Background())
	if err != nil || user != "root" {
		t.Fatalf("ValidateSession = %q, %v", user, err)
	}
	tokenID, err := client.CreateConnectionToken(context.Background(), ConnectionRequest{
		Asset: "asset-1", Account: "account-1", Protocol: "ssh", ConnectMethod: "web_cli",
	})
	if err != nil || tokenID != "connection-token-1" {
		t.Fatalf("CreateConnectionToken = %q, %v", tokenID, err)
	}

	const wantCookie = "jms_sessionid=session-value; jms_csrftoken=csrf-value"
	if getCookie != wantCookie || postCookie != wantCookie {
		t.Fatalf("cookie headers = %q / %q", getCookie, postCookie)
	}
	if getCSRF != "" || postCSRF != "csrf-value" {
		t.Fatalf("CSRF headers = %q / %q", getCSRF, postCSRF)
	}
	if postBody.ConnectMethod != "web_cli" || postBody.Protocol != "ssh" {
		t.Fatalf("connection request = %#v", postBody)
	}
}

func TestSessionClientReportsInvalidCookieSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Authentication credentials were not provided."}`))
	}))
	defer server.Close()

	client, err := NewSessionClient(server.URL, credential.Session{Cookie: cookieSession()}, "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ValidateSession(context.Background())
	if !errors.Is(err, ErrCookieSessionInvalid) {
		t.Fatalf("ValidateSession error = %v, want ErrCookieSessionInvalid", err)
	}
}

func TestSessionClientRequiresExactlyOneCredential(t *testing.T) {
	site := "http://jump.example.test"
	if _, err := NewSessionClient(site, credential.Session{}, "", nil); err == nil {
		t.Fatal("empty session accepted")
	}
	both := credential.Session{Token: credential.Token{AccessToken: "access"}, Cookie: cookieSession()}
	if _, err := NewSessionClient(site, both, "", nil); err == nil {
		t.Fatal("session with token and cookie accepted")
	}
	if _, err := NewClient(site, "access", "", nil); err != nil {
		t.Fatalf("bearer client error = %v", err)
	}
}

func TestAPIErrorReportsErrorCodeWithoutResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"perm_account_invalid","detail":"account secret-value was echoed"}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "oauth-secret", "", server.Client())
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.CreateConnectionToken(context.Background(), ConnectionRequest{Asset: "asset", InputSecret: "request-secret"})
	if err == nil {
		t.Fatal("request unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "perm_account_invalid") {
		t.Fatalf("error missing server code: %v", err)
	}
	for _, leaked := range []string{"secret-value", "request-secret", "oauth-secret"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error exposed %q: %v", leaked, err)
		}
	}
}
