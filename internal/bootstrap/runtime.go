package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/cmstar/jumpaccess/internal/application/agentmcp"
	authapp "github.com/cmstar/jumpaccess/internal/application/auth"
	connectapp "github.com/cmstar/jumpaccess/internal/application/connect"
	resourcesapp "github.com/cmstar/jumpaccess/internal/application/resources"
	settingsapp "github.com/cmstar/jumpaccess/internal/application/settings"
	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/credential"
	"github.com/cmstar/jumpaccess/internal/filelock"
	"github.com/cmstar/jumpaccess/internal/jumpserver"
	"github.com/cmstar/jumpaccess/internal/oauth"
)

type LoginFlow func(context.Context, string, authapp.LoginOptions) (credential.Token, error)

type Options struct {
	RootDir         string
	LoginFlow       LoginFlow
	ManualLoginFlow LoginFlow
}

type Runtime struct {
	RootDir       string
	ConfigPath    string
	Configuration projectconfig.Config
	Store         projectconfig.Store
	HTTPClient    *http.Client
	Tokens        credential.Repository
	AuthManager   authapp.Manager
	Sessions      authapp.Sessions
	Auth          authapp.Service
	Cookies       authapp.CookieService
	Connect       connectapp.Service
	Resources     resourcesapp.Service
	Settings      settingsapp.Service
	MCPSettings   agentmcp.Settings
}

func New(options Options) (Runtime, error) {
	if options.RootDir == "" {
		return Runtime{}, fmt.Errorf("application root directory is empty")
	}
	configPath := filepath.Join(options.RootDir, "config.toml")
	store := projectconfig.Store{Path: configPath}
	configuration, err := store.Load()
	if err != nil {
		return Runtime{}, err
	}
	httpClient := &http.Client{Timeout: configuration.Behavior.ConnectTimeout.Duration}
	tokens := credential.Repository{
		Backend: credential.NewFileBackend(filepath.Join(options.RootDir, "credentials")),
	}
	refresh := func(ctx context.Context, old credential.Token) (oauth.TokenResponse, error) {
		metadata, err := oauth.Discover(ctx, httpClient, old.Site)
		if err != nil {
			return oauth.TokenResponse{}, err
		}
		return (oauth.Client{HTTPClient: httpClient, Metadata: metadata}).Refresh(ctx, old.RefreshToken)
	}
	manager := authapp.Manager{
		Config:        store,
		Tokens:        tokens,
		Locker:        filelock.Locker{Dir: filepath.Join(options.RootDir, "locks")},
		Refresh:       refresh,
		RefreshBefore: configuration.Behavior.RefreshBeforeExpiry.Duration,
	}
	revoke := func(ctx context.Context, token credential.Token) error {
		metadata, err := oauth.Discover(ctx, httpClient, token.Site)
		if err != nil {
			return err
		}
		value := token.RefreshToken
		if value == "" {
			value = token.AccessToken
		}
		return (oauth.Client{HTTPClient: httpClient, Metadata: metadata}).Revoke(ctx, value)
	}
	validateSession := func(ctx context.Context, site string, session credential.Session) (string, error) {
		client, err := jumpserver.NewSessionClient(site, session, "", httpClient)
		if err != nil {
			return "", err
		}
		return client.ValidateSession(ctx)
	}
	authService := authapp.Service{
		Config:          store,
		Tokens:          tokens,
		Cookies:         tokens,
		Manager:         manager,
		LoginFlow:       options.LoginFlow,
		ManualLoginFlow: options.ManualLoginFlow,
		Revoke:          revoke,
		Validate:        validateSession,
		Timeout:         configuration.Behavior.OAuthTimeout.Duration,
	}
	sessions := authapp.Sessions{Tokens: manager, Cookies: tokens}
	cookieService := authapp.CookieService{
		Config:  store,
		Cookies: tokens,
		Validate: func(ctx context.Context, site string, session credential.CookieSession) (string, error) {
			return validateSession(ctx, site, credential.Session{Cookie: session})
		},
	}
	newAPI := func(site string, session credential.Session, organization string) (*jumpserver.Client, error) {
		return jumpserver.NewSessionClient(site, session, organization, httpClient)
	}
	connectService := connectapp.Service{
		Config:   store,
		Sessions: sessions,
		Cookies:  sessions,
		NewAPI: func(site string, session credential.Session, organization string) (connectapp.API, error) {
			return newAPI(site, session, organization)
		},
	}
	resourceService := resourcesapp.Service{
		Config:   store,
		Sessions: sessions,
		NewAPI: func(site string, session credential.Session, organization string) (resourcesapp.API, error) {
			return newAPI(site, session, organization)
		},
	}
	return Runtime{
		RootDir:       options.RootDir,
		ConfigPath:    configPath,
		Configuration: configuration,
		Store:         store,
		HTTPClient:    httpClient,
		Tokens:        tokens,
		AuthManager:   manager,
		Sessions:      sessions,
		Auth:          authService,
		Cookies:       cookieService,
		Connect:       connectService,
		Resources:     resourceService,
		Settings:      settingsapp.Service{Store: store, Credentials: tokens, Locker: manager.Locker},
		MCPSettings:   agentmcp.Settings{Store: store, Credentials: tokens.Backend, Locker: filelock.Locker{Dir: filepath.Join(options.RootDir, "locks")}},
	}, nil
}
