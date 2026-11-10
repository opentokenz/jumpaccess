package connect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authapp "github.com/cmstar/jumpaccess/internal/application/auth"
	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/credential"
	"github.com/cmstar/jumpaccess/internal/jumpserver"
	"github.com/cmstar/jumpaccess/internal/target"
)

var (
	ErrAssetNotFound                 = errors.New("asset not found")
	ErrAccountNotFound               = errors.New("account not found")
	ErrAccountAmbiguous              = errors.New("account is ambiguous")
	ErrInteractiveCredentialRequired = errors.New("interactive account credential is required")
	ErrProtocolNotPermitted          = errors.New("protocol not permitted")
)

const webConnectMethod = "web_cli"

type ConfigLoader interface {
	Load() (projectconfig.Config, error)
}

type SessionSource interface {
	Ensure(context.Context, string, string) (credential.Session, error)
}

// CookieSource 提供只用于 Web 终端的 Cookie 会话，避免 OAuth 凭据抢占。
type CookieSource interface {
	Cookie(profile, site string) (credential.CookieSession, error)
}

type AssetAPI interface {
	ListAssets(context.Context, jumpserver.AssetQuery) (jumpserver.AssetPage, error)
	GetAsset(context.Context, string) (jumpserver.AssetDetail, error)
}

type API interface {
	AssetAPI
	CreateConnectionToken(context.Context, jumpserver.ConnectionRequest) (string, error)
	GetClientConnection(context.Context, string) (jumpserver.ClientConnection, error)
	ValidateSession(context.Context) (string, error)
}

type Options struct {
	Target         target.Input
	Protocol       string
	NonInteractive bool
	SelectAccount  func([]jumpserver.Account) (jumpserver.Account, error)
}

type Prepared struct {
	Selection  target.Selection
	Asset      jumpserver.AssetDetail
	Account    jumpserver.Account
	Connection jumpserver.ClientConnection
}

// WebTerminal 是 KoKo WebSocket 终端所需的已连接参数：Cookie 会话、资产账号和连接令牌 ID。
type WebTerminal struct {
	Selection target.Selection
	Asset     jumpserver.AssetDetail
	Account   jumpserver.Account
	Cookie    credential.CookieSession
	TokenID   string
}

type Service struct {
	Config   ConfigLoader
	Sessions SessionSource
	Cookies  CookieSource
	NewAPI   func(site string, session credential.Session, organization string) (API, error)
}

type resolved struct {
	selection target.Selection
	session   credential.Session
	api       API
	asset     jumpserver.AssetDetail
	account   jumpserver.Account
}

func (s Service) Prepare(ctx context.Context, options Options) (Prepared, error) {
	protocol := options.Protocol
	if protocol == "" {
		protocol = "ssh"
	}
	if protocol != "ssh" && protocol != "sftp" {
		return Prepared{}, fmt.Errorf("connection protocol %q is not supported", protocol)
	}
	current, err := s.resolve(ctx, options, s.oauthSession(ctx))
	if err != nil {
		return Prepared{}, err
	}
	if err := ensureProtocol(current.asset, protocol); err != nil {
		return Prepared{}, err
	}
	connectionTokenID, err := current.api.CreateConnectionToken(ctx, jumpserver.ConnectionRequest{
		Asset:         current.asset.ID,
		Account:       accountName(current.account),
		Protocol:      protocol,
		ConnectMethod: protocol + "_client",
	})
	if err != nil {
		return Prepared{}, err
	}
	connection, err := current.api.GetClientConnection(ctx, connectionTokenID)
	if err != nil {
		return Prepared{}, err
	}
	if connection.Protocol != protocol {
		return Prepared{}, fmt.Errorf("connection protocol %q does not match requested %q", connection.Protocol, protocol)
	}
	return Prepared{Selection: current.selection, Asset: current.asset, Account: current.account, Connection: connection}, nil
}

// PrepareWebTerminal 申请 web_cli 连接令牌，供 KoKo WebSocket 终端使用，不建立 SSH 客户端连接。
func (s Service) PrepareWebTerminal(ctx context.Context, options Options) (WebTerminal, error) {
	current, err := s.resolve(ctx, options, s.cookieSession())
	if err != nil {
		return WebTerminal{}, err
	}
	if err := ensureProtocol(current.asset, "ssh"); err != nil {
		return WebTerminal{}, err
	}
	tokenID, err := current.api.CreateConnectionToken(ctx, jumpserver.ConnectionRequest{
		Asset:         current.asset.ID,
		Account:       accountName(current.account),
		Protocol:      "ssh",
		ConnectMethod: webConnectMethod,
	})
	if err != nil {
		return WebTerminal{}, err
	}
	return WebTerminal{
		Selection: current.selection,
		Asset:     current.asset,
		Account:   current.account,
		Cookie:    current.session.Cookie,
		TokenID:   tokenID,
	}, nil
}

func (s Service) oauthSession(ctx context.Context) func(profile, site string) (credential.Session, error) {
	return func(profile, site string) (credential.Session, error) {
		if s.Sessions == nil {
			return credential.Session{}, fmt.Errorf("authentication service is unavailable")
		}
		return s.Sessions.Ensure(ctx, profile, site)
	}
}

func (s Service) cookieSession() func(profile, site string) (credential.Session, error) {
	return func(profile, site string) (credential.Session, error) {
		if s.Cookies == nil {
			return credential.Session{}, fmt.Errorf("%w: run jumpctl auth import-cookie", jumpserver.ErrCookieSessionRequired)
		}
		cookie, err := s.Cookies.Cookie(profile, site)
		if errors.Is(err, authapp.ErrCookieRequired) {
			return credential.Session{}, fmt.Errorf("%w: run jumpctl auth import-cookie", jumpserver.ErrCookieSessionRequired)
		}
		if err != nil {
			return credential.Session{}, err
		}
		return credential.Session{Cookie: cookie}, nil
	}
}

func (s Service) resolve(ctx context.Context, options Options, selectSession func(profile, site string) (credential.Session, error)) (resolved, error) {
	if s.Config == nil {
		return resolved{}, fmt.Errorf("configuration is unavailable")
	}
	configuration, err := s.Config.Load()
	if err != nil {
		return resolved{}, err
	}
	selection, err := target.Resolve(configuration, options.Target)
	if err != nil {
		return resolved{}, err
	}
	session, err := selectSession(selection.Profile, selection.SiteURL)
	if err != nil {
		return resolved{}, err
	}
	if err := authapp.ValidateSessionSite(session, selection.SiteURL); err != nil {
		return resolved{}, err
	}
	if s.NewAPI == nil {
		return resolved{}, fmt.Errorf("JumpServer API client is unavailable")
	}
	api, err := s.NewAPI(selection.SiteURL, session, selection.Organization)
	if err != nil {
		return resolved{}, err
	}
	if session.IsCookie() {
		// 先确认 Cookie 会话有效，避免把 401 误报成资产不存在或权限不足。
		if _, err := api.ValidateSession(ctx); err != nil {
			return resolved{}, err
		}
	}
	asset, err := ResolveAsset(ctx, api, selection.Asset)
	if err != nil {
		return resolved{}, err
	}
	account, err := resolveAccount(asset.Accounts, selection.Account, options)
	if err != nil {
		return resolved{}, err
	}
	if requiresInputCredential(account) {
		return resolved{}, fmt.Errorf("%w for account %q; choose a managed account", ErrInteractiveCredentialRequired, accountName(account))
	}
	return resolved{selection: selection, session: session, api: api, asset: asset, account: account}, nil
}

func ensureProtocol(asset jumpserver.AssetDetail, protocol string) error {
	if !supportsProtocol(asset.Protocols, protocol) {
		return fmt.Errorf("%w: asset %q does not permit %s", ErrProtocolNotPermitted, asset.Name, strings.ToUpper(protocol))
	}
	return nil
}

// accountName 返回连接令牌所需的账号名。JumpServer 的 account 字段是账号名（别名），
// 不是账号 ID；发送 ID 会得到 400 perm_account_invalid。
func accountName(account jumpserver.Account) string {
	for _, value := range []string{account.Alias, account.Name, account.Username} {
		if value != "" {
			return value
		}
	}
	return account.ID
}

func ResolveAsset(ctx context.Context, api AssetAPI, reference string) (jumpserver.AssetDetail, error) {
	if isUUID(reference) {
		return api.GetAsset(ctx, reference)
	}
	offset := 0
	seen := make(map[string]struct{})
	for {
		if err := ctx.Err(); err != nil {
			return jumpserver.AssetDetail{}, err
		}
		page, err := api.ListAssets(ctx, jumpserver.AssetQuery{Search: reference, Offset: offset, Limit: 100})
		if err != nil {
			return jumpserver.AssetDetail{}, err
		}
		previousCount := len(seen)
		for _, asset := range page.Results {
			if asset.ID == reference || strings.EqualFold(asset.Name, reference) || strings.EqualFold(asset.Address, reference) {
				return api.GetAsset(ctx, asset.ID)
			}
			seen[asset.ID] = struct{}{}
		}
		if len(page.Results) > 0 && len(seen) == previousCount {
			return jumpserver.AssetDetail{}, fmt.Errorf("asset pagination made no progress at offset %d", offset)
		}
		offset += len(page.Results)
		if page.Next == "" && offset >= page.Count {
			return jumpserver.AssetDetail{}, fmt.Errorf("%w: %q", ErrAssetNotFound, reference)
		}
		if len(page.Results) == 0 {
			return jumpserver.AssetDetail{}, fmt.Errorf("asset pagination made no progress at offset %d", offset)
		}
	}
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := range value {
		switch index {
		case 8, 13, 18, 23:
			if value[index] != '-' {
				return false
			}
		default:
			character := value[index]
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f') ||
				(character >= 'A' && character <= 'F')) {
				return false
			}
		}
	}
	return true
}

func resolveAccount(accounts []jumpserver.Account, reference string, options Options) (jumpserver.Account, error) {
	if isPseudoAccount(reference) {
		return jumpserver.Account{ID: strings.ToUpper(reference), Username: strings.ToUpper(reference)}, nil
	}
	if reference != "" {
		return ResolvePermittedAccount(accounts, reference)
	}
	if len(accounts) == 0 {
		return jumpserver.Account{}, ErrAccountNotFound
	}
	if len(accounts) == 1 {
		return accounts[0], nil
	}
	if options.NonInteractive || options.SelectAccount == nil {
		return jumpserver.Account{}, fmt.Errorf("%w: choose one of %d permitted accounts", ErrAccountAmbiguous, len(accounts))
	}
	return options.SelectAccount(accounts)
}

func supportsProtocol(protocols []jumpserver.Protocol, expected string) bool {
	for _, protocol := range protocols {
		if strings.EqualFold(protocol.Name, expected) {
			return true
		}
	}
	return false
}

func isPseudoAccount(value string) bool {
	switch strings.ToUpper(value) {
	case "@INPUT", "@USER", "@ANON":
		return true
	default:
		return false
	}
}

func requiresInputCredential(account jumpserver.Account) bool {
	value := strings.ToUpper(account.ID)
	if value == "" {
		value = strings.ToUpper(account.Username)
	}
	return value == "@INPUT" || value == "@USER"
}
