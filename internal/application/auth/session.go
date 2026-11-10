package auth

import (
	"context"
	"errors"
	"fmt"

	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/credential"
)

// TokenManager 返回可用的 OAuth Token；行为沿用 OAuth 模式，不感知 Cookie。
type TokenManager interface {
	EnsureFresh(context.Context, string) (credential.Token, error)
}

// CookieRepository 读写手工导入的浏览器会话；由 security 凭据后端实现。
type CookieRepository interface {
	LoadCookie(profile string) (credential.CookieSession, error)
	SaveCookie(profile string, session credential.CookieSession) error
	DeleteCookie(profile string) error
}

// Sessions 按 Profile 选择认证方式。存在 OAuth 凭据时保持 OAuth 行为，
// 只有 OAuth 凭据缺失时才回退到导入的 Cookie 会话。
type Sessions struct {
	Tokens  TokenManager
	Cookies CookieRepository
}

func (s Sessions) Ensure(ctx context.Context, profile, site string) (credential.Session, error) {
	if s.Tokens == nil {
		return credential.Session{}, fmt.Errorf("OAuth credential store is unavailable")
	}
	token, err := s.Tokens.EnsureFresh(ctx, profile)
	if err == nil {
		if err := ValidateTokenSite(token, site); err != nil {
			return credential.Session{}, err
		}
		return credential.Session{Token: token}, nil
	}
	if !errors.Is(err, ErrLoginRequired) || s.Cookies == nil {
		return credential.Session{}, err
	}
	cookie, cookieErr := s.Cookies.LoadCookie(profile)
	if errors.Is(cookieErr, credential.ErrNotFound) {
		return credential.Session{}, err
	}
	if cookieErr != nil {
		return credential.Session{}, fmt.Errorf("load cookie session: %w", cookieErr)
	}
	if err := ValidateCookieSite(cookie, site); err != nil {
		return credential.Session{}, err
	}
	return credential.Session{Cookie: cookie}, nil
}

// ErrCookieRequired 表示该操作必须使用导入的 Cookie 会话。
var ErrCookieRequired = errors.New("cookie session required")

// Cookie 直接读取 Profile 的 Cookie 会话，供只接受 Cookie 的能力使用；不回退到 OAuth。
func (s Sessions) Cookie(profile, site string) (credential.CookieSession, error) {
	if s.Cookies == nil {
		return credential.CookieSession{}, fmt.Errorf("cookie session store is unavailable")
	}
	cookie, err := s.Cookies.LoadCookie(profile)
	if errors.Is(err, credential.ErrNotFound) {
		return credential.CookieSession{}, ErrCookieRequired
	}
	if err != nil {
		return credential.CookieSession{}, fmt.Errorf("load cookie session: %w", err)
	}
	if err := ValidateCookieSite(cookie, site); err != nil {
		return credential.CookieSession{}, err
	}
	return cookie, nil
}

// ValidateSessionSite 要求会话凭据与目标站点一致，供服务层在调用 API 前复核。
func ValidateSessionSite(session credential.Session, site string) error {
	if session.IsCookie() {
		return ValidateCookieSite(session.Cookie, site)
	}
	return ValidateTokenSite(session.Token, site)
}

// ValidateCookieSite 要求导入会话与当前 Profile 指向同一个 Origin。
func ValidateCookieSite(session credential.CookieSession, site string) error {
	actual, err := projectconfig.NormalizeProfileURL(session.Site)
	if err != nil {
		return fmt.Errorf("%w: cookie session site is invalid", ErrLoginRequired)
	}
	expected, err := projectconfig.NormalizeProfileURL(site)
	if err != nil || actual != expected {
		return fmt.Errorf("%w: cookie session belongs to another site", ErrLoginRequired)
	}
	return nil
}
