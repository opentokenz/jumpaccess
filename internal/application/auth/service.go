package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	projectconfig "github.com/cmstar/jumpaccess/internal/config"
	"github.com/cmstar/jumpaccess/internal/credential"
)

type ConfigLoader interface {
	Load() (projectconfig.Config, error)
}

type Status struct {
	Profile          string
	LoggedIn         bool
	Expired          bool
	RefreshAvailable bool
	ExpiresAt        time.Time

	CookieImported    bool
	CookieImportedAt  time.Time
	CookieValidatedAt time.Time
	CookieSite        string
}

type LoginOptions struct {
	Manual    bool
	NoBrowser bool
}

type Service struct {
	Config    ConfigLoader
	Tokens    TokenRepository
	Cookies   CookieRepository
	Manager   Manager
	LoginFlow func(context.Context, string, LoginOptions) (credential.Token, error)
	// ManualLoginFlow 是其他程序占用私有协议或系统禁止注册协议时永久保留的回退方式。
	ManualLoginFlow func(context.Context, string, LoginOptions) (credential.Token, error)
	Revoke          func(context.Context, credential.Token) error
	// Validate 用用户资料接口确认当前会话有效，供 Cookie 导入和 auth check 使用。
	Validate func(context.Context, string, credential.Session) (string, error)
	Now      func() time.Time
	Timeout  time.Duration
}

func (s Service) Login(ctx context.Context, requestedProfile string, options LoginOptions) (Status, error) {
	profile, configured, err := s.resolveProfile(requestedProfile)
	if err != nil {
		return Status{}, err
	}
	loginFlow := s.LoginFlow
	if options.Manual || options.NoBrowser {
		loginFlow = s.ManualLoginFlow
		if loginFlow == nil {
			return Status{}, fmt.Errorf("manual browser login is unavailable")
		}
	} else if loginFlow == nil {
		// 原生协议处理发布前，手工流程既是默认方式，也是显式 --manual 回退方式。
		loginFlow = s.ManualLoginFlow
	}
	if loginFlow == nil {
		return Status{}, fmt.Errorf("browser login is unavailable")
	}
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	token, err := loginFlow(ctx, configured.URL, options)
	if err != nil {
		return Status{}, err
	}
	if err := CommitLogin(ctx, s.Config, s.Tokens, s.Manager.Locker, profile, token); err != nil {
		return Status{}, err
	}
	return s.statusFor(profile, token), nil
}

func (s Service) Status(requestedProfile string) (Status, error) {
	profile, configured, err := s.resolveProfile(requestedProfile)
	if err != nil {
		return Status{}, err
	}
	token, err := s.Tokens.Load(profile)
	if errors.Is(err, credential.ErrNotFound) {
		return s.withCookie(profile, Status{Profile: profile})
	}
	if err != nil {
		return Status{}, fmt.Errorf("load OAuth credential: %w", err)
	}
	status := s.statusFor(profile, token)
	if err := ValidateTokenSite(token, configured.URL); err != nil {
		return s.withCookie(profile, Status{Profile: profile})
	}
	return status, nil
}

// CheckResult 是一次网络校验的结果，mode 为 oauth 或 cookie。
type CheckResult struct {
	Profile     string
	Mode        string
	User        string
	ValidatedAt time.Time
}

// Check 立即用用户资料接口验证当前认证方式；Cookie 会话校验成功后记录时间。
func (s Service) Check(ctx context.Context, requestedProfile string) (CheckResult, error) {
	profile, configured, err := s.resolveProfile(requestedProfile)
	if err != nil {
		return CheckResult{}, err
	}
	if s.Validate == nil {
		return CheckResult{}, fmt.Errorf("session validation is unavailable")
	}
	session, err := (Sessions{Tokens: s.Manager, Cookies: s.Cookies}).Ensure(ctx, profile, configured.URL)
	if err != nil {
		return CheckResult{}, err
	}
	user, err := s.Validate(ctx, configured.URL, session)
	if err != nil {
		return CheckResult{}, err
	}
	result := CheckResult{Profile: profile, Mode: "oauth", User: user}
	if !session.IsCookie() {
		return result, nil
	}
	result.Mode = "cookie"
	cookie := session.Cookie
	cookie.ValidatedAt = s.now()
	if s.Cookies != nil {
		if err := s.Cookies.SaveCookie(profile, cookie); err != nil {
			return CheckResult{}, fmt.Errorf("save cookie validation time: %w", err)
		}
	}
	result.ValidatedAt = cookie.ValidatedAt
	return result, nil
}

// withCookie 只补充 Cookie 会话的存在信息，不在 status 中发起网络校验。
func (s Service) withCookie(profile string, status Status) (Status, error) {
	if s.Cookies == nil {
		return status, nil
	}
	cookie, err := s.Cookies.LoadCookie(profile)
	if errors.Is(err, credential.ErrNotFound) {
		return status, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("load cookie session: %w", err)
	}
	status.CookieImported = true
	status.CookieImportedAt = cookie.ImportedAt
	status.CookieValidatedAt = cookie.ValidatedAt
	status.CookieSite = cookie.Site
	return status, nil
}

func (s Service) Refresh(ctx context.Context, requestedProfile string) (Status, error) {
	profile, _, err := s.resolveProfile(requestedProfile)
	if err != nil {
		return Status{}, err
	}
	token, err := s.Manager.RefreshNow(ctx, profile)
	if err != nil {
		return Status{}, err
	}
	return s.statusFor(profile, token), nil
}

func (s Service) Logout(ctx context.Context, requestedProfile string) error {
	profile, _, err := s.resolveProfile(requestedProfile)
	if err != nil {
		return err
	}
	// Cookie 会话只有本地副本，优先清理，避免 OAuth 注销失败时遗留可用的浏览器会话。
	if s.Cookies != nil {
		if err := s.Cookies.DeleteCookie(profile); err != nil && !errors.Is(err, credential.ErrNotFound) {
			return fmt.Errorf("delete cookie session: %w", err)
		}
	}
	unlock, err := LockProfile(ctx, s.Manager.Locker, profile)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	token, err := s.Tokens.Load(profile)
	if errors.Is(err, credential.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load OAuth credential: %w", err)
	}
	if s.Revoke != nil {
		if err := s.Revoke(ctx, token); err != nil {
			return err
		}
	}
	if err := s.Tokens.Delete(profile); err != nil && !errors.Is(err, credential.ErrNotFound) {
		return fmt.Errorf("delete OAuth credential: %w", err)
	}
	return nil
}

func (s Service) resolveProfile(requested string) (string, projectconfig.Profile, error) {
	return resolveProfile(s.Config, requested)
}

func resolveProfile(config ConfigLoader, requested string) (string, projectconfig.Profile, error) {
	value, err := config.Load()
	if err != nil {
		return "", projectconfig.Profile{}, err
	}
	profile := requested
	if profile == "" {
		profile = value.CurrentProfile
	}
	if profile == "" {
		return "", projectconfig.Profile{}, fmt.Errorf("no current profile; add one with jumpctl profile add")
	}
	configured, ok := value.Profiles[profile]
	if !ok {
		return "", projectconfig.Profile{}, fmt.Errorf("profile %q does not exist", profile)
	}
	return profile, configured, nil
}

func (s Service) statusFor(profile string, token credential.Token) Status {
	now := s.now()
	return Status{
		Profile:          profile,
		LoggedIn:         true,
		Expired:          !token.ExpiresAt.After(now),
		RefreshAvailable: token.RefreshToken != "",
		ExpiresAt:        token.ExpiresAt,
	}
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
