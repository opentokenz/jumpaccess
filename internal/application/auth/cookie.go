package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cmstar/jumpaccess/internal/credential"
)

type CookieStatus struct {
	Profile    string
	Site       string
	User       string
	ImportedAt time.Time
	HasCSRF    bool
}

// CookieService 导入和删除手工 Cookie 会话。凭据只写入安全存储，不进入普通配置。
type CookieService struct {
	Config   ConfigLoader
	Cookies  CookieRepository
	Validate func(context.Context, string, credential.CookieSession) (string, error)
	Now      func() time.Time
}

func (s CookieService) Import(ctx context.Context, requestedProfile, raw string) (CookieStatus, error) {
	profile, configured, err := resolveProfile(s.Config, requestedProfile)
	if err != nil {
		return CookieStatus{}, err
	}
	cookies, err := credential.ParseCookieHeader(raw)
	if err != nil {
		return CookieStatus{}, err
	}
	now := s.now()
	session := credential.CookieSession{
		Site:        configured.URL,
		Cookies:     cookies,
		CSRFToken:   credential.CSRFTokenFromCookies(cookies),
		ImportedAt:  now,
		ValidatedAt: now,
	}
	if err := session.Validate(); err != nil {
		return CookieStatus{}, err
	}
	if s.Cookies == nil {
		return CookieStatus{}, fmt.Errorf("cookie session store is unavailable")
	}
	if s.Validate == nil {
		return CookieStatus{}, fmt.Errorf("cookie session validation is unavailable")
	}
	user, err := s.Validate(ctx, configured.URL, session)
	if err != nil {
		return CookieStatus{}, err
	}
	if err := s.Cookies.SaveCookie(profile, session); err != nil {
		return CookieStatus{}, fmt.Errorf("save cookie session: %w", err)
	}
	return CookieStatus{
		Profile:    profile,
		Site:       configured.URL,
		User:       user,
		ImportedAt: session.ImportedAt,
		HasCSRF:    session.CSRFToken != "",
	}, nil
}

func (s CookieService) Delete(requestedProfile string) error {
	profile, _, err := resolveProfile(s.Config, requestedProfile)
	if err != nil {
		return err
	}
	if s.Cookies == nil {
		return fmt.Errorf("cookie session store is unavailable")
	}
	if err := s.Cookies.DeleteCookie(profile); err != nil && !errors.Is(err, credential.ErrNotFound) {
		return fmt.Errorf("delete cookie session: %w", err)
	}
	return nil
}

func (s CookieService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
