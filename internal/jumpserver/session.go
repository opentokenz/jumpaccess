package jumpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrCookieSessionInvalid 表示导入的浏览器 Cookie 已过期、被注销或不属于当前账号。
	ErrCookieSessionInvalid = errors.New("cookie session is invalid or expired")
	// ErrCookieSessionRequired 表示该操作需要 Cookie 会话，而当前会话只有 OAuth 凭据。
	ErrCookieSessionRequired = errors.New("cookie session is required")
)

type userProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

// ValidateSession 用用户资料接口确认当前凭据仍然有效，返回登录用户名。
// Cookie 失效时给出可操作的提示，避免把 302/403 直接暴露给用户。
func (c *Client) ValidateSession(ctx context.Context) (string, error) {
	var profile userProfile
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/users/profile/", nil, http.StatusOK, &profile); err != nil {
		if c.session.IsCookie() {
			return "", fmt.Errorf("%w: %v; run jumpctl auth import-cookie", ErrCookieSessionInvalid, err)
		}
		return "", err
	}
	if profile.Username == "" {
		if c.session.IsCookie() {
			return "", fmt.Errorf("%w: user profile response is incomplete", ErrCookieSessionInvalid)
		}
		return "", fmt.Errorf("user profile response is incomplete")
	}
	return profile.Username, nil
}
