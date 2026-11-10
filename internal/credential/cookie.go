package credential

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Cookie 是浏览器 Cookie 的名值对。值等同于登录凭据，不得写入配置或日志。
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CookieSession 保存用户手工导入的浏览器会话。Site 限定发送目标，不跟随 Cookie 自身 Domain。
type CookieSession struct {
	Site        string    `json:"site"`
	Cookies     []Cookie  `json:"cookies"`
	CSRFToken   string    `json:"csrf_token,omitempty"`
	ImportedAt  time.Time `json:"imported_at"`
	ValidatedAt time.Time `json:"validated_at,omitempty"`
}

// Session 是一次 API 调用使用的凭据，OAuth Token 与 Cookie 会话互斥。
type Session struct {
	Token  Token
	Cookie CookieSession
}

func (s Session) IsCookie() bool { return s.Token.AccessToken == "" }

// Header 返回 Cookie 请求头的值，顺序与导入时一致。
func (s CookieSession) Header() string {
	parts := make([]string, 0, len(s.Cookies))
	for _, cookie := range s.Cookies {
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

func (r Repository) LoadCookie(profile string) (CookieSession, error) {
	key, err := cookieKey(profile)
	if err != nil {
		return CookieSession{}, err
	}
	data, err := r.Backend.Get(key)
	if err != nil {
		return CookieSession{}, err
	}
	defer clear(data)
	var session CookieSession
	if err := json.Unmarshal(data, &session); err != nil {
		return CookieSession{}, fmt.Errorf("decode stored cookie session: %w", err)
	}
	if err := session.Validate(); err != nil {
		return CookieSession{}, fmt.Errorf("stored cookie session is incomplete: %w", err)
	}
	return session, nil
}

func (r Repository) SaveCookie(profile string, session CookieSession) error {
	key, err := cookieKey(profile)
	if err != nil {
		return err
	}
	if err := session.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode cookie session: %w", err)
	}
	defer clear(data)
	return r.Backend.Set(key, data)
}

func (r Repository) DeleteCookie(profile string) error {
	key, err := cookieKey(profile)
	if err != nil {
		return err
	}
	return r.Backend.Delete(key)
}

func (s CookieSession) Validate() error {
	if strings.TrimSpace(s.Site) == "" {
		return fmt.Errorf("cookie session site is empty")
	}
	if len(s.Cookies) == 0 {
		return fmt.Errorf("cookie session has no cookies")
	}
	for _, cookie := range s.Cookies {
		if err := cookie.Validate(); err != nil {
			return err
		}
	}
	if strings.ContainsAny(s.CSRFToken, "\r\n\x00") {
		return fmt.Errorf("CSRF token is invalid")
	}
	return nil
}

func (c Cookie) Validate() error {
	if c.Name == "" || strings.ContainsAny(c.Name, "=;\r\n\t \x00") {
		return fmt.Errorf("cookie name is invalid")
	}
	if c.Value == "" || strings.ContainsAny(c.Value, ";\r\n\x00") {
		return fmt.Errorf("cookie %q has an invalid value", c.Name)
	}
	if !utf8.ValidString(c.Name) || !utf8.ValidString(c.Value) {
		return fmt.Errorf("cookie %q is not valid UTF-8", c.Name)
	}
	return nil
}

// ParseCookieHeader 接受浏览器开发者工具复制的 Cookie 串，允许带 "Cookie:" 前缀。
func ParseCookieHeader(raw string) ([]Cookie, error) {
	value := strings.TrimSpace(raw)
	if len(value) >= len("cookie:") && strings.EqualFold(value[:len("cookie:")], "cookie:") {
		value = strings.TrimSpace(value[len("cookie:"):])
	}
	if value == "" {
		return nil, fmt.Errorf("cookie string is empty")
	}
	if len(value) > 16<<10 {
		return nil, fmt.Errorf("cookie string is too long")
	}
	var cookies []Cookie
	index := make(map[string]int)
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, cookieValue, found := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		cookie := Cookie{Name: name, Value: strings.TrimSpace(cookieValue)}
		if !found {
			return nil, fmt.Errorf("cookie %q has no value", name)
		}
		if err := cookie.Validate(); err != nil {
			return nil, err
		}
		if existing, ok := index[name]; ok {
			cookies[existing] = cookie
			continue
		}
		index[name] = len(cookies)
		cookies = append(cookies, cookie)
	}
	if len(cookies) == 0 {
		return nil, fmt.Errorf("cookie string has no cookies")
	}
	return cookies, nil
}

// CSRFTokenFromCookies 取名称以 csrftoken 结尾的 Cookie；JumpServer 默认名为 jms_csrftoken。
func CSRFTokenFromCookies(cookies []Cookie) string {
	for _, cookie := range cookies {
		if strings.HasSuffix(strings.ToLower(cookie.Name), "csrftoken") {
			return cookie.Value
		}
	}
	return ""
}

func cookieKey(profile string) (string, error) {
	if strings.TrimSpace(profile) == "" {
		return "", fmt.Errorf("invalid profile name")
	}
	return "cookie/" + profile, nil
}
