package webterminal

import (
	"fmt"
	"net/url"
	"strings"
)

const terminalPath = "/koko/ws/terminal/"

// Endpoint 由 Profile 站点地址和连接令牌 ID 构造 KoKo WebSocket 地址。
// 站点使用 http/https，WebSocket 相应使用 ws/wss。
func Endpoint(site, tokenID string) (string, error) {
	if strings.TrimSpace(tokenID) == "" {
		return "", fmt.Errorf("connection token ID is empty")
	}
	parsed, err := url.Parse(site)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid JumpServer URL")
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("JumpServer URL must use http or https")
	}
	parsed.Path = terminalPath
	parsed.RawPath = ""
	parsed.Fragment = ""
	query := url.Values{}
	query.Set("token", tokenID)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
