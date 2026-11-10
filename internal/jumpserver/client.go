package jumpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cmstar/jumpaccess/internal/credential"
)

type Client struct {
	baseURL    *url.URL
	session    credential.Session
	orgID      string
	httpClient *http.Client
	Timezone   string
}

func NewClient(site, accessToken, organization string, httpClient *http.Client) (*Client, error) {
	return NewSessionClient(site, credential.Session{Token: credential.Token{AccessToken: accessToken}}, organization, httpClient)
}

// NewSessionClient 按会话中的 OAuth Token 或导入的 Cookie 认证，两者互斥。
func NewSessionClient(site string, session credential.Session, organization string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(site)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid JumpServer URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, fmt.Errorf("JumpServer URL must contain only scheme and host")
	}
	hasToken := session.Token.AccessToken != ""
	hasCookie := len(session.Cookie.Cookies) > 0
	if hasToken == hasCookie {
		return nil, fmt.Errorf("JumpServer session must contain exactly one credential")
	}
	parsed.Path = "/"
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: parsed, session: session, orgID: organization, httpClient: httpClient, Timezone: localTimezone()}, nil
}

func (c *Client) ListOrganizations(ctx context.Context) ([]Organization, error) {
	var permissions struct {
		PAM       []Organization `json:"pam_orgs"`
		Audit     []Organization `json:"audit_orgs"`
		Console   []Organization `json:"console_orgs"`
		Workbench []Organization `json:"workbench_orgs"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/users/profile/permissions/", nil, http.StatusOK, &permissions); err != nil {
		return nil, err
	}
	byID := make(map[string]Organization)
	for _, group := range [][]Organization{permissions.PAM, permissions.Audit, permissions.Console, permissions.Workbench} {
		for _, organization := range group {
			if organization.ID != "" {
				byID[organization.ID] = organization
			}
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]Organization, 0, len(ids))
	for _, id := range ids {
		result = append(result, byID[id])
	}
	return result, nil
}

func (c *Client) ListAssets(ctx context.Context, query AssetQuery) (AssetPage, error) {
	values := url.Values{}
	setIfNotEmpty(values, "type", query.Type)
	setIfNotEmpty(values, "category", query.Category)
	setIfNotEmpty(values, "search", query.Search)
	setIfNotEmpty(values, "order", query.Order)
	if query.Offset > 0 {
		values.Set("offset", strconv.Itoa(query.Offset))
	}
	if query.Limit > 0 {
		values.Set("limit", strconv.Itoa(query.Limit))
	}
	if c.orgID != "" {
		values.Set("oid", c.orgID)
	}
	requestPath := "/api/v1/perms/users/self/assets/"
	if encoded := values.Encode(); encoded != "" {
		requestPath += "?" + encoded
	}
	var page AssetPage
	if err := c.doJSON(ctx, http.MethodGet, requestPath, nil, http.StatusOK, &page); err != nil {
		return AssetPage{}, err
	}
	return page, nil
}

func (c *Client) GetAsset(ctx context.Context, id string) (AssetDetail, error) {
	if strings.TrimSpace(id) == "" {
		return AssetDetail{}, fmt.Errorf("asset ID is required")
	}
	var asset AssetDetail
	requestPath := "/api/v1/perms/users/self/assets/" + url.PathEscape(id) + "/"
	if err := c.doJSON(ctx, http.MethodGet, requestPath, nil, http.StatusOK, &asset); err != nil {
		return AssetDetail{}, err
	}
	return asset, nil
}

func (c *Client) CreateConnectionToken(ctx context.Context, request ConnectionRequest) (string, error) {
	if request.Asset == "" {
		return "", fmt.Errorf("asset ID is required")
	}
	if request.Protocol == "" {
		request.Protocol = "ssh"
	}
	if request.Protocol != "ssh" && request.Protocol != "sftp" {
		return "", fmt.Errorf("connection protocol %q is not supported", request.Protocol)
	}
	if request.ConnectMethod == "" {
		request.ConnectMethod = request.Protocol + "_client"
	}
	request.ConnectOptions = ConnectionOptions{TokenReusable: false, DisableAutoHash: false}
	var response json.RawMessage
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/authentication/connection-token/", request, http.StatusCreated, &response); err != nil {
		return "", err
	}
	var object struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response, &object); err != nil || object.ID == "" {
		var id string
		if stringErr := json.Unmarshal(response, &id); stringErr != nil || id == "" {
			return "", fmt.Errorf("connection-token response is incomplete")
		}
		return id, nil
	}
	return object.ID, nil
}

func (c *Client) GetClientConnection(ctx context.Context, connectionTokenID string) (ClientConnection, error) {
	if connectionTokenID == "" {
		return ClientConnection{}, fmt.Errorf("connection token ID is required")
	}
	var response struct {
		URL string `json:"url"`
	}
	requestPath := "/api/v1/authentication/connection-token/" + url.PathEscape(connectionTokenID) + "/client-url/"
	if err := c.doJSON(ctx, http.MethodGet, requestPath, nil, http.StatusOK, &response); err != nil {
		return ClientConnection{}, err
	}
	return DecodeClientURL(response.URL)
}

func (c *Client) doJSON(ctx context.Context, method, requestPath string, body any, expectedStatus int, target any) error {
	endpoint, err := c.baseURL.Parse(requestPath)
	if err != nil {
		return fmt.Errorf("build JumpServer API URL: %w", err)
	}
	var encoded io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode JumpServer API request: %w", err)
		}
		defer clear(data)
		encoded = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), encoded)
	if err != nil {
		return fmt.Errorf("create JumpServer API request: %w", err)
	}
	if c.session.IsCookie() {
		request.Header.Set("Cookie", c.session.Cookie.Header())
		// JumpServer 的 Session 认证会校验 CSRF，失败时静默降级为未认证。
		if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions {
			if c.session.Cookie.CSRFToken == "" {
				return fmt.Errorf("cookie session has no CSRF token; re-import the browser Cookie header including csrftoken")
			}
			request.Header.Set("X-CSRFToken", c.session.Cookie.CSRFToken)
		}
	} else {
		request.Header.Set("Authorization", "Bearer "+c.session.Token.AccessToken)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Referer", c.baseURL.String())
	request.Header.Set("X-TZ", c.Timezone)
	if c.orgID != "" {
		request.Header.Set("X-JMS-ORG", c.orgID)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call JumpServer API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		if code := errorCode(response.Body); code != "" {
			return fmt.Errorf("JumpServer API %s %s returned HTTP %d (%s)", method, endpoint.Path, response.StatusCode, code)
		}
		return fmt.Errorf("JumpServer API %s %s returned HTTP %d", method, endpoint.Path, response.StatusCode)
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(target); err != nil {
		return fmt.Errorf("decode JumpServer API response: %w", err)
	}
	return nil
}

// errorCode 只返回服务端错误码。响应正文可能回显请求内容，不能整体写入错误信息。
func errorCode(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, 1024))
	if err != nil {
		return ""
	}
	var payload struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(data, &payload) != nil || !validErrorCode(payload.Code) {
		return ""
	}
	return payload.Code
}

// validErrorCode 只接受小写标识符形状的错误码，避免把任意文本带入输出。
func validErrorCode(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for index, character := range code {
		switch {
		case character >= 'a' && character <= 'z':
		case character == '_':
		case character >= '0' && character <= '9' && index > 0:
		default:
			return false
		}
	}
	return true
}

func setIfNotEmpty(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

func localTimezone() string {
	_, seconds := time.Now().Zone()
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	return fmt.Sprintf("%s%02d:%02d", sign, seconds/3600, seconds%3600/60)
}
