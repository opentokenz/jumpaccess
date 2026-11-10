package webterminal

import (
	"encoding/json"
	"fmt"
)

// KoKo 消息类型，见 KoKo v4.0.2 pkg/httpd/message.go。
const (
	TypeConnect         = "CONNECT"
	TypeTerminalInit    = "TERMINAL_INIT"
	TypeTerminalSession = "TERMINAL_SESSION"
	TypeTerminalData    = "TERMINAL_DATA"
	TypeTerminalBinary  = "TERMINAL_BINARY"
	TypeTerminalResize  = "TERMINAL_RESIZE"
	TypePing            = "PING"
	TypePong            = "PONG"
	TypeClose           = "CLOSE"
	TypeError           = "ERROR"
)

// Message 是文本帧的统一信封；终端数据走二进制帧，不套信封。
type Message struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data string `json:"data"`
	Err  string `json:"err"`
}

// Size 是终端列数与行数。
type Size struct {
	Cols int
	Rows int
}

func (s Size) valid() bool { return s.Cols > 0 && s.Rows > 0 }

// SessionInfo 是 TERMINAL_SESSION 的 data 字段。
type SessionInfo struct {
	Session struct {
		ID        string `json:"id"`
		Asset     string `json:"asset"`
		Account   string `json:"account"`
		LoginFrom string `json:"login_from"`
		Protocol  string `json:"protocol"`
		Type      string `json:"type"`
	} `json:"session"`
	Permission struct {
		Actions []string `json:"actions"`
	} `json:"permission"`
	BackspaceAsCtrlH bool   `json:"backspaceAsCtrlH"`
	CtrlCAsCtrlZ     bool   `json:"ctrlCAsCtrlZ"`
	ThemeName        string `json:"themeName"`
}

type sizeData struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

func encodeMessage(id, messageType string, data any) ([]byte, error) {
	payload := ""
	if data != nil {
		encoded, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("encode %s data: %w", messageType, err)
		}
		payload = string(encoded)
	}
	return json.Marshal(Message{ID: id, Type: messageType, Data: payload})
}

func decodeMessage(payload []byte, target *Message) error {
	return json.Unmarshal(payload, target)
}

func decodeData(message Message, target any) error {
	if message.Data == "" {
		return fmt.Errorf("%s message has no data", message.Type)
	}
	return json.Unmarshal([]byte(message.Data), target)
}
