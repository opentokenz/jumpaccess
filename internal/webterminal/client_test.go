package webterminal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cmstar/jumpaccess/internal/credential"
	"github.com/gorilla/websocket"
)

func TestEndpointUsesWebSocketSchemeAndKokoPath(t *testing.T) {
	for _, test := range []struct {
		site string
		want string
	}{
		{"http://172.16.251.2", "ws://172.16.251.2/koko/ws/terminal/?token=token-1"},
		{"https://jump.example.test/", "wss://jump.example.test/koko/ws/terminal/?token=token-1"},
	} {
		got, err := Endpoint(test.site, "token-1")
		if err != nil {
			t.Fatalf("Endpoint(%q) error: %v", test.site, err)
		}
		if got != test.want {
			t.Fatalf("Endpoint(%q) = %q, want %q", test.site, got, test.want)
		}
	}
	if _, err := Endpoint("ftp://jump.example.test", "token-1"); err == nil {
		t.Fatal("unsupported scheme accepted")
	}
	if _, err := Endpoint("http://jump.example.test", ""); err == nil {
		t.Fatal("empty token accepted")
	}
}

type kokoCapture struct {
	init      Message
	initSize  sizeData
	input     string
	session   bool
	resize    Message
	resizeVal sizeData
}

func cookieForTests() credential.CookieSession {
	return credential.CookieSession{
		Site: "http://jump.example.test",
		Cookies: []credential.Cookie{
			{Name: "jms_sessionid", Value: "session-value"},
		},
	}
}

func upgradeForTest(t *testing.T, w http.ResponseWriter, r *http.Request) *websocket.Conn {
	t.Helper()
	if token := r.URL.Query().Get("token"); token != "token-1" {
		t.Errorf("token query = %q", token)
	}
	if protocol := r.Header.Get("Sec-WebSocket-Protocol"); !strings.Contains(protocol, subprotocol) {
		t.Errorf("subprotocol = %q", protocol)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "jms_sessionid=session-value" {
		t.Errorf("cookie header = %q", cookie)
	}
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{subprotocol},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		t.Errorf("upgrade: %v", err)
		return nil
	}
	return conn
}

func sendConnect(t *testing.T, conn *websocket.Conn, id string) {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"user":    map[string]string{"username": "root"},
		"setting": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(Message{ID: id, Type: TypeConnect, Data: string(data)}); err != nil {
		t.Errorf("write CONNECT: %v", err)
	}
}

func TestRunInitializesFromConnectIDAndBridgesTerminalData(t *testing.T) {
	results := make(chan kokoCapture, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeForTest(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		sendConnect(t, conn, "ws-connection-1")

		var capture kokoCapture
		done := func() bool { return capture.init.Type != "" && capture.input == "ls\n" }
		finish := func() {
			results <- capture
			_ = conn.WriteJSON(Message{ID: "ws-connection-1", Type: TypeClose})
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(deadline)
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if messageType == websocket.BinaryMessage {
				capture.input += string(payload)
				if done() {
					finish()
					return
				}
				continue
			}
			var message Message
			if json.Unmarshal(payload, &message) != nil {
				continue
			}
			if message.Type == TypeTerminalInit && capture.init.Type == "" {
				capture.init = message
				_ = json.Unmarshal([]byte(message.Data), &capture.initSize)
				sessionData, _ := json.Marshal(map[string]any{
					"session":    map[string]string{"id": "audit-1", "asset": "app-1(10.0.0.1)", "account": "root(root)"},
					"permission": map[string]any{"actions": []string{"connect"}},
					"themeName":  "Default",
				})
				_ = conn.WriteJSON(Message{ID: "ws-connection-1", Type: TypeTerminalSession, Data: string(sessionData)})
				_ = conn.WriteMessage(websocket.BinaryMessage, []byte("hello\r\n"))
				if done() {
					finish()
					return
				}
			}
		}
		results <- capture
	}))
	defer server.Close()

	var output bytes.Buffer
	session := make(chan SessionInfo, 1)
	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), Options{
		URL:    endpoint,
		Cookie: cookieForTests(),
		Size:   Size{Cols: 132, Rows: 43},
		Input:  strings.NewReader("ls\n"),
		Output: &output,
		OnSession: func(info SessionInfo) {
			session <- info
		},
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	capture := <-results
	if capture.init.ID != "ws-connection-1" || capture.init.Type != TypeTerminalInit {
		t.Fatalf("TERMINAL_INIT = %#v", capture.init)
	}
	if capture.initSize.Cols != 132 || capture.initSize.Rows != 43 {
		t.Fatalf("TERMINAL_INIT size = %#v", capture.initSize)
	}
	if capture.input != "ls\n" {
		t.Fatalf("terminal input = %q", capture.input)
	}
	if output.String() != "hello\r\n" {
		t.Fatalf("terminal output = %q", output.String())
	}
	select {
	case info := <-session:
		if info.Session.Asset != "app-1(10.0.0.1)" || info.Session.Account != "root(root)" {
			t.Fatalf("session info = %#v", info)
		}
	case <-time.After(time.Second):
		t.Fatal("TERMINAL_SESSION was not reported")
	}
}

func TestRunSendsResizeWithConnectID(t *testing.T) {
	resized := make(chan kokoCapture, 1)
	initReceived := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeForTest(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		sendConnect(t, conn, "ws-resize-1")

		var capture kokoCapture
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(deadline)
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if messageType != websocket.TextMessage {
				continue
			}
			var message Message
			if json.Unmarshal(payload, &message) != nil {
				continue
			}
			switch message.Type {
			case TypeTerminalInit:
				capture.init = message
				close(initReceived)
			case TypeTerminalResize:
				capture.resize = message
				_ = json.Unmarshal([]byte(message.Data), &capture.resizeVal)
				resized <- capture
				_ = conn.WriteJSON(Message{ID: "ws-resize-1", Type: TypeClose})
				return
			}
		}
		resized <- capture
	}))
	defer server.Close()

	input, inputWriter := io.Pipe()
	defer inputWriter.Close()
	resize := make(chan Size, 1)
	go func() {
		<-initReceived
		resize <- Size{Cols: 100, Rows: 30}
	}()
	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), Options{
		URL:    endpoint,
		Cookie: cookieForTests(),
		Size:   Size{Cols: 80, Rows: 24},
		Input:  input,
		Output: io.Discard,
		Resize: resize,
	}); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	capture := <-resized
	if capture.init.ID != "ws-resize-1" {
		t.Fatalf("TERMINAL_INIT = %#v", capture.init)
	}
	if capture.resize.ID != "ws-resize-1" || capture.resize.Type != TypeTerminalResize {
		t.Fatalf("TERMINAL_RESIZE = %#v", capture.resize)
	}
	if capture.resizeVal.Cols != 100 || capture.resizeVal.Rows != 30 {
		t.Fatalf("resize size = %#v", capture.resizeVal)
	}
}

func TestRunReportsExpiredSessionOnRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/koko/ws/terminal/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/core/auth/login/", http.StatusFound)
	})
	mux.HandleFunc("/core/auth/login/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>login</html>"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), Options{URL: endpoint, Cookie: cookieForTests(), Input: strings.NewReader(""), Output: io.Discard})
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Run error = %v, want ErrSessionExpired", err)
	}
}

func TestRunReportsForbiddenHandshake(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), Options{URL: endpoint, Cookie: cookieForTests(), Input: strings.NewReader(""), Output: io.Discard})
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Run error = %v, want ErrSessionExpired", err)
	}
}

func TestRunReturnsServerErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeForTest(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(Message{ID: "ws-1", Type: TypeError, Err: "Token invalid"})
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()

	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), Options{URL: endpoint, Cookie: cookieForTests(), Input: strings.NewReader(""), Output: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "Token invalid") {
		t.Fatalf("Run error = %v", err)
	}
}

func TestRunSendsProtocolPingAfterConnect(t *testing.T) {
	pingSeen := make(chan Message, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeForTest(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		sendConnect(t, conn, "ws-ping-1")
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(deadline)
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if messageType != websocket.TextMessage {
				continue
			}
			var message Message
			if json.Unmarshal(payload, &message) != nil {
				continue
			}
			if message.Type == TypePing {
				pingSeen <- message
				_ = conn.WriteJSON(Message{ID: "ws-ping-1", Type: TypeClose})
				return
			}
		}
	}))
	defer server.Close()

	input, inputWriter := io.Pipe()
	defer inputWriter.Close()
	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), Options{
		URL:          endpoint,
		Cookie:       cookieForTests(),
		Size:         Size{Cols: 80, Rows: 24},
		Input:        input,
		Output:       io.Discard,
		PingInterval: 20 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	select {
	case message := <-pingSeen:
		if message.ID != "ws-ping-1" || message.Type != TypePing {
			t.Fatalf("PING = %#v", message)
		}
	case <-time.After(time.Second):
		t.Fatal("keepalive PING was not sent")
	}
}

func TestRunStreamBridgesBinaryBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeForTest(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		sendConnect(t, conn, "ws-stream-1")
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(deadline)
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if messageType == websocket.TextMessage {
				var message Message
				if json.Unmarshal(payload, &message) == nil && message.Type == TypeTerminalInit {
					_ = conn.WriteMessage(websocket.BinaryMessage, []byte("in"))
					continue
				}
			}
			if messageType == websocket.BinaryMessage && string(payload) == "out" {
				_ = conn.WriteJSON(Message{ID: "ws-stream-1", Type: TypeClose})
				return
			}
		}
	}))
	defer server.Close()

	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	err = RunStream(context.Background(), Options{
		URL:    endpoint,
		Cookie: cookieForTests(),
		Size:   Size{Cols: 80, Rows: 24},
	}, func(stream *Stream) error {
		buffer := make([]byte, 2)
		if _, err := io.ReadFull(stream, buffer); err != nil {
			return err
		}
		if string(buffer) != "in" {
			t.Errorf("stream input = %q", buffer)
		}
		if _, err := stream.Write([]byte("out")); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, stream)
		return err
	})
	if err != nil {
		t.Fatalf("RunStream error: %v", err)
	}
}

func TestRunStreamDoesNotHangWhenSessionFailsBeforeInit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeForTest(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(Message{ID: "ws-1", Type: TypeError, Err: "Token invalid"})
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	err = RunStream(context.Background(), Options{URL: endpoint, Cookie: cookieForTests()}, func(stream *Stream) error {
		_, err := io.Copy(io.Discard, stream)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "Token invalid") {
		t.Fatalf("RunStream error = %v", err)
	}
}
