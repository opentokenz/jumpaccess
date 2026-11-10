package webterminal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cmstar/jumpaccess/internal/credential"
	"github.com/gorilla/websocket"
)

const (
	subprotocol       = "JMS-KOKO"
	writeTimeout      = 30 * time.Second
	defaultPingPeriod = 25 * time.Second
	closeGrace        = 5 * time.Second
)

var (
	// ErrSessionExpired 表示 WebSocket 握手被重定向到登录页或直接拒绝，通常是 Cookie 会话失效。
	ErrSessionExpired = errors.New("cookie session is invalid or expired")
	errSessionClosed  = errors.New("session closed")
)

type Options struct {
	URL       string
	Cookie    credential.CookieSession
	Size      Size
	Input     io.Reader
	Output    io.Writer
	Resize    <-chan Size
	Dialer    *websocket.Dialer
	OnSession func(SessionInfo)

	// PingInterval 覆盖保活间隔；KoKo 前端默认每 25 秒发送一次 PING 消息。
	PingInterval time.Duration
}

// Run 建立 KoKo WebSocket 终端并按协议转发输入输出，返回时表示会话已结束。
func Run(ctx context.Context, options Options) error {
	if options.Input == nil || options.Output == nil {
		return fmt.Errorf("web terminal requires input and output streams")
	}
	term, err := dialSession(ctx, options)
	if err != nil {
		return err
	}
	defer term.conn.Close()
	term.output = options.Output

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go term.pumpInput(runCtx, options.Input)
	term.startPumps(runCtx, options)

	err = term.readLoop()
	cancel()
	return err
}

// Stream 把终端二进制字节流暴露为 io.ReadWriter，用于在其上运行 ZMODEM 等流式协议。
type Stream struct {
	client *client
	reader *io.PipeReader
}

func (s *Stream) Read(p []byte) (int, error) { return s.reader.Read(p) }

func (s *Stream) Write(p []byte) (int, error) {
	if err := s.client.writeBinary(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// RunStream 把终端二进制字节流交给 handler，控制消息、resize 与保活仍由内部处理。
func RunStream(ctx context.Context, options Options, handler func(*Stream) error) error {
	if handler == nil {
		return fmt.Errorf("web terminal stream handler is required")
	}
	term, err := dialSession(ctx, options)
	if err != nil {
		return err
	}
	defer term.conn.Close()

	reader, writer := io.Pipe()
	term.binary = writer
	defer reader.Close()
	defer writer.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	term.startPumps(runCtx, options)

	transferred := make(chan error, 1)
	go func() {
		select {
		case <-term.ready:
		case <-runCtx.Done():
			transferred <- nil
			return
		}
		transferred <- handler(&Stream{client: term, reader: reader})
	}()

	readErr := term.readLoop()
	cancel()
	_ = writer.CloseWithError(io.EOF)
	if transferErr := <-transferred; transferErr != nil {
		return transferErr
	}
	return readErr
}

func dialSession(ctx context.Context, options Options) (*client, error) {
	dialer := options.Dialer
	if dialer == nil {
		dialer = websocket.DefaultDialer
	}
	configured := *dialer
	configured.Subprotocols = append([]string{subprotocol}, configured.Subprotocols...)

	header := http.Header{}
	if len(options.Cookie.Cookies) > 0 {
		header.Set("Cookie", options.Cookie.Header())
	}
	conn, response, err := configured.DialContext(ctx, options.URL, header)
	if err != nil {
		return nil, handshakeError(err, response)
	}
	return &client{conn: conn, onSession: options.OnSession, size: options.Size, ready: make(chan struct{})}, nil
}

func (c *client) startPumps(ctx context.Context, options Options) {
	if options.Resize != nil {
		go c.pumpResize(ctx, options.Resize)
	}
	interval := options.PingInterval
	if interval <= 0 {
		interval = defaultPingPeriod
	}
	go c.keepAlive(ctx, interval)
}

func handshakeError(err error, response *http.Response) error {
	if response == nil {
		return fmt.Errorf("connect to JumpServer web terminal: %w", err)
	}
	// 未认证时 KoKo 返回 302 到 /core/auth/login/；跟随重定向后最终状态可能是登录页的 200。
	redirected := response.Request != nil && response.Request.URL != nil && response.Request.URL.Path != terminalPath
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: handshake returned HTTP %d; run jumpctl auth import-cookie", ErrSessionExpired, response.StatusCode)
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return fmt.Errorf("%w: handshake was redirected (HTTP %d) to the login page; run jumpctl auth import-cookie", ErrSessionExpired, response.StatusCode)
	case redirected:
		return fmt.Errorf("%w: handshake was redirected to the login page; run jumpctl auth import-cookie", ErrSessionExpired)
	default:
		return fmt.Errorf("connect to JumpServer web terminal: handshake returned HTTP %d (expected 101)", response.StatusCode)
	}
}

type client struct {
	conn      *websocket.Conn
	output    io.Writer
	binary    io.Writer
	onSession func(SessionInfo)

	writeMu sync.Mutex
	mu      sync.Mutex
	id      string
	size    Size

	// ready 在 TERMINAL_INIT 发出后关闭，避免输入早于初始化被服务端丢弃。
	ready     chan struct{}
	readyOnce sync.Once
	closing   atomic.Bool
}

func (c *client) readLoop() error {
	for {
		messageType, payload, err := c.conn.ReadMessage()
		if err != nil {
			if c.closing.Load() || websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			return fmt.Errorf("web terminal connection closed: %w", err)
		}
		switch messageType {
		case websocket.BinaryMessage:
			target := c.output
			if c.binary != nil {
				target = c.binary
			}
			if target == nil {
				continue
			}
			if _, err := target.Write(payload); err != nil {
				return fmt.Errorf("write terminal output: %w", err)
			}
		case websocket.TextMessage:
			var message Message
			if err := decodeMessage(payload, &message); err != nil {
				// 无法解析的文本帧不影响已建立的终端会话。
				continue
			}
			if err := c.handle(message); err != nil {
				if errors.Is(err, errSessionClosed) {
					return nil
				}
				return err
			}
		}
	}
}

func (c *client) handle(message Message) error {
	switch message.Type {
	case TypeConnect:
		if message.ID == "" {
			return fmt.Errorf("CONNECT message has no connection id")
		}
		c.mu.Lock()
		c.id = message.ID
		size := c.size
		c.mu.Unlock()
		if !size.valid() {
			// 拿不到本地终端尺寸时使用传统 80x24，避免初始化失败。
			size = Size{Cols: 80, Rows: 24}
		}
		payload, err := encodeMessage(message.ID, TypeTerminalInit, sizeData{Cols: size.Cols, Rows: size.Rows})
		if err != nil {
			return err
		}
		if err := c.writeText(payload); err != nil {
			return err
		}
		c.readyOnce.Do(func() { close(c.ready) })
		return nil
	case TypeTerminalSession:
		var info SessionInfo
		if err := decodeData(message, &info); err != nil {
			return fmt.Errorf("decode TERMINAL_SESSION: %w", err)
		}
		if c.onSession != nil {
			c.onSession(info)
		}
		return nil
	case TypeClose:
		return errSessionClosed
	case TypeError, "TERMINAL_ERROR":
		if message.Err == "" {
			return fmt.Errorf("JumpServer web terminal reported an error")
		}
		return fmt.Errorf("JumpServer web terminal: %s", message.Err)
	default:
		return nil
	}
}

func (c *client) pumpInput(ctx context.Context, input io.Reader) {
	select {
	case <-ctx.Done():
		return
	case <-c.ready:
	}
	buffer := make([]byte, 4096)
	for {
		n, err := input.Read(buffer)
		if n > 0 {
			if writeErr := c.writeBinary(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && c.closing.CompareAndSwap(false, true) {
				_ = c.sendClose()
				// 远端没有及时回 CLOSE 时主动断开，避免进程退出前一直等待。
				time.AfterFunc(closeGrace, func() { _ = c.conn.Close() })
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (c *client) pumpResize(ctx context.Context, resize <-chan Size) {
	for {
		select {
		case <-ctx.Done():
			return
		case size, ok := <-resize:
			if !ok {
				return
			}
			if !size.valid() {
				continue
			}
			c.mu.Lock()
			c.size = size
			id := c.id
			c.mu.Unlock()
			if id == "" {
				// CONNECT 之前的尺寸变化由 TERMINAL_INIT 使用最新值。
				continue
			}
			payload, err := encodeMessage(id, TypeTerminalResize, sizeData{Cols: size.Cols, Rows: size.Rows})
			if err != nil {
				continue
			}
			if err := c.writeText(payload); err != nil {
				return
			}
		}
	}
}

// keepAlive 发送协议内的 PING 消息。KoKo 忽略该消息，但接收它会重置服务端 5 分钟的读取期限。
func (c *client) keepAlive(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			id := c.id
			c.mu.Unlock()
			if id == "" {
				continue
			}
			payload, err := encodeMessage(id, TypePing, nil)
			if err != nil {
				continue
			}
			if err := c.writeText(payload); err != nil {
				return
			}
		}
	}
}

func (c *client) sendClose() error {
	c.mu.Lock()
	id := c.id
	c.mu.Unlock()
	if id == "" {
		return nil
	}
	payload, err := encodeMessage(id, TypeClose, nil)
	if err != nil {
		return err
	}
	return c.writeText(payload)
}

func (c *client) writeText(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return c.conn.WriteMessage(websocket.TextMessage, payload)
}

func (c *client) writeBinary(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return c.conn.WriteMessage(websocket.BinaryMessage, payload)
}
