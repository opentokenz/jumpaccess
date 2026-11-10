package webterminal

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/cmstar/jumpaccess/internal/clitransfer"
	"github.com/cmstar/jumpaccess/internal/credential"
	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// TTYOptions 绑定本机终端与已经申请好的 KoKo 会话。Cookie 与令牌只用于连接，不输出。
type TTYOptions struct {
	URL     string
	Cookie  credential.CookieSession
	Asset   string
	Account string
	Stdin   *os.File
	Stdout  io.Writer
	Stderr  io.Writer
	Dialer  *websocket.Dialer

	// Transfer 启用 ZMODEM rz/sz，与直接 SSH 的交互一致；DownloadDirectory 为空时使用系统下载目录。
	Transfer          bool
	DownloadDirectory string
}

// RunTTY 把本机终端切到 Raw 模式并在退出时恢复，期间与 KoKo 双向转发终端数据。
func RunTTY(ctx context.Context, options TTYOptions) error {
	if options.Stdin == nil {
		return fmt.Errorf("standard input is unavailable")
	}
	fd := int(options.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("webssh requires an interactive terminal; run it directly in a shell")
	}
	cols, rows, err := term.GetSize(fd)
	if err != nil || cols <= 0 || rows <= 0 {
		cols, rows = 80, 24
	}
	stderr := options.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	fmt.Fprintln(stderr, "Connecting to JumpServer via WebSocket...")

	state, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("switch local terminal to raw mode: %w", err)
	}
	defer func() {
		if restoreErr := term.Restore(fd, state); restoreErr != nil {
			fmt.Fprintf(stderr, "\r\nwarning: restore terminal state: %v\r\n", restoreErr)
		}
	}()

	resizeCtx, stopResize := context.WithCancel(ctx)
	defer stopResize()

	wsOptions := Options{
		URL:    options.URL,
		Cookie: options.Cookie,
		Size:   Size{Cols: cols, Rows: rows},
		Resize: sizeEvents(resizeCtx, fd),
		Dialer: options.Dialer,
		OnSession: func(SessionInfo) {
			fmt.Fprintf(stderr, "\r\nConnected: %s / %s\r\n", options.Asset, options.Account)
		},
	}
	if options.Transfer {
		err = RunStream(ctx, wsOptions, func(stream *Stream) error {
			return clitransfer.Run(ctx, options.Stdin, options.Stdout, stream, stream, clitransfer.Options{DownloadDirectory: options.DownloadDirectory})
		})
	} else {
		wsOptions.Input = options.Stdin
		wsOptions.Output = options.Stdout
		err = Run(ctx, wsOptions)
	}
	if err != nil {
		fmt.Fprint(stderr, "\r\n")
	}
	return err
}
