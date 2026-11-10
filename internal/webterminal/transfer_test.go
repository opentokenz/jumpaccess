package webterminal

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cmstar/jumpaccess/internal/clitransfer"
	"github.com/cmstar/jumpaccess/internal/zmodem"
	"github.com/gorilla/websocket"
)

// wsBytes 在测试中把 WebSocket 二进制帧当作连续字节流，模拟远端 rz/sz。
type wsBytes struct {
	conn   *websocket.Conn
	buffer []byte
}

func (w *wsBytes) Read(p []byte) (int, error) {
	for len(w.buffer) == 0 {
		messageType, payload, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		w.buffer = append(w.buffer, payload...)
	}
	n := copy(p, w.buffer)
	w.buffer = w.buffer[n:]
	return n, nil
}

func (w *wsBytes) ReadByte() (byte, error) {
	var value [1]byte
	_, err := io.ReadFull(w, value[:])
	return value[0], err
}

func (w *wsBytes) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

type transferDisplay struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (d *transferDisplay) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.data.Write(p)
}

func (d *transferDisplay) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.data.String()
}

func (d *transferDisplay) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(d.String(), text) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing %q in %q", text, d.String())
}

// startTransferPeer 建立 KoKo 终端会话并把二进制流交给 peer。
func startTransferPeer(t *testing.T, peer func(*wsBytes)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := upgradeForTest(t, w, r)
		if conn == nil {
			return
		}
		defer conn.Close()
		sendConnect(t, conn, "ws-transfer-1")
		for {
			_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if messageType != websocket.TextMessage {
				continue
			}
			var message Message
			if json.Unmarshal(payload, &message) != nil || message.Type != TypeTerminalInit {
				continue
			}
			peer(&wsBytes{conn: conn})
			_ = conn.WriteJSON(Message{ID: "ws-transfer-1", Type: TypeClose})
			return
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// zmodemHexHeader 构造标准十六进制起始帧；远端 sz 先发 ZRQINIT 触发下载。
func zmodemHexHeader(kind byte, value uint32) []byte {
	raw := []byte{kind, byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	crc := testCRC16(raw)
	raw = append(raw, byte(crc>>8), byte(crc))
	var buffer bytes.Buffer
	buffer.WriteString("**\x18B")
	buffer.WriteString(hex.EncodeToString(raw))
	buffer.WriteString("\r\n")
	return buffer.Bytes()
}

func testCRC16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func TestRunStreamDownloadsZmodemFile(t *testing.T) {
	payload := bytes.Repeat([]byte("webssh zmodem download\n"), 500)
	server := startTransferPeer(t, func(peer *wsBytes) {
		if _, err := peer.Write(zmodemHexHeader(0, 0)); err != nil {
			t.Errorf("write ZRQINIT: %v", err)
			return
		}
		_, err := zmodem.Send(peer, peer, zmodem.Upload{Name: "remote.txt", Size: int64(len(payload)), Reader: bytes.NewReader(payload)}, zmodem.SendOptions{})
		if err != nil {
			t.Errorf("zmodem send: %v", err)
		}
	})

	directory := t.TempDir()
	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	keyboard, keys := io.Pipe()
	defer keyboard.Close()
	defer keys.Close()
	var display transferDisplay
	err = RunStream(context.Background(), Options{URL: endpoint, Cookie: cookieForTests(), Size: Size{Cols: 80, Rows: 24}}, func(stream *Stream) error {
		return clitransfer.Run(context.Background(), keyboard, &display, stream, stream, clitransfer.Options{DownloadDirectory: directory})
	})
	if err != nil {
		t.Fatalf("RunStream error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(directory, "remote.txt"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("downloaded file: %v, %d bytes", err, len(got))
	}
}

func TestRunStreamUploadsZmodemFile(t *testing.T) {
	payload := bytes.Repeat([]byte("webssh zmodem upload\n"), 500)
	directory := t.TempDir()
	source := filepath.Join(directory, "local.txt")
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	received := make(chan []byte, 1)
	server := startTransferPeer(t, func(peer *wsBytes) {
		var buffer bytes.Buffer
		err := zmodem.Receive(peer, peer, zmodem.ReceiveOptions{
			Open: func(name string, size int64) (zmodem.Download, error) {
				if name != "local.txt" {
					t.Errorf("uploaded name = %q", name)
				}
				return zmodem.Download{
					Write: func(data []byte) error { _, err := buffer.Write(data); return err },
					Close: func(bool) error { return nil },
				}, nil
			},
		})
		if err != nil {
			t.Errorf("zmodem receive: %v", err)
		}
		received <- buffer.Bytes()
	})

	endpoint, err := Endpoint(server.URL, "token-1")
	if err != nil {
		t.Fatal(err)
	}
	keyboard, keys := io.Pipe()
	defer keyboard.Close()
	defer keys.Close()
	var display transferDisplay
	go func() {
		display.waitFor(t, "Local file to upload")
		_, _ = io.WriteString(keys, strconv.Quote(source)+"\r")
	}()
	err = RunStream(context.Background(), Options{URL: endpoint, Cookie: cookieForTests(), Size: Size{Cols: 80, Rows: 24}}, func(stream *Stream) error {
		return clitransfer.Run(context.Background(), keyboard, &display, stream, stream, clitransfer.Options{DownloadDirectory: directory})
	})
	if err != nil {
		t.Fatalf("RunStream error: %v", err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatalf("uploaded content mismatch: %d bytes", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer did not receive the uploaded file")
	}
}
