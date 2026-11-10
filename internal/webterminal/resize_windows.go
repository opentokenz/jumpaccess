//go:build windows

package webterminal

import (
	"context"
	"time"

	"golang.org/x/term"
)

// Windows 没有 SIGWINCH，用定时查询替代，只在尺寸变化时通知。
func sizeEvents(ctx context.Context, fd int) <-chan Size {
	events := make(chan Size, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var last Size
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cols, rows, err := term.GetSize(fd)
				if err != nil || cols <= 0 || rows <= 0 {
					continue
				}
				size := Size{Cols: cols, Rows: rows}
				if size == last {
					continue
				}
				last = size
				select {
				case events <- size:
				default:
				}
			}
		}
	}()
	return events
}
