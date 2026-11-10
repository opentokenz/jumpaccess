//go:build !windows

package webterminal

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

func sizeEvents(ctx context.Context, fd int) <-chan Size {
	events := make(chan Size, 1)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGWINCH)
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals:
				cols, rows, err := term.GetSize(fd)
				if err != nil || cols <= 0 || rows <= 0 {
					continue
				}
				select {
				case events <- Size{Cols: cols, Rows: rows}:
				default:
				}
			}
		}
	}()
	return events
}
