package mcp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The stdio transport (PRD §16.3): `kanea mcp`, for a local agent that launches
// Kanea as a subprocess.
//
// One JSON-RPC message per line, in and out. The credential is the unix socket
// the backend dials: reaching it means being the user who runs kanead, which
// §13.1 already treats as the local administrative path. There is no header to
// forward and no session to build, which is why ServeStdio passes a nil Session.
//
// Nothing may be written to stdout that is not a JSON-RPC message. That is the
// one rule of this transport and it is easy to break — a stray fmt.Println, a
// logger with the wrong writer — so the logger is required to be pointed
// somewhere else, and the CLI points it at stderr.

// ServeStdio reads messages from in and writes replies to out until in ends or
// the context is cancelled.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, 64<<10)
	writer := bufio.NewWriter(out)

	// The writer is guarded because replies are produced on this goroutine but
	// the flush happens after each one, and a future server-initiated message
	// would arrive from another. Cheap insurance against interleaved JSON, which
	// is a class of bug that presents as a client mysteriously hanging.
	var mu sync.Mutex

	// A cancelled context has to interrupt a read that is blocked on a client
	// that has gone quiet. Closing is the only way to unblock os.Stdin, and the
	// caller owns it — so the read runs on its own goroutine and this one
	// returns when either finishes.
	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		defer close(lines)
		for {
			line, err := readMessage(reader)
			if err != nil {
				readErr <- err
				return
			}
			if len(line) == 0 {
				continue // a blank line between messages is not an error
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil

		case err := <-readErr:
			mu.Lock()
			flushErr := writer.Flush()
			mu.Unlock()
			if errors.Is(err, io.EOF) {
				// The client closed its end. That is how an MCP session ends,
				// not a failure to report.
				return flushErr
			}
			return errors.Join(err, flushErr)

		case line, ok := <-lines:
			if !ok {
				return writer.Flush()
			}
			reply := s.Handle(ctx, nil, line)
			if reply == nil {
				continue // a notification
			}
			mu.Lock()
			_, err := writer.Write(append(reply, '\n'))
			if err == nil {
				// Flushed per message: a client is waiting on this reply and
				// will not send another until it arrives, so a buffer that
				// waits for more input deadlocks the session.
				err = writer.Flush()
			}
			mu.Unlock()
			if err != nil {
				return fmt.Errorf("mcp: cannot write to stdout: %w", err)
			}
		}
	}
}

// maxLineBytes bounds one stdio message, matching the HTTP transport's cap.
const maxLineBytes = maxMessageBytes

// readMessage reads one newline-delimited message, refusing one that is too
// long rather than growing a buffer for it.
func readMessage(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		buf = append(buf, chunk...)
		if len(buf) > maxLineBytes {
			// Drain the rest of the oversized line so the next read starts at a
			// message boundary rather than in the middle of the one refused.
			for isPrefix {
				_, isPrefix, err = r.ReadLine()
				if err != nil {
					return nil, err
				}
			}
			return nil, fmt.Errorf("mcp: message exceeds %d bytes", maxLineBytes)
		}
		if !isPrefix {
			return buf, nil
		}
	}
}
