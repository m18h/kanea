package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/term"
)

// The client half of the exec protocol (PRD §16.2).
//
// It lives beside the server half deliberately. The framing is a private
// agreement between exactly these two files, and a protocol whose two ends are
// edited in different packages is a protocol that drifts.

// ExecOptions describes a debug-shell session.
type ExecOptions struct {
	Project string
	Alloc   string
	Command []string
	// TTY puts the local terminal into raw mode and asks for a pseudo-terminal
	// on the far side. Without it the session is a pipe, which is what a script
	// wants.
	TTY  bool
	User string

	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Exec attaches to an alloc and returns the remote command's exit code.
func (c *Client) Exec(ctx context.Context, opts ExecOptions) (_ uint32, err error) {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stderr == nil {
		opts.Stderr = opts.Stdout
	}

	// Raw mode before the socket opens, restored on every path out. A terminal
	// left in raw mode after a session is a shell that no longer echoes what
	// the operator types: recoverable with `reset`, and alarming until they
	// remember that.
	var restore func()
	if opts.TTY {
		restore, err = enterRawMode(opts.Stdin)
		if err != nil {
			return 0, err
		}
		defer restore()
	}

	conn, err := c.dialExec(ctx, opts)
	if err != nil {
		return 0, err
	}
	// Read limit raised: the default is 32 KiB per message, and a program
	// spewing output produces frames larger than that.
	conn.SetReadLimit(maxExecFrameBytes)
	defer func() {
		if cerr := conn.Close(websocket.StatusNormalClosure, ""); cerr != nil {
			// A close error after a completed session is noise: the process has
			// already exited and its code is what the caller wants.
			_ = cerr
		}
	}()

	// Cancelled when the session ends, so the stdin pump stops blocking on a
	// terminal read nobody will consume.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if opts.Stdin != nil {
		go pumpStdin(ctx, conn, opts.Stdin)
	}
	if opts.TTY {
		go watchResize(ctx, conn, opts.Stdin)
	}
	return readExecOutput(ctx, conn, opts)
}

// maxExecFrameBytes bounds one inbound frame, matching the server's stdin cap
// plus the stream prefix.
const maxExecFrameBytes = (1 << 20) + 1

// dialExec opens the websocket over the daemon's transport.
func (c *Client) dialExec(ctx context.Context, opts ExecOptions) (*websocket.Conn, error) {
	target := c.wsURL(PathExec) + "?" +
		ExecQuery(opts.Project, opts.Alloc, opts.Command, opts.TTY, opts.User)

	conn, resp, err := websocket.Dial(ctx, target, &websocket.DialOptions{
		// The client's own transport, so an exec goes over the same unix socket
		// every other command does. Nothing about this route is reachable by a
		// path the rest of the CLI does not already use.
		//
		// Remotely that transport is the TLS one, and the bearer token rides
		// its RoundTripper: coder/websocket builds this handshake request
		// itself and sends it through this client, so auth set anywhere else
		// would miss it. The server side needs nothing — checkOrigin admits a
		// request with no Origin (a CLI is not a browser) and checkCSRF exempts
		// token callers.
		HTTPClient: c.http,
	})
	if err != nil {
		if resp != nil {
			// The daemon refused before upgrading (401, 403, 503) and its body
			// says why. That message is far more useful than "bad handshake".
			refusal := decodeError(resp)
			return nil, errors.Join(refusal, resp.Body.Close())
		}
		return nil, c.dialError(err)
	}
	return conn, nil
}

// readExecOutput consumes frames until the session ends.
func readExecOutput(ctx context.Context, conn *websocket.Conn, opts ExecOptions) (uint32, error) {
	for {
		typ, body, err := conn.Read(ctx)
		if err != nil {
			var closeErr websocket.CloseError
			if errors.As(err, &closeErr) && closeErr.Code == websocket.StatusNormalClosure {
				// The daemon closed cleanly without an exit frame. Nothing said
				// the command failed, so nothing here should claim it did.
				return 0, nil
			}
			return 0, fmt.Errorf("exec session ended: %w", err)
		}

		switch typ {
		case websocket.MessageBinary:
			if len(body) < 2 {
				continue // a stream byte and nothing else
			}
			target := opts.Stdout
			if body[0] == streamStderr {
				target = opts.Stderr
			}
			if _, err := target.Write(body[1:]); err != nil {
				return 0, fmt.Errorf("write output: %w", err)
			}

		case websocket.MessageText:
			var frame ExecFrame
			if err := json.Unmarshal(body, &frame); err != nil {
				continue
			}
			switch frame.Type {
			case "exit":
				return frame.Code, nil
			case "error":
				return 0, errors.New(frame.Message)
			}
		}
	}
}

// pumpStdin forwards local input to the remote process.
func pumpStdin(ctx context.Context, conn *websocket.Conn, stdin io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			// EOF on stdin is a message, not a failure: a piped command has
			// finished delivering its input and the remote process should see
			// that rather than wait forever.
			if errors.Is(err, io.EOF) {
				sendControl(ctx, conn, ExecFrame{Type: "eof"})
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// watchResize forwards terminal size changes.
func watchResize(ctx context.Context, conn *websocket.Conn, stdin io.Reader) {
	fd, ok := terminalFD(stdin)
	if !ok {
		return
	}

	// SIGWINCH is how a terminal announces a resize. The initial size is sent
	// unprompted, because the remote process starts before any signal arrives
	// and would otherwise assume 80x24 until the window happened to change.
	sizes := make(chan os.Signal, 1)
	signal.Notify(sizes, syscall.SIGWINCH)
	defer signal.Stop(sizes)

	send := func() {
		width, height, err := term.GetSize(fd)
		if err != nil {
			return
		}
		// Clamped rather than converted. A terminal wider than 65535 columns
		// does not exist, but an unchecked conversion of a negative or absurd
		// value would wrap into a size that makes the remote process render
		// nonsense.
		sendControl(ctx, conn, ExecFrame{
			Type: "resize", Width: clampDimension(width), Height: clampDimension(height),
		})
	}
	send()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sizes:
			send()
		}
	}
}

func sendControl(ctx context.Context, conn *websocket.Conn, frame ExecFrame) {
	body, err := json.Marshal(frame)
	if err != nil {
		return
	}
	// Bounded: a control frame that cannot be written within a moment is one
	// the far side is not reading, and blocking here would wedge the stdin pump.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		// Nothing useful to do and nobody to tell: the session is ending, and a
		// resize or an EOF that did not land is not worth interrupting it over.
		_ = err
	}
}

// clampDimension bounds a terminal dimension into the wire's uint16.
func clampDimension(v int) uint16 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(v)
}

// enterRawMode puts the terminal into raw mode and returns the restore.
//
// Raw mode is what makes a remote shell behave like a shell: without it the
// local terminal buffers a line before sending it, echoes it locally, and eats
// Ctrl-C, so tab completion does nothing, arrow keys print escape sequences,
// and interrupting the remote process is impossible.
func enterRawMode(stdin io.Reader) (func(), error) {
	fd, ok := terminalFD(stdin)
	if !ok {
		// Not a terminal: a pipe, or a test. Asking for a TTY is then a
		// request that cannot be honoured locally, and pretending otherwise
		// would corrupt whatever is actually on the other end.
		return func() {}, nil
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("cannot put the terminal into raw mode: %w", err)
	}
	return func() {
		if err := term.Restore(fd, state); err != nil {
			// Written directly rather than through the logger: the terminal is
			// in an unknown state and this is the last useful thing to say.
			fmt.Fprintln(os.Stderr, "kanea: could not restore the terminal; run `reset`:", err)
		}
	}, nil
}

// terminalFD reports the file descriptor behind a reader, when it is a
// terminal.
func terminalFD(r io.Reader) (int, bool) {
	file, ok := r.(*os.File)
	if !ok {
		return 0, false
	}
	fd := int(file.Fd())
	return fd, term.IsTerminal(fd)
}
