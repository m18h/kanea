package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// tailer streams one alloc's log file, optionally starting from the last N
// lines. It reads what is there and returns: following is the caller's loop;
// so a slow client can never block a workload's writer. That is the same
// property PRD §17 demands of the log pipeline: the reader is never in the
// workload's path.
type tailer struct {
	file    *os.File
	allocID string
	prefix  bool
	buf     []byte
	// partial holds a trailing incomplete line between reads, so a line split
	// across two reads is emitted once, whole.
	partial []byte
}

func newTailer(path, allocID string, tail int, prefix bool) (*tailer, error) {
	f, err := os.Open(path) // #nosec G304; path is composed from the alloc id
	if err != nil {
		return nil, err
	}
	t := &tailer{file: f, allocID: allocID, prefix: prefix, buf: make([]byte, 32<<10)}
	if tail > 0 {
		if err := t.seekToLastLines(tail); err != nil {
			return nil, errors.Join(err, f.Close())
		}
	}
	return t, nil
}

// seekToLastLines positions the file at the start of the last n lines, reading
// backwards in chunks so a large log does not have to be read in full.
func (t *tailer) seekToLastLines(n int) error {
	info, err := t.file.Stat()
	if err != nil {
		return err
	}
	const chunk = 8 << 10
	var (
		offset = info.Size()
		lines  int
		buf    = make([]byte, chunk)
	)
	for offset > 0 && lines <= n {
		size := int64(chunk)
		if offset < size {
			size = offset
		}
		offset -= size
		if _, err := t.file.ReadAt(buf[:size], offset); err != nil && err != io.EOF {
			return err
		}
		for i := int(size) - 1; i >= 0; i-- {
			if buf[i] != '\n' {
				continue
			}
			lines++
			if lines > n {
				offset += int64(i) + 1
				_, err := t.file.Seek(offset, io.SeekStart)
				return err
			}
		}
	}
	_, err = t.file.Seek(offset, io.SeekStart)
	return err
}

// copyTo writes whatever new output is available, and reports how many bytes
// it wrote.
func (t *tailer) copyTo(w io.Writer) (int, error) {
	total := 0
	for {
		n, err := t.file.Read(t.buf)
		if n > 0 {
			written, werr := t.write(w, t.buf[:n])
			total += written
			if werr != nil {
				return total, werr
			}
		}
		if err == io.EOF {
			return total, nil // caller polls again if following
		}
		if err != nil {
			return total, err
		}
	}
}

// write emits complete lines, prefixing each with the alloc id when more than
// one alloc is being followed.
func (t *tailer) write(w io.Writer, data []byte) (int, error) {
	if !t.prefix {
		return w.Write(data)
	}

	t.partial = append(t.partial, data...)
	total := 0
	for {
		idx := bytes.IndexByte(t.partial, '\n')
		if idx < 0 {
			return total, nil
		}
		line := t.partial[:idx+1]
		t.partial = t.partial[idx+1:]
		n, err := fmt.Fprintf(w, "%s | %s", t.allocID, line)
		total += n
		if err != nil {
			return total, err
		}
	}
}

func (t *tailer) Close() error { return t.file.Close() }
