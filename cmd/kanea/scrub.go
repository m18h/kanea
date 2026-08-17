package main

import "io"

// scrubTerminal wraps a writer so repo-controlled output - buildkit progress,
// commit subjects, the clone URL - cannot write terminal control sequences to
// the operator's terminal (K-45). C0 and C1 controls are dropped, except \n
// and \t, which logs legitimately use. \r becomes \n: carriage-return
// overwrite is buildkit's progress rendering, and it is also the "rewrite the
// visible line" primitive.
type scrubTerminal struct{ w io.Writer }

func (s scrubTerminal) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p))
	for _, b := range p {
		switch {
		case b == '\n' || b == '\t':
			out = append(out, b)
		case b == '\r':
			out = append(out, '\n')
		case b < 0x20 || (b >= 0x7f && b <= 0x9f):
			// Dropped: a control character is not output, it is a cursor.
		default:
			out = append(out, b)
		}
	}
	if err := writeAll(s.w, out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
