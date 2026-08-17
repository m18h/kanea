package main

import (
	"bytes"
	"testing"
)

func TestScrubTerminal(t *testing.T) {
	var buf bytes.Buffer
	w := scrubTerminal{&buf}
	in := "ok\nline\ttab\x1b]52;c;YmlnLXNlY3JldA==\x07bell\rCR\x00nul\x9bCSI"
	if _, err := w.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	want := "ok\nline\ttab]52;c;YmlnLXNlY3JldA==bell\nCRnulCSI"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}
