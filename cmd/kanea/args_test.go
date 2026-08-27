package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func newTestFlagSet() (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c := fs.String("c", "", "container")
	rm := fs.Bool("rm", false, "remove")
	return fs, c, rm
}

func TestParseArgsFlagsAfterPositionals(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantC   string
		wantRm  bool
		wantPos []string
		wantErr bool
	}{
		{
			// The documented form that used to silently drop -c.
			name: "flag after positional", args: []string{"shop/api", "-c", "migrate"},
			wantC: "migrate", wantPos: []string{"shop/api"},
		},
		{
			// The kanea stop shape that used to quietly scale to zero.
			name: "bool flag after positional", args: []string{"shop/web", "--rm"},
			wantRm: true, wantPos: []string{"shop/web"},
		},
		{
			name: "flags before positional still work", args: []string{"-c", "migrate", "shop/api"},
			wantC: "migrate", wantPos: []string{"shop/api"},
		},
		{
			name: "flags on both sides", args: []string{"--rm", "shop/web", "-c", "migrate"},
			wantC: "migrate", wantRm: true, wantPos: []string{"shop/web"},
		},
		{
			name: "interleaved positionals", args: []string{"a.hcl", "-c", "x", "shop/web"},
			wantC: "x", wantPos: []string{"a.hcl", "shop/web"},
		},
		{
			name: "no flags", args: []string{"shop/api"},
			wantPos: []string{"shop/api"},
		},
		{
			name: "empty", args: nil,
			wantPos: nil,
		},
		{
			// A typo'd flag is a loud failure, never a silent wrong answer.
			name: "unknown trailing flag errors", args: []string{"shop/api", "--nope"},
			wantErr: true,
		},
		{
			// Everything after "--" is positional, verbatim.
			name: "double dash keeps the tail positional", args: []string{"shop/api", "--", "-c", "migrate"},
			wantPos: []string{"shop/api", "-c", "migrate"},
		},
		{
			// A bare "-" is stdin by convention, not a flag.
			name: "bare dash is positional", args: []string{"-c", "x", "-"},
			wantC: "x", wantPos: []string{"-"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, c, rm := newTestFlagSet()
			err := parseArgs(fs, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseArgs(%q) = nil, want error", tt.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArgs(%q): %v", tt.args, err)
			}
			if *c != tt.wantC {
				t.Errorf("-c = %q, want %q", *c, tt.wantC)
			}
			if *rm != tt.wantRm {
				t.Errorf("--rm = %v, want %v", *rm, tt.wantRm)
			}
			var got []string
			if fs.NArg() > 0 {
				got = fs.Args()
			}
			if !reflect.DeepEqual(got, tt.wantPos) {
				t.Errorf("positionals = %q, want %q", got, tt.wantPos)
			}
		})
	}
}
