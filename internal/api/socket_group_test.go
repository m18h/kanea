package api

import (
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os/user"
	"strings"
	"testing"
)

// The group's absence is the default and must read as "root-only", never as an
// error — while a present group with an unusable gid must fall back the same
// way, because deny-closed is the rule on this surface (PRD v1.48, §13.1).
func TestSocketGroupIDDecidesDenyClosed(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name    string
		lookup  func(string) (*user.Group, error)
		wantGid int
		wantOK  bool
	}{
		{
			name: "absent group is the default, not an error",
			lookup: func(name string) (*user.Group, error) {
				return nil, user.UnknownGroupError(name)
			},
		},
		{
			name: "a failed lookup stays root-only",
			lookup: func(string) (*user.Group, error) {
				return nil, errors.New("nss is on fire")
			},
		},
		{
			name: "a non-numeric gid stays root-only",
			lookup: func(string) (*user.Group, error) {
				return &user.Group{Name: SocketGroup, Gid: "not-a-gid"}, nil
			},
		},
		{
			name: "the created group resolves",
			lookup: func(string) (*user.Group, error) {
				return &user.Group{Name: SocketGroup, Gid: "993"}, nil
			},
			wantGid: 993,
			wantOK:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gid, ok := socketGroupID(tt.lookup, log)
			if ok != tt.wantOK || gid != tt.wantGid {
				t.Errorf("socketGroupID = (%d, %v), want (%d, %v)", gid, ok, tt.wantGid, tt.wantOK)
			}
		})
	}
}

// EACCES on the socket is working as designed, and the error must carry the
// remedy — sudo or the kanea group — not a bare errno on a path most people
// have never seen.
func TestDialErrorNamesTheRemedyForPermissionDenied(t *testing.T) {
	c := NewClient("")

	denied := c.dialError(&net.OpError{Op: "dial", Net: "unix", Err: fs.ErrPermission})
	for _, want := range []string{"sudo", "usermod -aG kanea"} {
		if !strings.Contains(denied.Error(), want) {
			t.Errorf("permission-denied error is missing %q: %v", want, denied)
		}
	}

	// The not-running case keeps its own question.
	gone := c.dialError(&net.OpError{Op: "dial", Net: "unix", Err: errors.New("connect: no such file or directory")})
	if !strings.Contains(gone.Error(), "is it running") {
		t.Errorf("dial error lost the is-it-running hint: %v", gone)
	}
}
