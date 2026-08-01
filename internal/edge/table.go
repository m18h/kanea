package edge

import (
	"fmt"
	"net"
	"strings"
)

// Table is an immutable host → route index.
//
// Immutable on purpose: reloading swaps a whole new table in behind an atomic
// pointer rather than mutating a shared map. A routing table is read by every
// in-flight request, and a request that started under one table finishing under
// another is a class of bug not worth having.
type Table struct {
	byHost map[string]compiled
	index  uint64
}

// NewTable indexes a snapshot for lookup and compiles its middleware.
//
// Compiling here rather than per request is what makes a malformed rule a
// rejected snapshot instead of a decision with no good answer in the middle of
// serving a request.
func NewTable(snap Snapshot) (*Table, error) {
	if err := snap.Validate(); err != nil {
		return nil, err
	}
	t := &Table{byHost: make(map[string]compiled, len(snap.Routes)), index: snap.Index}
	for _, r := range snap.Routes {
		c, err := compile(r)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
		}
		for _, d := range r.Domains {
			t.byHost[d] = c
		}
	}
	return t, nil
}

// EmptyTable routes nothing. It is what the edge starts with, and what it uses
// when no snapshot exists yet — every request 404s, which is the correct answer
// to "which service is this host?" when the answer is none.
func EmptyTable() *Table { return &Table{byHost: map[string]compiled{}} }

// Lookup finds the route for a Host header value.
func (t *Table) Lookup(host string) (Route, bool) {
	c, ok := t.byHost[NormalizeHost(host)]
	return c.Route, ok
}

// lookup finds the compiled route, which is what the request path uses.
func (t *Table) lookup(host string) (compiled, bool) {
	c, ok := t.byHost[NormalizeHost(host)]
	return c, ok
}

// Len is the number of distinct hostnames served.
func (t *Table) Len() int { return len(t.byHost) }

// Index is the Store index this table was projected from.
func (t *Table) Index() uint64 { return t.index }

// Hosts lists the served hostnames. For diagnostics.
func (t *Table) Hosts() []string {
	out := make([]string, 0, len(t.byHost))
	for h := range t.byHost {
		out = append(out, h)
	}
	return out
}

// NormalizeHost reduces a Host header to the form the table is keyed by.
//
// Three things get stripped, and each of them is a way an attacker gets two
// spellings of one host: the port (":443" — a Host header carries one when the
// listener is on a non-default port, and clients may send it regardless), the
// case (DNS is case-insensitive, so "SHOP.example.com" is the same host), and
// the trailing dot of the fully qualified form ("shop.example.com."). Without
// this, "unknown Host → 404" is defeated by typing the name differently.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// SplitHostPort fails when there is no port, which is the common case; and
	// on an IPv6 literal without brackets, which is not a hostname anyway.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}
