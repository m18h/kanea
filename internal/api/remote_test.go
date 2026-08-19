package api

import (
	"strings"
	"testing"
)

// TestEndpointValidateRefusals pins every combination that leaks a credential
// or cannot mean anything. Each of these is a message someone reads once, at
// the moment they are wiring CI up, so the wording is part of the contract.
func TestEndpointValidateRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		ep   Endpoint
		want string // substring; "" means it must be accepted
	}{
		{"the local socket needs nothing", Endpoint{Socket: "/run/kanea/kanead.sock"}, ""},
		{"the zero value is local", Endpoint{}, ""},
		{
			"a token with no endpoint",
			Endpoint{Token: "t"},
			"a token needs an endpoint",
		},
		{
			"a CA with no endpoint",
			Endpoint{CACert: []byte("-----BEGIN CERTIFICATE-----")},
			"applies to a remote endpoint",
		},
		{
			"a URL with no token",
			Endpoint{URL: "https://node:8600"},
			"no credential without a token",
		},
		{
			"plain http beyond loopback",
			Endpoint{URL: "http://node.example:8600", Token: "t"},
			"clear text",
		},
		{"plain http on loopback is fine", Endpoint{URL: "http://127.0.0.1:8600", Token: "t"}, ""},
		{"plain http on localhost is fine", Endpoint{URL: "http://localhost:8600", Token: "t"}, ""},
		{"https beyond loopback is the point", Endpoint{URL: "https://node.example:8600", Token: "t"}, ""},
		{
			"a scheme that is not http",
			Endpoint{URL: "ws://node:8600", Token: "t"},
			"must be http or https",
		},
		{
			"no host",
			Endpoint{URL: "https://", Token: "t"},
			"names no host",
		},
		{
			// Silently dropping it would make a typo look like a daemon that
			// answered strangely.
			"a path would be dropped",
			Endpoint{URL: "https://node:8600/v1", Token: "t"},
			"bare scheme://host",
		},
		{
			"userinfo would be dropped",
			Endpoint{URL: "https://user:pw@node:8600", Token: "t"},
			"bare scheme://host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ep.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() accepted %+v, want a refusal naming %q", tc.ep, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestNewClientForLocalIsTheClientItAlwaysWas is the regression guard for the
// whole refactor: an endpoint with no URL must produce exactly the client every
// caller had before remote endpoints existed, down to the error messages, which
// name a group to join and a daemon to start.
func TestNewClientForLocalIsTheClientItAlwaysWas(t *testing.T) {
	client, err := NewClientFor(Endpoint{Socket: "/tmp/x.sock"})
	if err != nil {
		t.Fatalf("NewClientFor: %v", err)
	}
	if client.Remote() {
		t.Error("a socket endpoint produced a remote client")
	}
	if got := client.Socket(); got != "/tmp/x.sock" {
		t.Errorf("Socket() = %q, want /tmp/x.sock", got)
	}
	if got := client.url("/v1/healthz"); got != localBase+"/v1/healthz" {
		t.Errorf("url() = %q, want the dummy authority the unix transport ignores", got)
	}
	if got := client.wsURL("/v1/exec"); got != "ws://kanead/v1/exec" {
		t.Errorf("wsURL() = %q, want ws://kanead/v1/exec", got)
	}
}

func TestNewClientForRemoteBuildsTheRightURLs(t *testing.T) {
	client, err := NewClientFor(Endpoint{URL: "https://node.example:8600", Token: "t"})
	if err != nil {
		t.Fatalf("NewClientFor: %v", err)
	}
	if !client.Remote() {
		t.Fatal("a URL endpoint produced a local client")
	}
	if got := client.Socket(); got != "" {
		t.Errorf("Socket() = %q, want empty: a remote client has no socket to name", got)
	}
	if got := client.Target(); got != "https://node.example:8600" {
		t.Errorf("Target() = %q", got)
	}
	if got := client.url(PathHealth); got != "https://node.example:8600"+PathHealth {
		t.Errorf("url() = %q", got)
	}
	// wss, not ws: an exec over a TLS endpoint that dialled ws:// would fail
	// in a way that looks like the daemon refused the upgrade.
	if got := client.wsURL(PathExec); got != "wss://node.example:8600"+PathExec {
		t.Errorf("wsURL() = %q, want the wss twin", got)
	}
}

func TestRemoteTransportRefusesAGarbageCA(t *testing.T) {
	_, err := NewClientFor(Endpoint{
		URL: "https://node:8600", Token: "t", CACert: []byte("not a certificate"),
	})
	if err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Fatalf("err = %v, want a refusal naming the empty PEM", err)
	}
}

// TestRemoteTransportDisablesHTTP2 pins a trap rather than a preference: an
// HTTP/2 response body is not the io.ReadWriteCloser coder/websocket hijacks
// for exec, so h2 would break `kanea exec` against TLS endpoints only, which
// is the hardest kind of failure to attribute.
func TestRemoteTransportDisablesHTTP2(t *testing.T) {
	transport, err := remoteTransport(nil)
	if err != nil {
		t.Fatalf("remoteTransport: %v", err)
	}
	if transport.TLSNextProto == nil {
		t.Fatal("TLSNextProto is nil, so net/http may negotiate h2 and break exec")
	}
	if len(transport.TLSNextProto) != 0 {
		t.Errorf("TLSNextProto = %v, want empty", transport.TLSNextProto)
	}
}

func TestCACertIsInline(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"-----BEGIN CERTIFICATE-----\nMII...", true},
		{"\n  -----BEGIN CERTIFICATE-----", true},
		{"/etc/kanea/ca.crt", false},
		{"ca.pem", false},
		{"", false},
	} {
		if got := CACertIsInline(tc.value); got != tc.want {
			t.Errorf("CACertIsInline(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
