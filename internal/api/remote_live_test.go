package api_test

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
)

// TestRemoteClientAgainstATLSServer is the end-to-end proof that the remote
// path works: a real TLS listener, a real certificate the client must be told
// to trust, and a real bearer token on the wire.
//
// It exists because every part of this is invisible to a unit test of the
// pieces. The token is attached by a RoundTripper rather than at the call
// sites, the CA replaces the system pool, and TLS is what a node actually
// serves; a test that mocked any of those would prove nothing about CI.
func TestRemoteClientAgainstATLSServer(t *testing.T) {
	h := newAuthHarness(t)
	ts := httptest.NewTLSServer(h.server.Config.Handler)
	t.Cleanup(ts.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: ts.Certificate().Raw,
	})
	token := h.token(t, auth.RoleAdmin)

	t.Run("a token and the node's CA reach an authenticated route", func(t *testing.T) {
		client, err := api.NewClientFor(api.Endpoint{URL: ts.URL, Token: token, CACert: caPEM})
		if err != nil {
			t.Fatalf("NewClientFor: %v", err)
		}
		if _, err := client.Services(context.Background()); err != nil {
			t.Fatalf("Services over TLS with a token: %v", err)
		}
	})

	t.Run("without the CA the failure names --ca-cert", func(t *testing.T) {
		// The whole point of the remoteDialError branch. A node serves a
		// self-signed or node-CA certificate by default, so this is where a
		// first CI run stops, and "unknown authority" alone gives no way out.
		client, err := api.NewClientFor(api.Endpoint{URL: ts.URL, Token: token})
		if err != nil {
			t.Fatalf("NewClientFor: %v", err)
		}
		_, err = client.Services(context.Background())
		if err == nil {
			t.Fatal("an untrusted certificate was accepted")
		}
		if !strings.Contains(err.Error(), "--ca-cert") {
			t.Errorf("err = %q, want it to name --ca-cert as the way forward", err)
		}
	})

	t.Run("a viewer token cannot apply", func(t *testing.T) {
		client, err := api.NewClientFor(api.Endpoint{
			URL: ts.URL, Token: h.token(t, auth.RoleViewer), CACert: caPEM,
		})
		if err != nil {
			t.Fatalf("NewClientFor: %v", err)
		}
		// Remote does not widen authorization: the role decides, exactly as it
		// does for any other token caller.
		if _, err := client.Apply(context.Background(), applyOne("shop", "web"), nil); err == nil {
			t.Fatal("a viewer token applied a service")
		}
	})

	t.Run("a bad token is refused", func(t *testing.T) {
		client, err := api.NewClientFor(api.Endpoint{
			URL: ts.URL, Token: "kanea_deadbeef.nope", CACert: caPEM,
		})
		if err != nil {
			t.Fatalf("NewClientFor: %v", err)
		}
		if _, err := client.Services(context.Background()); err == nil {
			t.Fatal("a forged token was accepted")
		}
	})
}
