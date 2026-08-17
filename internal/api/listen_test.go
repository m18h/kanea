package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/store"
)

// newTestLogger writes to a buffer a test can read back, which is how the
// listener refusals are checked: they are deliberately log output rather than
// errors, so that the daemon keeps running.
func newTestLogger(w *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newListenServer builds a server with a network listener, without starting it.
func newListenServer(t *testing.T, with func(*api.ServerConfig)) (*api.Server, *syncBuffer) {
	t.Helper()

	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logs := &syncBuffer{}
	cfg := api.ServerConfig{
		Store:   st,
		Logger:  newTestLogger(logs),
		Socket:  filepath.Join(shortTempDir(t), "k.sock"),
		Version: "test",
		LogDir:  t.TempDir(),
		Listen:  "127.0.0.1:0",
		// The default for these tests is a daemon that *has* an account, so a
		// refusal in one of them is about the thing that test is checking.
		AuthConfigured: true,
	}
	if with != nil {
		with(&cfg)
	}
	server, err := api.NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server, logs
}

func TestNetworkListenerIsRefusedWithoutAnAccount(t *testing.T) {
	server, logs := newListenServer(t, func(cfg *api.ServerConfig) {
		cfg.AuthConfigured = false
	})

	// The socket still binds: it is where `kanea user add` lands, and a daemon
	// that refused to start here could never be given the account it wants
	// (PRD §13.1).
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen = %v, want the socket to bind anyway", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if addr := server.NetworkAddr(); addr != "" {
		t.Fatalf("a network listener was opened at %s with no account configured", addr)
	}
	if !strings.Contains(logs.String(), "refused") {
		t.Errorf("the refusal was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "kanea user add") {
		t.Errorf("the log does not say how to fix it: %s", logs.String())
	}
}

func TestPublicListenerWithoutTLSIsRefused(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0"} {
		t.Run(addr, func(t *testing.T) {
			server, logs := newListenServer(t, func(cfg *api.ServerConfig) {
				cfg.Listen = addr
			})
			if err := server.Listen(); err != nil {
				t.Fatalf("Listen = %v, want the socket to bind anyway", err)
			}
			t.Cleanup(func() { _ = server.Close() })

			if got := server.NetworkAddr(); got != "" {
				t.Fatalf("a plaintext public listener was opened at %s", got)
			}
			if !strings.Contains(logs.String(), "TLS") {
				t.Errorf("the refusal does not mention TLS: %s", logs.String())
			}
		})
	}
}

func TestLoopbackListenerNeedsNoTLS(t *testing.T) {
	// Loopback carries credentials over a wire nobody else is on, so plain HTTP
	// is a reasonable local default, and it is what the dashboard behind
	// kanea-edge uses.
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		t.Run(addr, func(t *testing.T) {
			server, _ := newListenServer(t, func(cfg *api.ServerConfig) {
				cfg.Listen = addr
			})
			if err := server.Listen(); err != nil {
				t.Fatalf("Listen: %v", err)
			}
			t.Cleanup(func() { _ = server.Close() })

			if server.NetworkAddr() == "" {
				t.Fatal("no loopback listener was opened")
			}
		})
	}
}

func TestPublicListenerWithTLSIsAllowed(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	server, _ := newListenServer(t, func(cfg *api.ServerConfig) {
		cfg.Listen = "0.0.0.0:0"
		cfg.TLSCert, cfg.TLSKey = certFile, keyFile
	})
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	// The refusal above is about plaintext, not about reach: with a certificate,
	// binding the world is the operator's call to make.
	if server.NetworkAddr() == "" {
		t.Fatal("a public TLS listener was refused")
	}
}

func TestTLSListenerServesHTTPS(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	server, _ := newListenServer(t, func(cfg *api.ServerConfig) {
		cfg.Listen = "127.0.0.1:0"
		cfg.TLSCert, cfg.TLSKey = certFile, keyFile
	})
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})

	addr := server.NetworkAddr()
	if addr == "" {
		t.Fatal("no network listener")
	}

	client := &http.Client{Transport: &http.Transport{
		// The certificate is self-signed for this test; the property under test
		// is that the listener speaks TLS at all.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402
	}}
	resp, err := client.Get("https://" + addr + api.PathHealth)
	if err != nil {
		t.Fatalf("https health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("the connection was not TLS")
	}
}

func TestNetworkListenerDeniesUnauthenticatedCallers(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	users, err := auth.NewStore(auth.StoreConfig{Store: st})
	if err != nil {
		t.Fatalf("auth store: %v", err)
	}
	server, err := api.NewServer(api.ServerConfig{
		Store: st, Socket: filepath.Join(shortTempDir(t), "k.sock"),
		LogDir: t.TempDir(), Listen: "127.0.0.1:0", AuthConfigured: true, Auth: users,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Loopback is not local: only the unix socket is (§13.1). Someone who can
	// reach 127.0.0.1 through a proxied port, an SSH tunnel or another container
	// is not the root of this host.
	resp, err := http.Get("http://" + server.NetworkAddr() + api.PathServices)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 over the network listener", resp.StatusCode)
	}
}

func TestBadListenerConfigurationFailsLoudly(t *testing.T) {
	tests := []struct {
		name string
		with func(*api.ServerConfig)
	}{
		{"unparseable address", func(cfg *api.ServerConfig) { cfg.Listen = "not-an-address" }},
		{"certificate without a key", func(cfg *api.ServerConfig) {
			cfg.TLSCert = "/nonexistent/cert.pem"
		}},
		{"unreadable certificate", func(cfg *api.ServerConfig) {
			cfg.TLSCert, cfg.TLSKey = "/nonexistent/cert.pem", "/nonexistent/key.pem"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A bind failure is the operator's configuration not working. Unlike
			// the two policy refusals, starting anyway would hide it.
			st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			t.Cleanup(func() { _ = st.Close() })

			cfg := api.ServerConfig{
				Store: st, Socket: filepath.Join(shortTempDir(t), "k.sock"),
				LogDir: t.TempDir(), Listen: "127.0.0.1:0", AuthConfigured: true,
			}
			tc.with(&cfg)

			server, err := api.NewServer(cfg)
			if err != nil {
				return // a certificate problem is caught at construction
			}
			t.Cleanup(func() { _ = server.Close() })
			if err := server.Listen(); err == nil {
				t.Fatal("a broken listener configuration started anyway")
			} else if errors.Is(err, api.ErrNoAuthConfigured) || errors.Is(err, api.ErrInsecureListener) {
				t.Fatalf("misreported as a policy refusal: %v", err)
			}
		})
	}
}

// writeTestCert produces a self-signed certificate for the loopback address.
func writeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kanea-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	body := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
