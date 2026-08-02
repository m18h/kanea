package api

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// DefaultListenAddr is the network address the control API binds when one is
// configured (PRD §15.1, `bind.api_addr`). Loopback, because that is the
// address that needs no further decisions: anything wider has to justify how it
// is protected.
const DefaultListenAddr = "127.0.0.1:8600"

// Errors a caller distinguishes when a listener is refused.
var (
	// ErrNoAuthConfigured means a network listener was asked for on a daemon
	// where nobody could authenticate to it (PRD §13.1, §14 A05).
	ErrNoAuthConfigured = errors.New("api: no account is configured")
	// ErrInsecureListener means a non-loopback listener was asked for without
	// TLS.
	ErrInsecureListener = errors.New("api: a public listener needs TLS")
)

// listenNetwork binds the network listener, or explains why it will not.
//
// Two refusals, both from §13.1 and §14 A05, and both deliberately refusing the
// *listener* rather than the daemon: kanead must keep running and keep serving
// its socket, because the socket is where `kanea user add` and `kanea token
// create` land. A daemon that refused to start here would be a bootstrap trap —
// the account cannot be created without the daemon, and the daemon will not
// start without the account.
func (s *Server) listenNetwork() (net.Listener, error) {
	if s.listenAddr == "" {
		return nil, nil
	}
	if !s.authConfigured {
		return nil, fmt.Errorf("%w: refusing to open %s", ErrNoAuthConfigured, s.listenAddr)
	}

	public, err := isPublicAddr(s.listenAddr)
	if err != nil {
		return nil, err
	}
	if public && s.tls == nil {
		// Session cookies and bearer tokens over plain HTTP on a network
		// anyone else is on is how a credential is stolen without anybody
		// noticing. Loopback is exempt because there is no wire to read.
		return nil, fmt.Errorf("%w: %s carries credentials in clear text; "+
			"pass a certificate, or bind loopback and put kanea-edge in front",
			ErrInsecureListener, s.listenAddr)
	}

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("api: listen on %s: %w", s.listenAddr, err)
	}
	if s.tls != nil {
		listener = tls.NewListener(listener, s.tls)
	}
	return listener, nil
}

// isPublicAddr reports whether an address binds anything beyond loopback.
//
// An empty or unspecified host (":8600", "0.0.0.0:8600", "[::]:8600") is the
// widest case there is and is treated as public — that is the address someone
// types when they have not thought about who can reach it.
func isPublicAddr(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("api: bad listen address %q: %w", addr, err)
	}
	if host == "" {
		return true, nil
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return !ip.IsLoopback(), nil
	}
	// A name, not an address. "localhost" is the one that is knowably loopback;
	// anything else has to be resolved, and a name that resolves to loopback
	// today can resolve elsewhere tomorrow. Treating it as public is the safe
	// reading, and TLS is not a hardship on a host someone gave a name.
	return host != "localhost", nil
}

// loadTLS reads the listener's certificate.
//
// Loaded at construction so an unreadable or mismatched pair fails while the
// operator is still looking at the terminal, rather than at the first handshake
// hours later.
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	switch {
	case certFile == "" && keyFile == "":
		return nil, nil
	case certFile == "" || keyFile == "":
		return nil, errors.New("api: a TLS certificate needs both a cert and a key")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("api: load TLS keypair: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}
