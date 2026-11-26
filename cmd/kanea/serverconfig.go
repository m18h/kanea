package main

import (
	"net"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// apiListener is the resolved API/dashboard listener story (PRD §15.1,
// v1.61): where it binds and which of R20's modes secures it.
type apiListener struct {
	addr string
	// mode is a nodeconfig.TLS* constant, or "": an address with no declared
	// mode and no pair, which serves plaintext on loopback and is refused
	// beyond it at the daemon's listener construction.
	mode      string
	cert, key string // the provided pair
	domain    string // the certificate's name for acme/self-signed
}

// tlsEnabled reports whether handshakes will carry a certificate.
func (l apiListener) tlsEnabled() bool {
	return l.cert != "" || l.mode == nodeconfig.TLSAcme || l.mode == nodeconfig.TLSSelfSigned
}

// apiListenFromConfig reads the listener out of the bind stanza. No stanza,
// or one with no api_addr, is socket-only: the zero value.
//
// An unset bind.api_tls resolves here: a declared pair means provided, and
// anything else is left empty for the listener's own loopback rule. The
// self-signed certificate name falls back to the address's host; parse
// already refused the unspecified-host case with no api_domain.
func apiListenFromConfig(cfg *nodeconfig.Config) apiListener {
	if cfg.Bind == nil || cfg.Bind.APIAddr == "" {
		return apiListener{}
	}
	l := apiListener{
		addr: cfg.Bind.APIAddr, mode: cfg.Bind.APITLS,
		cert: cfg.Bind.APICert, key: cfg.Bind.APIKey,
		domain: cfg.Bind.APIDomain,
	}
	if l.mode == "" && l.cert != "" {
		l.mode = nodeconfig.TLSProvided
	}
	if l.mode == nodeconfig.TLSSelfSigned && l.domain == "" {
		if host, _, err := net.SplitHostPort(l.addr); err == nil {
			l.domain = host
		}
	}
	return l
}
