package main

import (
	"net"
	"strings"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// serverConfigForRun decides whether the §15.1 server config is consulted at
// all, and loads it. wellKnown is nodeconfig.DefaultPath in production; a
// parameter so tests can point it at a temp file.
//
// The v1.51/v1.61 all-halves probe-skip is retired (v1.63): the variables
// stanza is a file-only half with no flag, so a version that reads it must
// probe the file even when every flagged half is flagged — skipping would
// silently drop the node's variables. `--config off` remains the whole-file
// switch for a node that never wanted the file read.
func serverConfigForRun(configFlag, wellKnown string) (*nodeconfig.Config, error) {
	configFlag = strings.TrimSpace(configFlag)
	switch configFlag {
	case "off":
		return &nodeconfig.Config{}, nil
	case "":
		return nodeconfig.Probe(wellKnown)
	default:
		return nodeconfig.Load(configFlag)
	}
}

// resolveHostPaths picks the R15 allowlist source: the flag when set ("off"
// disables), the server config's storage stanza otherwise. source is for the
// startup log — where a security policy came from should never need guessing.
func resolveHostPaths(flagValue string, cfg *nodeconfig.Config) (paths []string, source string) {
	switch flagValue = strings.TrimSpace(flagValue); flagValue {
	case "off":
		return nil, "off"
	case "":
		return cfg.AllowedHostPaths, cfg.Path
	default:
		return splitList(flagValue), "--allowed-host-paths"
	}
}

// listenNone is --listen's explicit socket-only spelling (v1.61) — init's own
// prompt vocabulary, chosen over the other flags' "off" because "none" is what
// that prompt has always accepted.
const listenNone = "none"

// apiListener is the resolved API/dashboard listener story (PRD §15.1,
// v1.61): where it binds and which of R20's modes secures it.
type apiListener struct {
	addr string
	// mode is a nodeconfig.TLS* constant, or "" — the flags' pre-v1.61
	// vocabulary, where a pair means TLS and a bare non-loopback address is
	// refused at the daemon's listener construction.
	mode      string
	cert, key string // the provided pair
	domain    string // the certificate's name for acme/self-signed
	source    string // for the startup log
}

// tlsEnabled reports whether handshakes will carry a certificate.
func (l apiListener) tlsEnabled() bool {
	return l.cert != "" || l.mode == nodeconfig.TLSAcme || l.mode == nodeconfig.TLSSelfSigned
}

// resolveAPIListen picks the listener source: the --listen flag when set
// ("none" is the explicit socket-only), the server config's bind stanza
// otherwise. The half is atomic — whichever source supplies the address
// supplies its TLS story, because a listener assembled from two sources is a
// misconfiguration wearing a merge's name. Neither source means socket-only,
// today's posture byte for byte.
//
// An unset bind.api_tls resolves here: a declared pair means provided, and
// everything else keeps the flags' semantics — loopback serves plaintext,
// beyond loopback is refused at the daemon's listener construction. The
// self-signed certificate name falls back to the address's host; parse
// already refused the unspecified-host case with no api_domain.
func resolveAPIListen(listenFlag, certFlag, keyFlag string, cfg *nodeconfig.Config) apiListener {
	switch listenFlag = strings.TrimSpace(listenFlag); listenFlag {
	case listenNone:
		return apiListener{source: listenNone}
	case "":
		if cfg.Bind == nil || cfg.Bind.APIAddr == "" {
			return apiListener{}
		}
		l := apiListener{
			addr: cfg.Bind.APIAddr, mode: cfg.Bind.APITLS,
			cert: cfg.Bind.APICert, key: cfg.Bind.APIKey,
			domain: cfg.Bind.APIDomain, source: cfg.Path,
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
	default:
		l := apiListener{addr: listenFlag, cert: certFlag, key: keyFlag, source: "--listen"}
		if l.cert != "" {
			l.mode = nodeconfig.TLSProvided
		}
		return l
	}
}

// resolvePassthroughPath picks the file the R17/R18 grants are parsed from:
// the flag's file when set ("off" disables), the server config itself
// otherwise — internal/passthrough decodes its blocks straight out of
// kanea.hcl. An explicitly flagged file gets the same trust check the probed
// one got in nodeconfig.Load: the boundary claim does not weaken because the
// path arrived by argv.
func resolvePassthroughPath(flagValue string, cfg *nodeconfig.Config) (path, source string, err error) {
	switch flagValue = strings.TrimSpace(flagValue); flagValue {
	case "off":
		return "", "off", nil
	case "":
		if cfg.Path == "" {
			return "", "", nil
		}
		return cfg.Path, cfg.Path, nil
	default:
		if err := nodeconfig.CheckTrusted(flagValue); err != nil {
			return "", "", err
		}
		return flagValue, "--passthrough-config", nil
	}
}
