package api

// Talking to a kanead that is not on this machine (PRD v1.82, §16.2).
//
// The daemon has accepted bearer tokens over its network listener since §13.2:
// identify() checks Authorization before the unix-socket shortcut, and CSRF is
// skipped for token callers. What was missing was a client that could speak it,
// so `kanea` was usable only by someone sitting on the node. This file is that
// client's construction; nothing here relaxes an authorization rule, it only
// gives the CLI the credential the API already understood.
//
// The zero Endpoint is the local socket, so every caller that does not ask for
// a remote one keeps exactly the client it had.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Endpoint is where a client talks and what it presents on arrival.
type Endpoint struct {
	// Socket is the unix socket path; DefaultSocket when empty.
	Socket string
	// URL is a node's control API origin, e.g. https://node.example:8600.
	// Set means remote.
	URL string
	// Token is the bearer token a remote endpoint authenticates with, from
	// `kanea token create`. Required whenever URL is set.
	Token string
	// CACert is the PEM the remote endpoint's certificate is verified against.
	// It replaces the system roots rather than joining them; see remoteTransport.
	CACert []byte
}

// Remote reports whether this endpoint crosses a network.
func (e Endpoint) Remote() bool { return e.URL != "" }

// Validate refuses the combinations that would leak a credential or that cannot
// mean anything. NewClientFor calls it, so no caller can skip it.
func (e Endpoint) Validate() error {
	if e.URL == "" {
		// The local socket carries no token and needs no roots; a caller that
		// set one has the wrong mental model and should hear about it here
		// rather than watch it be ignored.
		if e.Token != "" {
			return errors.New("a token needs an endpoint: set KANEA_URL (or --url) to a node's " +
				"control API, or unset KANEA_TOKEN to use the local socket")
		}
		if len(e.CACert) > 0 {
			return errors.New("a CA certificate applies to a remote endpoint: set KANEA_URL " +
				"(or --url), or drop --ca-cert to use the local socket")
		}
		return nil
	}

	parsed, err := url.Parse(e.URL)
	if err != nil {
		return fmt.Errorf("endpoint %q is not a URL: %w (want something like https://node.example:8600)", e.URL, err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("endpoint %q names no host (want something like https://node.example:8600)", e.URL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("endpoint %q must be http or https, not %q", e.URL, parsed.Scheme)
	}
	// Every route is an absolute path, so anything here would be dropped when
	// the path is appended. Silently ignoring it would make a typo in the
	// endpoint look like a daemon that answered oddly.
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("endpoint %q must be a bare scheme://host[:port]: every route is an "+
			"absolute path, so the rest would be dropped", e.URL)
	}
	if parsed.Scheme == "http" && IsPublicHost(parsed.Hostname()) {
		return fmt.Errorf("refusing to send a token to %s over plain HTTP: a bearer token would "+
			"cross the network in clear text; use https:// (with --ca-cert for a node-CA or "+
			"self-signed certificate)", parsed.Host)
	}
	// Refused rather than deferred. Over a network every authenticated route
	// answers 401, so the only thing an absent token buys is the same failure
	// one request later with a less useful message. In CI the usual cause is a
	// secret that did not get exported, which renders as the empty string.
	if e.Token == "" {
		return fmt.Errorf("%s is a network endpoint and has no credential without a token: the "+
			"unix socket is the only credential-free path. Set KANEA_TOKEN (or --token) from "+
			"`kanea token create --role admin <name>`", e.URL)
	}
	return nil
}

// NewClientFor builds a client for an endpoint: the unix socket when no URL is
// set, which is the client NewClient has always returned, and a TLS-and-bearer
// client when one is.
func NewClientFor(e Endpoint) (*Client, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if !e.Remote() {
		return NewClient(e.Socket), nil
	}
	base, err := normalizeBase(e.URL)
	if err != nil {
		return nil, err
	}
	transport, err := remoteTransport(e.CACert)
	if err != nil {
		return nil, err
	}
	return &Client{
		// socket stays empty: that is what marks a client remote, and what
		// dialError reads to decide which remedies make sense.
		base: base,
		http: &http.Client{
			Timeout:   clientTimeout,
			Transport: &bearerTransport{base: transport, token: e.Token},
		},
	}, nil
}

// normalizeBase reduces an endpoint to scheme://host[:port] with no trailing
// slash, so base+path is always a well-formed URL.
func normalizeBase(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("endpoint %q is not a URL: %w", raw, err)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// bearerTransport presents the token on every request.
//
// At this layer rather than at the call sites because the exec websocket's
// handshake request is built inside coder/websocket and sent through this same
// http.Client: a header set where requests are constructed would have to be
// duplicated there and remembered for every route added afterwards.
//
// The response is returned untouched. coder/websocket type-asserts the 101
// body to io.ReadWriteCloser to take the connection over, so wrapping it would
// break `kanea exec` and nothing else, which is the hardest kind of break to
// attribute.
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A RoundTripper may not modify the request it is given.
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

// remoteTransport is the TLS transport a remote endpoint is dialled over.
func remoteTransport(caPEM []byte) (*http.Transport, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("the CA certificate holds no PEM certificate; " +
				"`kanea ca show` prints the node's")
		}
		// Replaces the system roots rather than joining them: this node's own
		// CA is the authority for this node, so pinning to it also refuses a
		// public mis-issuance for the same name. It is also the only thing that
		// works on a platform with no system root store at all.
		cfg.RootCAs = pool
	}
	return &http.Transport{
		// CI egress frequently goes through one.
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: cfg,
		// HTTP/2 off, deliberately. `kanea exec` is an HTTP/1.1 Upgrade, and an
		// h2 response body is not the io.ReadWriteCloser the websocket hijacks,
		// so h2 would break exec against TLS endpoints only: a failure that
		// depends on what the other end negotiates. A non-nil empty map is
		// net/http's documented way to say no.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}, nil
}

// clientTimeout bounds an ordinary request. The following streams (logs, build
// logs, exec) clone the client and clear it.
const clientTimeout = 30 * time.Second

// CACertIsInline reports whether a --ca-cert value is the PEM itself rather
// than a path to it.
//
// A CI system hands a secret to a job as an environment value, and requiring
// `echo "$CA" > ca.pem` first is the step people skip by reaching for a
// skip-verify flag instead. The discrimination is unambiguous: a filesystem
// path never begins with a PEM header.
func CACertIsInline(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "-----BEGIN")
}
