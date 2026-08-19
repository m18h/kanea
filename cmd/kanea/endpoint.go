package main

// Where a client command talks (PRD v1.82, §16.2).
//
// Before this, every command built `api.NewClient(*socket)` and could only
// reach a kanead on the same machine. The daemon has accepted bearer tokens on
// its network listener since §13.2; what was missing was a client that spoke
// it. `endpointFlags` is that decision made once, so a command names where it
// talks and never assembles a client itself.
//
// Environment first, because CI sets environment: KANEA_URL, KANEA_TOKEN and
// KANEA_CA_CERT are the interface a pipeline uses, and the flags exist so the
// same thing is discoverable in --help.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/m18h/kanea/internal/api"
)

// Environment variables that name a remote endpoint. Each is the default for
// the flag of the same name; a flag actually passed wins.
const (
	envURL    = "KANEA_URL"
	envToken  = "KANEA_TOKEN"
	envCACert = "KANEA_CA_CERT"
)

// endpoint holds the flags that decide where a command talks.
type endpoint struct {
	fs     *flag.FlagSet
	socket *string
	url    *string
	token  *string
	ca     *string
}

// endpointFlags registers --socket and the remote trio.
//
// Every client-side command calls this. `kanea agent`'s own --socket is the
// daemon's flag (where it *listens*) and is deliberately not this one.
func endpointFlags(fs *flag.FlagSet) *endpoint {
	return &endpoint{
		fs:     fs,
		socket: fs.String("socket", api.DefaultSocket, "kanead control socket"),
		url: fs.String("url", "",
			"remote control API base URL, e.g. https://node:8600 (default $"+envURL+")"),
		token: fs.String("token", "",
			"bearer token for a remote endpoint (default $"+envToken+")"),
		ca: fs.String("ca-cert", "",
			"PEM file, or the PEM itself, for a remote endpoint's CA (default $"+envCACert+")"),
	}
}

// passed reports whether a flag was given on the command line, as opposed to
// carrying its default. --socket has a non-empty default, so emptiness cannot
// answer this.
func (e *endpoint) passed(name string) bool {
	seen := false
	e.fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

// value resolves one setting: the flag if it was passed, else the environment,
// else empty.
//
// An empty environment variable counts as unset. CI renders a secret that did
// not get exported as the empty string, and treating that as "a token was
// supplied" produces a 401 instead of a message about the missing secret.
func (e *endpoint) value(flagName, envName string, flagValue *string) string {
	if e.passed(flagName) {
		return strings.TrimSpace(*flagValue)
	}
	return strings.TrimSpace(os.Getenv(envName))
}

// resolve turns flags and environment into an api.Endpoint.
func (e *endpoint) resolve() (api.Endpoint, error) {
	ep := api.Endpoint{Socket: *e.socket}
	url := e.value("url", envURL, e.url)
	token := e.value("token", envToken, e.token)
	ca := e.value("ca-cert", envCACert, e.ca)

	if e.passed("socket") {
		// An explicit --socket declares this invocation local. A KANEA_URL
		// exported for some other tool must not redirect it, so the environment
		// is dropped -- but a remote flag on the same command line is a
		// contradiction rather than a precedence question, and is refused.
		if e.passed("url") {
			return ep, errors.New("--socket and --url name two different endpoints; pass one")
		}
		if e.passed("token") || e.passed("ca-cert") {
			return ep, errors.New("--socket is local; --token and --ca-cert apply to --url")
		}
		return ep, nil
	}

	ep.URL, ep.Token = url, token
	pem, err := loadCACert(ca)
	if err != nil {
		return ep, err
	}
	ep.CACert = pem
	return ep, nil
}

// client resolves the endpoint and builds the client for it.
func (e *endpoint) client() (*api.Client, error) {
	ep, err := e.resolve()
	if err != nil {
		return nil, err
	}
	return api.NewClientFor(ep)
}

// local refuses a remote endpoint for a command that acts on this host.
//
// Some commands are about the machine rather than the platform: `kanea upgrade`
// restarts this host's units and writes this host's binary. Reading a remote
// daemon's version and then restarting local services is the worst outcome
// available, so it is refused by name.
func (e *endpoint) local(command, why string) error {
	ep, err := e.resolve()
	if err != nil {
		return err
	}
	if ep.Remote() {
		return fmt.Errorf("kanea %s acts on this host: %s. Run it on the node, or over ssh",
			command, why)
	}
	return nil
}

// loadCACert reads the CA from a file, or takes the value as the PEM itself.
//
// A CI system hands a secret to a job as an environment value; requiring
// `echo "$CA" > ca.pem` first is the step people skip by reaching for a
// skip-verify flag instead, which is why there is no skip-verify flag.
func loadCACert(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if api.CACertIsInline(value) {
		return []byte(value), nil
	}
	pem, err := os.ReadFile(value) // #nosec G304; an operator-named public certificate
	if err != nil {
		return nil, fmt.Errorf("read the CA certificate %s: %w", value, err)
	}
	return pem, nil
}
