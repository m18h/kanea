package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolveWith parses args with the environment set, the way a CI job would
// arrive: variables exported, flags mostly absent.
func resolveWith(t *testing.T, env map[string]string, args ...string) (ep *endpoint, err error) {
	t.Helper()
	for _, name := range []string{envURL, envToken, envCACert} {
		t.Setenv(name, env[name])
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.NewFile(0, os.DevNull))
	ep = endpointFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return ep, nil
}

func TestEndpointResolvesFromTheEnvironment(t *testing.T) {
	ep, _ := resolveWith(t, map[string]string{
		envURL: "https://node:8600", envToken: "tok",
	})
	got, err := ep.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !got.Remote() || got.URL != "https://node:8600" || got.Token != "tok" {
		t.Fatalf("resolve() = %+v, want the environment's endpoint", got)
	}
}

// TestAnEmptyEnvironmentVariableIsUnset is the CI failure mode this rule
// exists for: a secret that was never exported renders as the empty string, and
// treating that as "a token was supplied" produces a 401 instead of a message
// naming the missing secret.
func TestAnEmptyEnvironmentVariableIsUnset(t *testing.T) {
	ep, _ := resolveWith(t, map[string]string{envURL: "", envToken: ""})
	got, err := ep.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Remote() {
		t.Fatalf("an empty KANEA_URL produced a remote endpoint: %+v", got)
	}
}

func TestAFlagBeatsTheEnvironment(t *testing.T) {
	ep, _ := resolveWith(t,
		map[string]string{envURL: "https://from-env:8600", envToken: "tok"},
		"--url", "https://from-flag:8600")
	got, err := ep.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.URL != "https://from-flag:8600" {
		t.Errorf("URL = %q, want the flag to win", got.URL)
	}
}

// TestAnExplicitSocketStaysLocal keeps an exported KANEA_URL from redirecting a
// command that was told, on its own command line, to talk to this machine.
func TestAnExplicitSocketStaysLocal(t *testing.T) {
	ep, _ := resolveWith(t,
		map[string]string{envURL: "https://node:8600", envToken: "tok"},
		"--socket", "/tmp/x.sock")
	got, err := ep.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Remote() {
		t.Fatalf("--socket was overridden by KANEA_URL: %+v", got)
	}
	if got.Socket != "/tmp/x.sock" {
		t.Errorf("Socket = %q", got.Socket)
	}
}

func TestContradictoryFlagsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"socket and url", []string{"--socket", "/tmp/x.sock", "--url", "https://n:8600"}, "two different endpoints"},
		{"socket and token", []string{"--socket", "/tmp/x.sock", "--token", "t"}, "--socket is local"},
		{"socket and ca", []string{"--socket", "/tmp/x.sock", "--ca-cert", "/tmp/ca"}, "--socket is local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep, _ := resolveWith(t, nil, tc.args...)
			_, err := ep.resolve()
			if err == nil {
				t.Fatal("accepted a contradiction")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestCACertTakesAPathOrThePEM covers the reason the inline form exists: CI
// hands a secret to a job as a value, and requiring a file first is the step
// people skip by reaching for a skip-verify flag.
func TestCACertTakesAPathOrThePEM(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

	inline, err := loadCACert(pem)
	if err != nil || string(inline) != pem {
		t.Fatalf("inline PEM: %v / %q", err, inline)
	}

	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := loadCACert(path)
	if err != nil || string(fromFile) != pem {
		t.Fatalf("from file: %v / %q", err, fromFile)
	}

	if _, err := loadCACert(filepath.Join(t.TempDir(), "missing.crt")); err == nil {
		t.Error("a missing CA file was accepted")
	}
	if got, err := loadCACert(""); err != nil || got != nil {
		t.Errorf("empty = %q / %v, want nil", got, err)
	}
}

// TestLocalOnlyCommandsRefuseARemoteEndpoint pins that `kanea upgrade` cannot
// read a remote daemon and then restart this machine's units, which is the
// worst outcome available on this surface.
func TestLocalOnlyCommandsRefuseARemoteEndpoint(t *testing.T) {
	ep, _ := resolveWith(t, map[string]string{
		envURL: "https://node:8600", envToken: "tok",
	})
	err := ep.local("upgrade", "it restarts this machine's units")
	if err == nil {
		t.Fatal("a remote endpoint was accepted by a local-only command")
	}
	if !strings.Contains(err.Error(), "acts on this host") {
		t.Errorf("err = %q", err)
	}

	local, _ := resolveWith(t, nil)
	if err := local.local("upgrade", "x"); err != nil {
		t.Errorf("a local endpoint was refused: %v", err)
	}
}
