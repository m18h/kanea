package runtime

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
)

// ImageRef names an image to fetch and the credential to fetch it with.
//
// Auth is a docker `config.json`, already resolved by the caller: this package
// never resolves `secret:` references (R3), and the same rule that keeps secret
// values out of the driver keeps them out of the driver's logs.
type ImageRef struct {
	Project string
	Ref     string
	// Auth is nil for a public registry, which is the common case and the only
	// case that worked before v1.32.
	Auth []byte
	// Policy is R33's pull policy: empty or PullIfNotPresent is the historical
	// behaviour, PullNever refuses to reach the network. PullAlways never
	// arrives here (it lowers to R19 auto-update at parse time) and is read as
	// PullIfNotPresent if it somehow does, because the alternative is a driver
	// re-pulling per alloc create behind the record's back.
	Policy string
}

// dockerConfig is the subset of a docker config.json that carries credentials.
type dockerConfig struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

type dockerAuthEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Auth is base64("user:pass") and is what `docker login` actually writes.
	Auth string `json:"auth"`
	// IdentityToken is what a registry issues in place of a password. When it
	// is set the username is ignored and the token is sent as the password,
	// which is the convention containerd's authorizer already expects.
	IdentityToken string `json:"identitytoken"`
}

// dockerHostAliases are the spellings that all mean Docker Hub.
//
// `docker login` writes `https://index.docker.io/v1/`, containerd resolves
// against `registry-1.docker.io`, and a spec says `docker.io`. Three names for
// one registry, and a credential filed under one of them has to be found under
// the others or a valid login silently pulls anonymously.
var dockerHostAliases = []string{"docker.io", "index.docker.io", "registry-1.docker.io"}

// credentials indexes a docker config.json by registry host.
type credentials map[string]dockerAuthEntry

func parseCredentials(raw []byte) (credentials, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		// Deliberately does not quote the document: it is a credential file,
		// and a parse error that echoes it puts a password in a log line.
		return nil, fmt.Errorf("registry credential is not a docker config.json: %w", err)
	}
	if len(cfg.Auths) == 0 {
		return nil, fmt.Errorf("registry credential has no `auths` entries")
	}

	creds := make(credentials, len(cfg.Auths))
	for host, entry := range cfg.Auths {
		creds[normalizeAuthHost(host)] = entry
	}
	return creds, nil
}

// normalizeAuthHost reduces a config.json key to a bare host.
//
// The keys in the wild are inconsistent (`https://index.docker.io/v1/`,
// `ghcr.io`, `registry.example.com:5000/v2/`) and comparing them literally
// against what the resolver asks for finds nothing most of the time.
func normalizeAuthHost(host string) string {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	return host
}

// lookup returns the credential for a host, following the Docker Hub aliases.
func (c credentials) lookup(host string) (dockerAuthEntry, bool) {
	if entry, ok := c[host]; ok {
		return entry, true
	}
	for _, alias := range dockerHostAliases {
		if host != alias {
			continue
		}
		for _, other := range dockerHostAliases {
			if entry, ok := c[other]; ok {
				return entry, true
			}
		}
	}
	return dockerAuthEntry{}, false
}

// userPass renders one entry as the pair containerd's authorizer wants.
func (e dockerAuthEntry) userPass() (string, string, error) {
	if e.IdentityToken != "" {
		// containerd's convention: an empty username means the password field
		// carries a bearer token rather than a password.
		return "", e.IdentityToken, nil
	}
	if e.Auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(e.Auth)
		if err != nil {
			return "", "", fmt.Errorf("registry credential `auth` is not valid base64: %w", err)
		}
		user, pass, found := strings.Cut(string(decoded), ":")
		if !found {
			return "", "", fmt.Errorf("registry credential `auth` is not user:password")
		}
		return user, pass, nil
	}
	if e.Username == "" && e.Password == "" {
		return "", "", fmt.Errorf("registry credential has neither `auth` nor a username and password")
	}
	return e.Username, e.Password, nil
}

// resolverFor builds an image resolver, authenticated when a credential is
// given and anonymous when one is not.
//
// A host with no matching credential resolves anonymously rather than failing:
// a config.json holding a private registry's login is not a statement that
// Docker Hub now needs one, and a service pulling a public base image should
// not break because another service in the project has a credential.
func resolverFor(auth []byte) (remotes.Resolver, error) {
	creds, err := parseCredentials(auth)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return docker.NewResolver(docker.ResolverOptions{}), nil
	}

	authorizer := docker.NewDockerAuthorizer(
		docker.WithAuthCreds(func(host string) (string, string, error) {
			entry, ok := creds.lookup(host)
			if !ok {
				return "", "", nil
			}
			return entry.userPass()
		}),
	)
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: docker.ConfigureDefaultRegistries(docker.WithAuthorizer(authorizer)),
	}), nil
}
