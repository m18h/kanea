package secretsource

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// gcpsmProvider fetches from GCP Secret Manager, authenticating with a
// service-account key: a hand-built RS256 JWT exchanged for an access token
// at the key's own token_uri (the OAuth2 jwt-bearer grant). The metadata
// server — GCP's ambient identity — is out by design (§5.2.13).
//
// The access token is cached like Azure's; the JWT itself is minted fresh per
// exchange because it is one RSA signature over a hundred bytes.
type gcpsmProvider struct {
	name        string
	endpoint    string
	project     string // config override; defaults to the key's project_id
	credentials string // credentials_file path; read at token fetch
	maps        []syncMapping
	client      *http.Client
	log         *slog.Logger
	now         func() time.Time

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

const (
	gcpDefaultEndpoint = "https://secretmanager.googleapis.com"
	gcpScope           = "https://www.googleapis.com/auth/cloud-platform"
	gcpJWTBearerGrant  = "urn:ietf:params:oauth:grant-type:jwt-bearer" // #nosec G101 — a grant-type URN, not a credential
)

func newGCPSM(cfg providerConfig, client *http.Client, log *slog.Logger) *gcpsmProvider {
	endpoint := cfg.hcl.Endpoint
	if endpoint == "" {
		endpoint = gcpDefaultEndpoint
	}
	return &gcpsmProvider{
		name: cfg.name, endpoint: endpoint, project: cfg.hcl.Project,
		credentials: cfg.hcl.CredentialsFile,
		maps:        cfg.maps, client: client, log: log, now: time.Now,
	}
}

func (g *gcpsmProvider) Kind() Kind   { return KindGCP }
func (g *gcpsmProvider) Name() string { return g.name }

func (g *gcpsmProvider) ref(m syncMapping) string {
	return m.Name + "@" + m.Version
}

// serviceAccountKey is the part of the downloaded key JSON this provider
// reads. The private key never leaves this process and is parsed fresh at
// each token exchange, so a rotated key file needs no restart.
type serviceAccountKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
	ProjectID   string `json:"project_id"`
}

func (g *gcpsmProvider) Fetch(ctx context.Context) Result {
	var res Result
	for _, m := range g.maps {
		value, err := g.accessVersion(ctx, m)
		if err != nil {
			res.Failures = append(res.Failures, Failure{To: m.To, Ref: g.ref(m), Err: err})
			continue
		}
		res.Values = append(res.Values, Value{To: m.To, Ref: g.ref(m), Data: value})
	}
	return res
}

// accessVersion reads one secret version, refreshing the token once on a 401
// (Azure's rule: one revoked-early token is routine, two is an answer).
func (g *gcpsmProvider) accessVersion(ctx context.Context, m syncMapping) ([]byte, error) {
	value, status, err := g.tryAccess(ctx, m)
	if status == http.StatusUnauthorized {
		g.invalidateToken()
		value, _, err = g.tryAccess(ctx, m)
	}
	return value, err
}

func (g *gcpsmProvider) tryAccess(ctx context.Context, m syncMapping) ([]byte, int, error) {
	token, project, err := g.accessToken(ctx)
	if err != nil {
		return nil, 0, err
	}

	u := fmt.Sprintf("%s/v1/projects/%s/secrets/%s/versions/%s:access",
		g.endpoint, url.PathEscape(project), url.PathEscape(m.Name), url.PathEscape(m.Version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, httpStatusError(resp)
	}
	body, err := readAndClose(resp)
	if err != nil {
		return nil, 0, err
	}
	var parsed struct {
		Payload struct {
			Data       []byte `json:"data"` // base64 on the wire
			DataCrc32c string `json:"dataCrc32c"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, 0, fmt.Errorf("secretsource: %s: unexpected Secret Manager shape: %w", m.Name, err)
	}
	if len(parsed.Payload.Data) == 0 {
		return nil, 0, fmt.Errorf("secretsource: %s@%s has no payload", m.Name, m.Version)
	}
	// The API sends the checksum precisely so a client can notice corruption
	// before acting on the value; ignoring it would be declining the offer.
	if parsed.Payload.DataCrc32c != "" {
		want := fmt.Sprintf("%d", crc32.Checksum(parsed.Payload.Data, crc32.MakeTable(crc32.Castagnoli)))
		if parsed.Payload.DataCrc32c != want {
			return nil, 0, fmt.Errorf("secretsource: %s@%s failed its crc32c check", m.Name, m.Version)
		}
	}
	return parsed.Payload.Data, resp.StatusCode, nil
}

func (g *gcpsmProvider) invalidateToken() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.token, g.tokenExpiry = "", time.Time{}
}

// accessToken returns the cached token — and the project it is for — or
// exchanges a fresh self-signed JWT at the key's token_uri.
func (g *gcpsmProvider) accessToken(ctx context.Context) (token, project string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	raw, err := readCredentialFile(g.credentials)
	if err != nil {
		return "", "", err
	}
	var key serviceAccountKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return "", "", fmt.Errorf("secretsource: %s is not a service-account key JSON: %w",
			g.credentials, err)
	}
	if key.ClientEmail == "" || key.PrivateKey == "" || key.TokenURI == "" {
		return "", "", fmt.Errorf(
			"secretsource: %s is missing client_email, private_key or token_uri", g.credentials)
	}
	project = g.project
	if project == "" {
		project = key.ProjectID
	}
	if project == "" {
		return "", "", fmt.Errorf(
			"secretsource: no project: neither the config nor %s's project_id names one", g.credentials)
	}

	if g.token != "" && g.now().Before(g.tokenExpiry.Add(-tokenExpirySlack)) {
		return g.token, project, nil
	}

	assertion, err := signJWT(key, g.now())
	if err != nil {
		return "", "", err
	}
	form := url.Values{"grant_type": {gcpJWTBearerGrant}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, key.TokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("secretsource: gcp token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("secretsource: gcp token: %w", httpStatusError(resp))
	}
	body, err := readAndClose(resp)
	if err != nil {
		return "", "", err
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", "", fmt.Errorf("secretsource: gcp token endpoint answered without a token")
	}
	g.token = parsed.AccessToken
	g.tokenExpiry = g.now().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	return g.token, project, nil
}

// signJWT builds and signs the RS256 assertion the jwt-bearer grant wants.
// Hand-built for the reason the MCP server is: the shape is three base64url
// segments and one RSA signature, and a JWT library is a dependency tree for
// a format this fixed.
func signJWT(key serviceAccountKey, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("secretsource: the service-account private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Older keys are PKCS#1.
		if parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return "", fmt.Errorf("secretsource: parse service-account key: %w", err)
		}
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("secretsource: service-account key is %T, not RSA", parsed)
	}

	encode := func(v any) (string, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(raw), nil
	}
	header, err := encode(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := encode(map[string]any{
		"iss":   key.ClientEmail,
		"scope": gcpScope,
		"aud":   key.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}

	signingInput := header + "." + claims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("secretsource: sign assertion: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
