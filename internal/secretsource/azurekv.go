package secretsource

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// azureKVProvider fetches from Azure Key Vault over an OAuth2
// client-credentials token — a service principal's app registration, static
// credentials in files (§5.2.13; managed identity means the IMDS, which is
// out by design).
//
// The access token is cached until near expiry and lives only here: never in
// the Store, never in status output, never logged. Providers.Current keeps
// this instance alive across unchanged passes precisely so the cache works.
type azureKVProvider struct {
	name         string
	vaultURI     string
	loginURL     string
	tenantID     string
	clientID     string
	clientSecret string // client_secret_file path; read at token fetch
	maps         []syncMapping
	client       *http.Client
	log          *slog.Logger
	now          func() time.Time

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

const (
	azureDefaultLogin = "https://login.microsoftonline.com"
	azureScope        = "https://vault.azure.net/.default"
	azureAPIVersion   = "7.4"
	// tokenExpirySlack refreshes a token before the wire would refuse it; a
	// clock's worth of margin is cheaper than a retried pass.
	tokenExpirySlack = 2 * time.Minute
)

func newAzureKV(cfg providerConfig, client *http.Client, log *slog.Logger) *azureKVProvider {
	login := cfg.hcl.LoginURL
	if login == "" {
		login = azureDefaultLogin
	}
	return &azureKVProvider{
		name: cfg.name, vaultURI: strings.TrimSuffix(cfg.hcl.VaultURI, "/"),
		loginURL: login, tenantID: cfg.hcl.TenantID, clientID: cfg.hcl.ClientID,
		clientSecret: cfg.hcl.ClientSecretFile,
		maps:         cfg.maps, client: client, log: log, now: time.Now,
	}
}

func (a *azureKVProvider) Kind() Kind   { return KindAzure }
func (a *azureKVProvider) Name() string { return a.name }

func (a *azureKVProvider) ref(m syncMapping) string {
	if m.Version != "" {
		return m.Name + "@" + m.Version
	}
	return m.Name
}

func (a *azureKVProvider) Fetch(ctx context.Context) Result {
	var res Result
	for _, m := range a.maps {
		value, err := a.getSecret(ctx, m)
		if err != nil {
			res.Failures = append(res.Failures, Failure{To: m.To, Ref: a.ref(m), Err: err})
			continue
		}
		res.Values = append(res.Values, Value{To: m.To, Ref: a.ref(m), Data: value})
	}
	return res
}

// getSecret reads one secret, refreshing the token once on a 401: a token
// revoked before its stated expiry is routine, a second 401 is an answer.
func (a *azureKVProvider) getSecret(ctx context.Context, m syncMapping) ([]byte, error) {
	value, status, err := a.tryGet(ctx, m)
	if status == http.StatusUnauthorized {
		a.invalidateToken()
		value, _, err = a.tryGet(ctx, m)
	}
	return value, err
}

func (a *azureKVProvider) tryGet(ctx context.Context, m syncMapping) ([]byte, int, error) {
	token, err := a.accessToken(ctx)
	if err != nil {
		return nil, 0, err
	}

	u := a.vaultURI + "/secrets/" + url.PathEscape(m.Name)
	if m.Version != "" {
		u += "/" + url.PathEscape(m.Version)
	}
	u += "?api-version=" + azureAPIVersion

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.client.Do(req)
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
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, 0, fmt.Errorf("secretsource: %s: unexpected Key Vault shape: %w", m.Name, err)
	}
	if parsed.Value == "" {
		return nil, 0, fmt.Errorf("secretsource: %s has an empty value", m.Name)
	}
	return []byte(parsed.Value), resp.StatusCode, nil
}

func (a *azureKVProvider) invalidateToken() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token, a.tokenExpiry = "", time.Time{}
}

// accessToken returns the cached token or fetches a fresh one via the OAuth2
// client-credentials grant.
func (a *azureKVProvider) accessToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && a.now().Before(a.tokenExpiry.Add(-tokenExpirySlack)) {
		return a.token, nil
	}

	secret, err := readCredentialFile(a.clientSecret)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {a.clientID},
		"client_secret": {string(secret)},
		"scope":         {azureScope},
	}
	u := a.loginURL + "/" + url.PathEscape(a.tenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("secretsource: azure token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("secretsource: azure token: %w", httpStatusError(resp))
	}
	body, err := readAndClose(resp)
	if err != nil {
		return "", err
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", fmt.Errorf("secretsource: azure token endpoint answered without a token")
	}
	a.token = parsed.AccessToken
	a.tokenExpiry = a.now().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	return a.token, nil
}
