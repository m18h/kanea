package secretsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// vaultProvider reads KV v2 secrets over token auth. Mappings are grouped by
// path (one GET per distinct path serves every field mapped out of it) and
// a 404 fails only that path's mappings.
//
// Token-file auth only, deliberately (§5.2.13): AppRole and other dynamic
// auth methods are a login protocol to keep current with Vault, and the token
// file composes with every external rotation tool the same way the
// certificate files do.
type vaultProvider struct {
	name    string
	address string
	token   string // token_file path
	mount   string
	maps    []syncMapping
	client  *http.Client
	log     *slog.Logger
}

func newVault(cfg providerConfig, client *http.Client, log *slog.Logger) (*vaultProvider, error) {
	if cfg.hcl.CAFile != "" {
		withCA, err := clientWithCA(client, cfg.hcl.CAFile)
		if err != nil {
			return nil, fmt.Errorf("secretsource: provider %q: %w", cfg.name, err)
		}
		client = withCA
	}
	return &vaultProvider{
		name: cfg.name, address: cfg.hcl.Address, token: cfg.hcl.TokenFile,
		mount: cfg.hcl.Mount, maps: cfg.maps, client: client, log: log,
	}, nil
}

func (v *vaultProvider) Kind() Kind   { return KindVault }
func (v *vaultProvider) Name() string { return v.name }

func (v *vaultProvider) ref(m syncMapping) string {
	return v.mount + "/" + m.Path + "#" + m.Field
}

// kvV2Response is the KV v2 read envelope: the secret's own keys sit under
// data.data, beside the version metadata this provider does not consume.
type kvV2Response struct {
	Data struct {
		Data map[string]any `json:"data"`
	} `json:"data"`
}

func (v *vaultProvider) Fetch(ctx context.Context) Result {
	token, err := readCredentialFile(v.token)
	if err != nil {
		return failAll(v.maps, v.ref, err)
	}

	byPath := make(map[string][]syncMapping)
	var order []string
	for _, m := range v.maps {
		if _, seen := byPath[m.Path]; !seen {
			order = append(order, m.Path)
		}
		byPath[m.Path] = append(byPath[m.Path], m)
	}

	var res Result
	for _, path := range order {
		group := byPath[path]
		data, err := v.read(ctx, string(token), path)
		if err != nil {
			for _, m := range group {
				res.Failures = append(res.Failures, Failure{To: m.To, Ref: v.ref(m), Err: err})
			}
			continue
		}
		for _, m := range group {
			raw, ok := data[m.Field]
			if !ok {
				res.Failures = append(res.Failures, Failure{To: m.To, Ref: v.ref(m),
					Err: fmt.Errorf("secretsource: %s/%s has no field %q", v.mount, path, m.Field)})
				continue
			}
			// Only a string is a secret value. A map or a number silently
			// re-encoded into a credential file is a lie; refusing by name is
			// honest.
			value, ok := raw.(string)
			if !ok {
				res.Failures = append(res.Failures, Failure{To: m.To, Ref: v.ref(m),
					Err: fmt.Errorf("secretsource: %s/%s field %q is %T, not a string",
						v.mount, path, m.Field, raw)})
				continue
			}
			res.Values = append(res.Values, Value{To: m.To, Ref: v.ref(m), Data: []byte(value)})
		}
	}
	return res
}

func (v *vaultProvider) read(ctx context.Context, token, path string) (map[string]any, error) {
	u := fmt.Sprintf("%s/v1/%s/data/%s", v.address, v.mount, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.Join(
			fmt.Errorf("secretsource: no secret at %s/%s", v.mount, path), resp.Body.Close())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError(resp)
	}
	body, err := readAndClose(resp)
	if err != nil {
		return nil, err
	}
	var envelope kvV2Response
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("secretsource: %s/%s is not a KV v2 response: %w", v.mount, path, err)
	}
	if envelope.Data.Data == nil {
		return nil, fmt.Errorf("secretsource: %s/%s has no data (is %q a KV v2 mount?)",
			v.mount, path, v.mount)
	}
	return envelope.Data.Data, nil
}
