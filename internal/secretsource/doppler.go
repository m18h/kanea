package secretsource

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// dopplerProvider fetches one Doppler config's secrets in a single call:
// `GET /v3/configs/config/secrets/download?format=json` returns the whole
// flat name→value map, which is the batch shape a pass wants anyway.
type dopplerProvider struct {
	name    string
	base    string
	token   string // token_file path; read every Fetch, so rotation needs no restart
	project string
	config  string
	maps    []syncMapping
	client  *http.Client
	log     *slog.Logger
}

const dopplerDefaultBase = "https://api.doppler.com"

func newDoppler(cfg providerConfig, client *http.Client, log *slog.Logger) *dopplerProvider {
	base := cfg.hcl.BaseURL
	if base == "" {
		base = dopplerDefaultBase
	}
	return &dopplerProvider{
		name: cfg.name, base: base, token: cfg.hcl.TokenFile,
		project: cfg.hcl.Project, config: cfg.hcl.ConfigName,
		maps: cfg.maps, client: client, log: log,
	}
}

func (d *dopplerProvider) Kind() Kind   { return KindDoppler }
func (d *dopplerProvider) Name() string { return d.name }

func (d *dopplerProvider) ref(m syncMapping) string {
	return d.project + "/" + d.config + "/" + m.Name
}

func (d *dopplerProvider) Fetch(ctx context.Context) Result {
	token, err := readCredentialFile(d.token)
	if err != nil {
		return failAll(d.maps, d.ref, err)
	}

	u := fmt.Sprintf("%s/v3/configs/config/secrets/download?project=%s&config=%s&format=json",
		d.base, d.project, d.config)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return failAll(d.maps, d.ref, err)
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	resp, err := d.client.Do(req)
	if err != nil {
		return failAll(d.maps, d.ref, err)
	}
	if resp.StatusCode != http.StatusOK {
		return failAll(d.maps, d.ref, httpStatusError(resp))
	}
	body, err := readAndClose(resp)
	if err != nil {
		return failAll(d.maps, d.ref, err)
	}

	var values map[string]string
	if err := json.Unmarshal(body, &values); err != nil {
		return failAll(d.maps, d.ref, fmt.Errorf("secretsource: doppler download is not a flat JSON object: %w", err))
	}

	var res Result
	for _, m := range d.maps {
		value, ok := values[m.Name]
		if !ok {
			res.Failures = append(res.Failures, Failure{To: m.To, Ref: d.ref(m),
				Err: fmt.Errorf("secretsource: config %s/%s has no secret named %q",
					d.project, d.config, m.Name)})
			continue
		}
		res.Values = append(res.Values, Value{To: m.To, Ref: d.ref(m), Data: []byte(value)})
	}
	return res
}
