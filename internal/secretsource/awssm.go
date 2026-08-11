package secretsource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/m18h/kanea/internal/sigv4"
)

// awssmProvider fetches from AWS Secrets Manager: one SigV4-signed
// `GetSecretValue` per distinct secret id, sharing the signer the backup S3
// sink uses. Static access keys only — instance roles mean the IMDS, which
// the platform's egress posture treats as hostile (§5.2.13, §14 A10).
type awssmProvider struct {
	name      string
	region    string
	endpoint  string
	accessKey string
	secretKey string // secret_key_file path; read every Fetch
	maps      []syncMapping
	client    *http.Client
	log       *slog.Logger
	now       func() time.Time
}

func newAWSSM(cfg providerConfig, client *http.Client, log *slog.Logger) *awssmProvider {
	endpoint := cfg.hcl.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", cfg.hcl.Region)
	}
	return &awssmProvider{
		name: cfg.name, region: cfg.hcl.Region, endpoint: endpoint,
		accessKey: cfg.hcl.AccessKey, secretKey: cfg.hcl.SecretKeyFile,
		maps: cfg.maps, client: client, log: log, now: time.Now,
	}
}

func (a *awssmProvider) Kind() Kind   { return KindAWS }
func (a *awssmProvider) Name() string { return a.name }

func (a *awssmProvider) ref(m syncMapping) string {
	if m.JSONKey != "" {
		return m.ID + "#" + m.JSONKey
	}
	return m.ID
}

// getSecretValueResponse is the API's answer: exactly one of SecretString and
// SecretBinary is set.
type getSecretValueResponse struct {
	SecretString string `json:"SecretString"`
	SecretBinary []byte `json:"SecretBinary"` // encoding/json base64-decodes []byte
}

func (a *awssmProvider) Fetch(ctx context.Context) Result {
	secretKey, err := readCredentialFile(a.secretKey)
	if err != nil {
		return failAll(a.maps, a.ref, err)
	}

	// One request per distinct id+stage; json_key fan-out happens locally.
	type coord struct{ id, stage string }
	byCoord := make(map[coord][]syncMapping)
	var order []coord
	for _, m := range a.maps {
		c := coord{m.ID, m.VersionStage}
		if _, seen := byCoord[c]; !seen {
			order = append(order, c)
		}
		byCoord[c] = append(byCoord[c], m)
	}

	var res Result
	for _, c := range order {
		group := byCoord[c]
		value, err := a.getSecretValue(ctx, string(secretKey), c.id, c.stage)
		if err != nil {
			for _, m := range group {
				res.Failures = append(res.Failures, Failure{To: m.To, Ref: a.ref(m), Err: err})
			}
			continue
		}
		for _, m := range group {
			data, err := pickJSONKey(value, m.JSONKey, c.id)
			if err != nil {
				res.Failures = append(res.Failures, Failure{To: m.To, Ref: a.ref(m), Err: err})
				continue
			}
			res.Values = append(res.Values, Value{To: m.To, Ref: a.ref(m), Data: data})
		}
	}
	return res
}

func (a *awssmProvider) getSecretValue(ctx context.Context, secretKey, id, stage string) ([]byte, error) {
	payload, err := json.Marshal(map[string]string{"SecretId": id, "VersionStage": stage})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	sigv4.Sign(req, sigv4.Options{
		AccessKey: a.accessKey, SecretKey: secretKey,
		Region: a.region, Service: "secretsmanager",
		PayloadHash: sigv4.HashHex(payload), Now: a.now(),
	})

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError(resp)
	}
	body, err := readAndClose(resp)
	if err != nil {
		return nil, err
	}
	var parsed getSecretValueResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("secretsource: %s: unexpected GetSecretValue shape: %w", id, err)
	}
	if parsed.SecretString != "" {
		return []byte(parsed.SecretString), nil
	}
	if len(parsed.SecretBinary) > 0 {
		return parsed.SecretBinary, nil
	}
	return nil, fmt.Errorf("secretsource: %s has neither SecretString nor SecretBinary", id)
}

// pickJSONKey extracts one string value from a JSON-object secret when the
// mapping asks for it, and passes the whole value through when it does not.
func pickJSONKey(value []byte, key, id string) ([]byte, error) {
	if key == "" {
		return value, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(value, &obj); err != nil {
		return nil, fmt.Errorf("secretsource: %s: json_key needs a JSON object secret: %w", id, err)
	}
	raw, ok := obj[key]
	if !ok {
		return nil, fmt.Errorf("secretsource: %s has no key %q", id, key)
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("secretsource: %s key %q is %T, not a string", id, key, raw)
	}
	return []byte(s), nil
}
