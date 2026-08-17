package secretsource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/sigv4"
)

const (
	awsTestAccessKey = "AKIAEXAMPLE"
	awsTestSecretKey = "test-secret-key"
	awsTestRegion    = "eu-west-1"
)

// verifySigV4 recomputes the request's signature server-side and compares;
// the MinIO lesson: a fake that accepts anything verifies nothing, and the
// s3-interop job exists because every unit test used to pass a
// strings.Reader.
func verifySigV4(t *testing.T, r *http.Request, body []byte) {
	t.Helper()
	stamp := r.Header.Get("X-Amz-Date")
	when, err := time.Parse("20060102T150405Z", stamp)
	if err != nil {
		t.Errorf("X-Amz-Date %q: %v", stamp, err)
		return
	}
	replica, err := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"Content-Type", "X-Amz-Target"} {
		if v := r.Header.Get(h); v != "" {
			replica.Header.Set(h, v)
		}
	}
	sigv4.Sign(replica, sigv4.Options{
		AccessKey: awsTestAccessKey, SecretKey: awsTestSecretKey,
		Region: awsTestRegion, Service: "secretsmanager",
		PayloadHash: sigv4.HashHex(body), Now: when,
	})
	if got, want := r.Header.Get("Authorization"), replica.Header.Get("Authorization"); got != want {
		t.Errorf("signature mismatch:\ngot  %s\nwant %s", got, want)
	}
}

func awssmFixture(t *testing.T, handler http.Handler, maps []syncMapping) *awssmProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	secretKey := writeFile(t, t.TempDir(), "aws.secret", awsTestSecretKey, 0o600)
	cfg := providerConfig{
		kind: KindAWS, name: "prod",
		hcl: hclProvider{Region: awsTestRegion, AccessKey: awsTestAccessKey,
			SecretKeyFile: secretKey, Endpoint: srv.URL},
		maps: maps,
	}
	return newAWSSM(cfg, DefaultHTTPClient(), discardLogger())
}

func TestAWSSMFetchIsSignedAndParsed(t *testing.T) {
	maps := []syncMapping{
		{To: "shop/db-password", ID: "prod/shop/db", JSONKey: "password", VersionStage: "AWSCURRENT"},
		{To: "shop/db-user", ID: "prod/shop/db", JSONKey: "user", VersionStage: "AWSCURRENT"},
		{To: "shop/flat", ID: "prod/shop/flat", VersionStage: "AWSCURRENT"},
	}
	requests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, _ := io.ReadAll(r.Body)
		verifySigV4(t, r, body)
		if got := r.Header.Get("X-Amz-Target"); got != "secretsmanager.GetSecretValue" {
			t.Errorf("X-Amz-Target = %q", got)
		}
		var req struct {
			SecretID     string `json:"SecretId"`
			VersionStage string
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("request body: %v", err)
		}
		switch req.SecretID {
		case "prod/shop/db":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"SecretString": `{"password": "hunter2", "user": "shop"}`,
			})
		case "prod/shop/flat":
			_ = json.NewEncoder(w).Encode(map[string]string{"SecretString": "flat-value"})
		default:
			t.Errorf("unexpected SecretId %q", req.SecretID)
		}
	})
	p := awssmFixture(t, handler, maps)

	res := p.Fetch(context.Background())
	if len(res.Failures) != 0 {
		t.Fatalf("Failures = %+v", res.Failures)
	}
	got := map[string]string{}
	for _, v := range res.Values {
		got[v.To] = string(v.Data)
	}
	want := map[string]string{
		"shop/db-password": "hunter2", "shop/db-user": "shop", "shop/flat": "flat-value",
	}
	for to, value := range want {
		if got[to] != value {
			t.Errorf("%s = %q, want %q", to, got[to], value)
		}
	}
	// Two json_key mappings on one id are one request.
	if requests != 2 {
		t.Errorf("made %d requests, want 2", requests)
	}
}

func TestAWSSMDecodesSecretBinary(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xfe, 0xff}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"SecretBinary": base64.StdEncoding.EncodeToString(raw),
		})
	})
	p := awssmFixture(t, handler, []syncMapping{{To: "shop/blob", ID: "blob", VersionStage: "AWSCURRENT"}})

	res := p.Fetch(context.Background())
	if len(res.Values) != 1 || string(res.Values[0].Data) != string(raw) {
		t.Errorf("Values = %+v, Failures = %+v", res.Values, res.Failures)
	}
}

func TestAWSSMJSONKeyRefusals(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"SecretString": "not-json"})
	})
	p := awssmFixture(t, handler, []syncMapping{
		{To: "shop/a", ID: "x", JSONKey: "password", VersionStage: "AWSCURRENT"},
	})

	res := p.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "JSON object") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

func TestAWSSMAMissingSecretFailsOnlyItself(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "missing") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type": "ResourceNotFoundException", "message": "Secrets Manager can't find the specified secret."}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"SecretString": "ok"})
	})
	p := awssmFixture(t, handler, []syncMapping{
		{To: "shop/ok", ID: "present", VersionStage: "AWSCURRENT"},
		{To: "shop/gone", ID: "missing", VersionStage: "AWSCURRENT"},
	})

	res := p.Fetch(context.Background())
	if len(res.Values) != 1 || res.Values[0].To != "shop/ok" {
		t.Errorf("Values = %+v", res.Values)
	}
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "find the specified secret") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}
