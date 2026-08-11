package sigv4

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestKnownVector signs the request AWS documents as the SigV4 worked example
// and asserts the exact signature. A fake server accepts a signature that
// signs nothing; a published vector does not.
//
// The vector: GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08
// at 2015-08-30T12:36:00Z with the documented example credentials.
func TestKnownVector(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet,
		"https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	Sign(req, Options{
		AccessKey:   "AKIDEXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
		Service:     "iam",
		PayloadHash: HashHex(nil),
		Now:         time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC),
	})

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization =\n%s\nwant\n%s", got, want)
	}
}

func TestEveryAmzHeaderIsSigned(t *testing.T) {
	// AWS rejects a request carrying an x-amz-* header the signature does not
	// cover, so a caller adding X-Amz-Target (Secrets Manager's verb header)
	// must see it in SignedHeaders without asking.
	req, err := http.NewRequest(http.MethodPost, "https://secretsmanager.eu-west-1.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")

	Sign(req, Options{
		AccessKey: "AKIAEXAMPLE", SecretKey: "secret",
		Region: "eu-west-1", Service: "secretsmanager",
		PayloadHash: HashHex([]byte(`{"SecretId":"x"}`)),
		Now:         time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
	})

	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date;x-amz-target,") {
		t.Errorf("SignedHeaders is missing a header:\n%s", auth)
	}
}

func TestS3GetsTheContentHashHeader(t *testing.T) {
	// S3 wants the payload hash in a header as well as in the canonical
	// request; the JSON services reject the header's absence nowhere and the
	// signer must not invent it for them.
	s3req, _ := http.NewRequest(http.MethodPut, "https://b.s3.example.com/key", nil)
	Sign(s3req, Options{AccessKey: "a", SecretKey: "s", Region: "r", Service: "s3",
		PayloadHash: UnsignedPayload, Now: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)})
	if got := s3req.Header.Get("X-Amz-Content-Sha256"); got != UnsignedPayload {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %s", got, UnsignedPayload)
	}

	smreq, _ := http.NewRequest(http.MethodPost, "https://secretsmanager.example.com/", nil)
	Sign(smreq, Options{AccessKey: "a", SecretKey: "s", Region: "r", Service: "secretsmanager",
		PayloadHash: HashHex(nil), Now: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)})
	if got := smreq.Header.Get("X-Amz-Content-Sha256"); got != "" {
		t.Errorf("a non-S3 service got X-Amz-Content-Sha256 = %q", got)
	}
}

func TestPayloadHashChangesTheSignature(t *testing.T) {
	sign := func(hash string) string {
		req, _ := http.NewRequest(http.MethodPost, "https://secretsmanager.example.com/", nil)
		Sign(req, Options{AccessKey: "a", SecretKey: "s", Region: "r", Service: "secretsmanager",
			PayloadHash: hash, Now: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)})
		return req.Header.Get("Authorization")
	}
	if sign(HashHex([]byte("one"))) == sign(HashHex([]byte("two"))) {
		t.Error("the signature did not change with the payload hash")
	}
}

func TestCanonicalQueryEncodesSpacesTheWaySigV4Requires(t *testing.T) {
	// url.Values.Encode would write "+", which SigV4 does not accept. No
	// current parameter contains a space, and relying on that is relying on a
	// fact about today's callers.
	got := CanonicalQuery(url.Values{"prefix": {"a b"}, "list-type": {"2"}})
	want := "list-type=2&prefix=a%20b"
	if got != want {
		t.Errorf("CanonicalQuery = %q, want %q", got, want)
	}
}
