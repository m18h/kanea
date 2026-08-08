package gitops_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/gitops"
)

const webhookSecretRef = "secret:git/webhook"

func newWebhooks(t *testing.T, secret string, c *clock) *gitops.Webhooks {
	t.Helper()
	return gitops.NewWebhooks(gitops.WebhooksConfig{
		Secrets: &resolver{values: map[string][]byte{webhookSecretRef: []byte(secret)}},
		Now:     c.now,
	})
}

// githubPush builds a signed GitHub push delivery.
func githubPush(secret, deliveryID, body string) (http.Header, []byte) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))

	header := http.Header{}
	header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	header.Set("X-GitHub-Event", "push")
	header.Set("X-GitHub-Delivery", deliveryID)
	return header, []byte(body)
}

const pushBody = `{"ref":"refs/heads/main","after":"abc123def456","deleted":false}`

func TestGitHubPushIsAccepted(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, body := githubPush("s3cret", "delivery-1", pushBody)

	got, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Provider != gitops.ProviderGitHub || got.Event != "push" {
		t.Fatalf("delivery = %+v", got)
	}
	if got.Branch() != "main" || got.Commit != "abc123def456" {
		t.Fatalf("delivery = %+v; want the branch and sha a deploy needs", got)
	}
	if !got.Deployable() {
		t.Error("a push to a branch is not deployable")
	}
}

func TestAForgedSignatureIsRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, body := githubPush("the-wrong-secret", "delivery-1", pushBody)

	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); !errors.Is(err, gitops.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestATamperedBodyIsRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, _ := githubPush("s3cret", "delivery-1", pushBody)

	// The signature covers the raw body. Changing one byte of it — here, the
	// commit that would be deployed — must invalidate the delivery.
	tampered := []byte(strings.Replace(pushBody, "abc123def456", "deadbeefcafe", 1))

	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, tampered); !errors.Is(err, gitops.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestAnUnsignedWebhookIsRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)

	header := http.Header{}
	header.Set("X-GitHub-Event", "push")
	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, []byte(pushBody)); !errors.Is(err, gitops.ErrUnsignedWebhook) {
		t.Fatalf("err = %v, want ErrUnsignedWebhook", err)
	}
}

func TestSHA1SignaturesAreRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)

	header := http.Header{}
	header.Set("X-Hub-Signature-256", "sha1=abc123")
	header.Set("X-GitHub-Event", "push")

	// A downgrade an attacker can request is not a compatibility feature.
	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, []byte(pushBody)); !errors.Is(err, gitops.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestAReplayedDeliveryIsRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, body := githubPush("s3cret", "delivery-1", pushBody)

	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	// A replayed push redeploys whatever that commit contained — which, after
	// a revert, is exactly what someone deliberately took out of production.
	_, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body)
	if !errors.Is(err, gitops.ErrReplayedWebhook) {
		t.Fatalf("err = %v, want ErrReplayedWebhook", err)
	}
}

func TestADeliveryIsAcceptedAgainOnceForgotten(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, body := githubPush("s3cret", "delivery-1", pushBody)

	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	// The window is longer than any provider's retry schedule, so a genuine
	// retry is still recognised — but it is not forever.
	c.advance(gitops.DefaultWebhookMemory + time.Minute)
	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); err != nil {
		t.Fatalf("delivery after the memory window: %v", err)
	}
}

func TestTheSameDeliveryIDInTwoProjectsIsNotAReplay(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, body := githubPush("s3cret", "delivery-1", pushBody)

	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); err != nil {
		t.Fatalf("shop: %v", err)
	}
	// Delivery ids are unique per provider installation, not globally, so
	// keying the cache on the id alone would make one project's push silence
	// another's.
	if _, err := w.Verify(context.Background(), "blog", webhookSecretRef, header, body); err != nil {
		t.Fatalf("blog: %v", err)
	}
}

func TestADeliveryWithNoIDIsAlwaysAccepted(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, body := githubPush("s3cret", "", pushBody)

	// A hand-rolled sender may omit one. Refusing it outright would break a
	// legitimate configuration to defend against a replay the signature
	// already makes expensive.
	for range 2 {
		if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
}

func TestGitLabTokenIsAccepted(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)

	header := http.Header{}
	header.Set("X-Gitlab-Token", "s3cret")
	header.Set("X-Gitlab-Event", "Push Hook")
	header.Set("X-Gitlab-Event-UUID", "uuid-1")
	body := []byte(`{"ref":"refs/heads/main","checkout_sha":"abc123"}`)

	got, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// One vocabulary downstream: nothing after this should have to know that
	// GitLab spells a push "Push Hook".
	if got.Event != "push" {
		t.Errorf("event = %q, want push", got.Event)
	}
	if got.Commit != "abc123" {
		t.Errorf("commit = %q; GitLab's checkout_sha was not read", got.Commit)
	}
}

func TestAWrongGitLabTokenIsRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)

	header := http.Header{}
	header.Set("X-Gitlab-Token", "not-the-secret")
	header.Set("X-Gitlab-Event", "Push Hook")

	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, []byte(`{}`)); !errors.Is(err, gitops.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestNonDeployableDeliveries(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)

	tests := []struct {
		name  string
		event string
		body  string
		why   string
	}{
		{
			name: "ping", event: "ping", body: `{"zen":"Keep it logically awesome."}`,
			why: "a provider checking the endpoint exists is not a deploy",
		},
		{
			name: "tag push", event: "push",
			body: `{"ref":"refs/tags/v1.0.0","after":"abc123"}`,
			why:  "a tag is not a branch",
		},
		{
			name: "branch deletion", event: "push",
			body: `{"ref":"refs/heads/feature","after":"abc123","deleted":true}`,
			why:  "a deleted branch has no tree to deploy",
		},
		{
			name: "gitlab deletion", event: "push",
			body: `{"ref":"refs/heads/feature","checkout_sha":"0000000000000000000000000000000000000000"}`,
			why:  "GitLab marks a deletion with an all-zero sha rather than a flag",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A distinct delivery id per case, so the replay cache does not
			// reject the later ones for the wrong reason.
			header, body := githubPush("s3cret", tc.name, tc.body)
			header.Set("X-GitHub-Event", tc.event)

			got, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			// All four arrive at this route legitimately. Accepting them and
			// declining to deploy is right; rejecting them would make a
			// provider's UI show a broken webhook.
			if got.Deployable() {
				t.Fatalf("%s is deployable, but %s", tc.name, tc.why)
			}
		})
	}
}

func TestAProjectWithNoWebhookSecretIsRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)
	header, body := githubPush("s3cret", "delivery-1", pushBody)

	// Not "accept anything": a project without a configured secret has no way
	// to authenticate a push, and silently trusting one would be the worst
	// possible reading of the missing configuration.
	_, err := w.Verify(context.Background(), "shop", "", header, body)
	if err == nil {
		t.Fatal("a webhook for a project with no secret was accepted")
	}
	if !strings.Contains(err.Error(), "webhook_secret_ref") {
		t.Errorf("err = %v; it does not say what to configure", err)
	}
}

func TestAnUnresolvableSecretIsRefused(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := gitops.NewWebhooks(gitops.WebhooksConfig{
		Secrets: &resolver{err: errors.New("secrets: not found")}, Now: c.now,
	})
	header, body := githubPush("s3cret", "delivery-1", pushBody)

	if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); err == nil {
		t.Fatal("a webhook was accepted with an unresolvable secret")
	}
}

func TestTimestampToleranceWhenASenderProvidesOne(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)

	if err := w.CheckTimestamp(c.at.Add(-time.Minute)); err != nil {
		t.Errorf("a recent timestamp was rejected: %v", err)
	}
	// Clock skew runs both ways, so a timestamp from the future is as much a
	// problem as one from the past.
	if err := w.CheckTimestamp(c.at.Add(time.Hour)); !errors.Is(err, gitops.ErrWebhookTooOld) {
		t.Errorf("a far-future timestamp was accepted: %v", err)
	}
	if err := w.CheckTimestamp(c.at.Add(-time.Hour)); !errors.Is(err, gitops.ErrWebhookTooOld) {
		t.Errorf("a stale timestamp was accepted: %v", err)
	}
	// No timestamp is not a failure: GitHub and GitLab send none, and the
	// delivery-id cache is what defends those.
	if err := w.CheckTimestamp(time.Time{}); err != nil {
		t.Errorf("an absent timestamp was treated as invalid: %v", err)
	}
}

func TestTheReplayCacheIsBounded(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	w := newWebhooks(t, "s3cret", c)

	// Reaching this needs the secret, but a cache whose keys come from the
	// network is bounded on principle — the same rule the rate limiter and the
	// metrics store follow.
	for i := range 6000 {
		header, body := githubPush("s3cret", string(rune(i))+"-delivery", pushBody)
		if _, err := w.Verify(context.Background(), "shop", webhookSecretRef, header, body); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	// The oldest entries are evicted, so an old delivery becomes acceptable
	// again — which is the trade a bound buys, and it is the right way round.
}
