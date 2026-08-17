package gitops

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Git push webhooks (PRD §10.1).
//
// This is the one route on the control plane that no session or token can
// authenticate: a push comes from GitHub, not from a person. It is not
// *unauthenticated* (it is authenticated by a shared secret the operator
// configured on both ends) but that is a different mechanism from §13, and
// saying so plainly is the point. Everything below exists to make that
// mechanism hold up:
//
//   - the signature is verified over the **raw body**, before it is parsed,
//     because a payload that has been through a decoder is no longer the bytes
//     that were signed;
//   - the comparison is constant-time, because a byte-at-a-time compare turns
//     forging a signature into 32 sequential guesses;
//   - a delivery is accepted once, because a replayed push would redeploy
//     whatever that commit contained; including a commit since reverted;
//   - and the body is bounded, because the sender chooses its size.

// MaxWebhookBody bounds an inbound payload.
//
// GitHub's push payloads grow with the number of commits and its own limit is
// 25 MB. Kanea reads a ref and a sha out of them, so a megabyte is generous:
// and a bound the sender does not choose is the point.
const MaxWebhookBody = 1 << 20

// Provider is which service sent a webhook.
type Provider string

// Providers Kanea validates (§10.1).
const (
	// ProviderGitHub signs the body: X-Hub-Signature-256.
	ProviderGitHub Provider = "github"
	// ProviderGitLab sends the shared secret itself: X-Gitlab-Token. Weaker
	// than a signature (the secret is on the wire every time rather than
	// proving knowledge of it) but it is what GitLab sends, and refusing to
	// support it would not make anyone's deployment safer.
	ProviderGitLab Provider = "gitlab"
)

// Delivery is a validated webhook.
type Delivery struct {
	Project  string
	Provider Provider
	// ID is the provider's delivery identifier, used to reject replays.
	ID string
	// Event is the provider's event name, e.g. "push" or "ping".
	Event string
	// Ref is the git ref that was pushed, e.g. "refs/heads/main".
	Ref string
	// Commit is the sha the ref now points at.
	Commit string
	// Deleted reports a branch deletion, which is a push that must not deploy.
	Deleted bool
}

// Branch is the short branch name, or "" for anything that is not a branch.
func (d Delivery) Branch() string {
	if !strings.HasPrefix(d.Ref, "refs/heads/") {
		return ""
	}
	return strings.TrimPrefix(d.Ref, "refs/heads/")
}

// Deployable reports whether this delivery should trigger a sync.
//
// A ping is a provider checking the endpoint exists; a tag push is not a
// branch; a branch deletion has no tree to deploy. All three arrive at this
// route legitimately and none of them is a deploy.
func (d Delivery) Deployable() bool {
	return d.Event == "push" && d.Branch() != "" && !d.Deleted
}

// Errors a webhook can fail with. They are distinguished because they map to
// different statuses and different operator actions.
var (
	// ErrUnsignedWebhook means no recognised signature header was present.
	ErrUnsignedWebhook = errors.New("gitops: webhook carries no signature")
	// ErrBadSignature means the signature did not match.
	ErrBadSignature = errors.New("gitops: webhook signature does not match")
	// ErrReplayedWebhook means this delivery has already been processed.
	ErrReplayedWebhook = errors.New("gitops: webhook delivery already processed")
	// ErrWebhookTooOld means the payload's timestamp is outside tolerance.
	ErrWebhookTooOld = errors.New("gitops: webhook timestamp is outside the tolerance window")
)

// WebhooksConfig configures the verifier.
type WebhooksConfig struct {
	// Secrets resolves the per-project webhook secret.
	Secrets Resolver
	// Tolerance bounds how old a timestamped payload may be. It applies only
	// to senders that provide a timestamp: see Verify.
	Tolerance time.Duration
	// Remember is how long a delivery id is remembered for replay rejection.
	Remember time.Duration
	Now      func() time.Time
}

// Defaults for webhook validation.
const (
	// DefaultWebhookTolerance is how stale a timestamped delivery may be.
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMemory is how long delivery ids are remembered. Comfortably
	// longer than any provider's retry schedule, so a genuine retry of a
	// delivery Kanea already processed is still recognised as one.
	DefaultWebhookMemory = time.Hour
	// maxRememberedDeliveries bounds the replay cache. The keys come from
	// whoever can reach the route, so without a cap this is a memory
	// exhaustion vector: the same bound the rate limiter and the metrics
	// store apply for the same reason.
	maxRememberedDeliveries = 4096
)

// Webhooks validates inbound git webhooks.
type Webhooks struct {
	secrets   Resolver
	tolerance time.Duration
	remember  time.Duration
	now       func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewWebhooks builds the verifier.
func NewWebhooks(cfg WebhooksConfig) *Webhooks {
	if cfg.Tolerance <= 0 {
		cfg.Tolerance = DefaultWebhookTolerance
	}
	if cfg.Remember <= 0 {
		cfg.Remember = DefaultWebhookMemory
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Webhooks{
		secrets: cfg.Secrets, tolerance: cfg.Tolerance,
		remember: cfg.Remember, now: cfg.Now, seen: map[string]time.Time{},
	}
}

// Verify authenticates a delivery and returns what it says.
//
// The secret is resolved per delivery for the same reason git credentials are
// resolved per sync: rotating it should take effect on the next push, not on
// the next restart.
//
// **On timestamp tolerance.** §10.1 asks for it, and it is applied to any
// sender that provides one. Neither GitHub nor GitLab does (their payloads
// carry no signed timestamp) so for those two the replay defence is the
// delivery-id cache below, and saying that plainly beats implying a protection
// that is not there.
func (w *Webhooks) Verify(
	ctx context.Context, project, secretRef string, header http.Header, body []byte,
) (Delivery, error) {
	if secretRef == "" {
		return Delivery{}, fmt.Errorf(
			"gitops: project %s has no webhook secret configured; set git.webhook_secret_ref", project)
	}
	if w.secrets == nil {
		return Delivery{}, errors.New("gitops: no secrets store is configured for webhook validation")
	}
	secret, err := w.secrets.Resolve(ctx, secretRef)
	if err != nil {
		return Delivery{}, fmt.Errorf("gitops: resolve %s: %w", secretRef, err)
	}

	delivery, err := w.authenticate(header, body, secret)
	if err != nil {
		return Delivery{}, err
	}
	delivery.Project = project

	if err := w.parse(&delivery, body); err != nil {
		return Delivery{}, err
	}
	// Accepted once. A replayed push would redeploy whatever that commit
	// contained, which, after a revert, is precisely the thing someone
	// deliberately took out of production.
	if err := w.remembering(delivery); err != nil {
		return Delivery{}, err
	}
	return delivery, nil
}

// authenticate checks the provider's signature over the raw body.
func (w *Webhooks) authenticate(header http.Header, body, secret []byte) (Delivery, error) {
	switch {
	case header.Get("X-Hub-Signature-256") != "":
		if err := verifyGitHubSignature(header.Get("X-Hub-Signature-256"), body, secret); err != nil {
			return Delivery{}, err
		}
		return Delivery{
			Provider: ProviderGitHub,
			ID:       header.Get("X-GitHub-Delivery"),
			Event:    header.Get("X-GitHub-Event"),
		}, nil

	case header.Get("X-Gitlab-Token") != "":
		// Constant-time even though this is a plain comparison: the token is
		// the whole credential, and a timing signal on it is a way to learn it
		// a byte at a time.
		if subtleEqual([]byte(header.Get("X-Gitlab-Token")), secret) {
			return Delivery{
				Provider: ProviderGitLab,
				ID:       header.Get("X-Gitlab-Event-UUID"),
				Event:    gitlabEvent(header.Get("X-Gitlab-Event")),
			}, nil
		}
		return Delivery{}, ErrBadSignature

	default:
		return Delivery{}, ErrUnsignedWebhook
	}
}

// verifyGitHubSignature checks an X-Hub-Signature-256 header.
func verifyGitHubSignature(header string, body, secret []byte) error {
	algorithm, value, found := strings.Cut(header, "=")
	if !found || !strings.EqualFold(algorithm, "sha256") {
		// sha1 is the only other thing GitHub ever sent, and it is not accepted:
		// a downgrade an attacker can request is not a compatibility feature.
		return fmt.Errorf("%w: unsupported signature algorithm %q", ErrBadSignature, algorithm)
	}
	expected, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%w: signature is not hex", ErrBadSignature)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}

// gitlabEvent maps GitLab's event names onto GitHub's vocabulary.
//
// One vocabulary downstream: the rest of the pipeline should not have to know
// whether "a push happened" was spelled "push" or "Push Hook".
func gitlabEvent(name string) string {
	switch name {
	case "Push Hook":
		return "push"
	case "System Hook":
		return "ping"
	default:
		return strings.ToLower(strings.TrimSuffix(name, " Hook"))
	}
}

// pushPayload is the slice of a push event Kanea reads.
//
// Both providers are covered by one struct because the fields overlap: GitHub
// sends `after`, GitLab sends `checkout_sha`, and both send `ref`. Decoding
// only what is used means a provider adding a field cannot break a sync.
type pushPayload struct {
	Ref         string `json:"ref"`
	After       string `json:"after"`
	CheckoutSHA string `json:"checkout_sha"`
	Deleted     bool   `json:"deleted"`
}

// parse fills in the git details a delivery carries.
func (w *Webhooks) parse(delivery *Delivery, body []byte) error {
	if delivery.Event != "push" {
		// A ping has no ref and is not supposed to.
		return nil
	}

	var payload pushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("gitops: webhook payload is not JSON: %w", err)
	}
	delivery.Ref = payload.Ref
	delivery.Commit = payload.After
	if delivery.Commit == "" {
		delivery.Commit = payload.CheckoutSHA
	}
	delivery.Deleted = payload.Deleted
	// GitHub marks a branch deletion with deleted=true; GitLab sends an
	// all-zero `after`. Both mean there is no tree to deploy.
	if isZeroSHA(delivery.Commit) {
		delivery.Deleted = true
	}
	return nil
}

// remembering rejects a delivery that has already been seen.
//
// A delivery with no id is accepted every time: GitLab's System Hooks and
// hand-rolled senders may omit one, and refusing them outright would break a
// legitimate configuration to defend against a replay the signature already
// makes expensive.
func (w *Webhooks) remembering(delivery Delivery) error {
	if delivery.ID == "" {
		return nil
	}
	key := string(delivery.Provider) + ":" + delivery.Project + ":" + delivery.ID

	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.now()
	w.evict(now)
	if seen, ok := w.seen[key]; ok && now.Sub(seen) < w.remember {
		return fmt.Errorf("%w: %s", ErrReplayedWebhook, delivery.ID)
	}
	w.seen[key] = now
	return nil
}

// evict drops expired entries and, if still over the cap, the oldest.
// The caller holds the lock.
func (w *Webhooks) evict(now time.Time) {
	for key, at := range w.seen {
		if now.Sub(at) >= w.remember {
			delete(w.seen, key)
		}
	}
	// A flood of distinct signed deliveries is possible only from someone who
	// holds the secret, but the cap is cheap and the alternative is unbounded.
	for len(w.seen) >= maxRememberedDeliveries {
		var oldestKey string
		var oldest time.Time
		for key, at := range w.seen {
			if oldestKey == "" || at.Before(oldest) {
				oldestKey, oldest = key, at
			}
		}
		delete(w.seen, oldestKey)
	}
}

// CheckTimestamp enforces the tolerance window on a sender that provides one.
//
// Exported and separate because no provider Kanea validates sends a signed
// timestamp: this is for a generic sender that does, and for the day GitHub
// adds one. Folding it into Verify would suggest the protection is active
// when for GitHub and GitLab it is not.
func (w *Webhooks) CheckTimestamp(at time.Time) error {
	if at.IsZero() {
		return nil
	}
	drift := w.now().Sub(at)
	if drift < 0 {
		drift = -drift
	}
	if drift > w.tolerance {
		return fmt.Errorf("%w: %s out", ErrWebhookTooOld, drift.Round(time.Second))
	}
	return nil
}

// isZeroSHA reports the all-zero sha a deletion carries.
func isZeroSHA(sha string) bool {
	if sha == "" {
		return false
	}
	return strings.Trim(sha, "0") == ""
}

// subtleEqual is a constant-time comparison.
func subtleEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}
