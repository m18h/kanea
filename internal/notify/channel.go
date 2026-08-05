package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Notification channels (PRD §11).
//
// Every channel is the same shape: take a batch of events, produce one message,
// deliver it, say whether it worked. The batch rather than the single event is
// what makes coalescing possible without every channel knowing about it — a
// digest is just a batch with more than one event in it.

// Resolver reads a secret by reference. Channel credentials are `secret:`
// references like every other credential (R3); a bot token in a job file is a
// bot token in version control.
type Resolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// Channel delivers notifications somewhere.
type Channel interface {
	// Name identifies the channel in logs and in the drop counters. It never
	// contains a credential.
	Name() string
	// Send delivers a batch. It must return an error the caller can retry on,
	// or nil. It must not retry internally: the dispatcher owns backoff, and a
	// channel that also retried would multiply the two.
	Send(ctx context.Context, batch []Event) error
}

// ErrPermanent wraps an error that retrying cannot fix.
//
// The distinction is the whole value of a retry policy. A 500 from Slack is
// worth trying again; a 404 means the webhook was deleted, and retrying it for
// an hour only delays every other notification behind it.
var ErrPermanent = errors.New("notify: permanent failure")

// permanent marks an error as not worth retrying.
func permanent(err error) error { return fmt.Errorf("%w: %w", ErrPermanent, err) }

// classify turns an HTTP status into a delivery outcome.
//
// 408 and 429 are the two 4xx codes that are worth retrying: one is a timeout
// and the other is an explicit "later". Everything else in the 4xx range is the
// receiver saying the request itself is wrong, which will still be wrong in
// thirty seconds.
func classify(resp *http.Response, target string) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		return fmt.Errorf("notify: %s answered %s", target, resp.Status)
	default:
		return permanent(fmt.Errorf("%s answered %s", target, resp.Status))
	}
}

// finish drains and closes a response body, joining any close error onto the
// delivery result.
//
// The drain is bounded: the body belongs to a server this node was told to talk
// to, and an unbounded read is a memory exhaustion vector wearing a 200. It is
// read at all so the connection can go back to the pool rather than being torn
// down after every notification.
func finish(resp *http.Response, err error) error {
	if _, cerr := io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10)); cerr != nil && err == nil {
		err = cerr
	}
	return errors.Join(err, resp.Body.Close())
}

// ---- the generic signed webhook ----------------------------------------

// SignatureHeader carries the HMAC over the request body (§11).
const SignatureHeader = "X-Kanea-Signature"

// TimestampHeader carries the send time, which is inside the signature.
//
// Signing the timestamp is what makes a captured delivery unusable later: the
// receiver checks that it is recent, and it cannot be changed without breaking
// the signature — the same construction Kanea requires of *its* callers on the
// git webhook route.
const TimestampHeader = "X-Kanea-Timestamp"

// WebhookChannel posts a JSON payload signed with HMAC-SHA256.
type WebhookChannel struct {
	name   string
	url    string
	secret []byte
	client *http.Client
	now    func() time.Time
}

// WebhookConfig configures a signed webhook channel.
type WebhookConfig struct {
	Name string
	URL  string
	// SecretRef names the signing key. Optional: an unsigned webhook is a
	// legitimate configuration for a receiver that authenticates by URL alone,
	// and forcing a secret would only make people invent one and share it.
	SecretRef string
	Egress    EgressPolicy
	Timeout   time.Duration
	Now       func() time.Time
}

// NewWebhook builds a signed webhook channel.
func NewWebhook(ctx context.Context, cfg WebhookConfig, secrets Resolver) (*WebhookChannel, error) {
	target, err := cfg.Egress.CheckURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	ch := &WebhookChannel{
		name:   defaultName(cfg.Name, "webhook"),
		url:    target.String(),
		client: cfg.Egress.HTTPClient(cfg.Timeout),
		now:    orNow(cfg.Now),
	}
	if cfg.SecretRef != "" {
		if secrets == nil {
			return nil, errors.New("notify: a webhook secret was named but no secrets store is configured")
		}
		secret, err := secrets.Resolve(ctx, cfg.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("notify: resolve %s: %w", cfg.SecretRef, err)
		}
		ch.secret = secret
	}
	return ch, nil
}

// Name identifies the channel.
func (c *WebhookChannel) Name() string { return c.name }

// payload is the JSON body a webhook receives.
type payload struct {
	// Version lets a receiver tell a future shape from this one without
	// guessing from which fields are present.
	Version int     `json:"version"`
	SentAt  string  `json:"sent_at"`
	Count   int     `json:"count"`
	Events  []Event `json:"events"`
}

// Send posts the batch.
func (c *WebhookChannel) Send(ctx context.Context, batch []Event) error {
	body, err := json.Marshal(payload{
		Version: 1,
		SentAt:  c.now().UTC().Format(time.RFC3339),
		Count:   len(batch),
		Events:  batch,
	})
	if err != nil {
		return permanent(fmt.Errorf("encode payload: %w", err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kanea")

	if len(c.secret) > 0 {
		timestamp := strconv.FormatInt(c.now().Unix(), 10)
		req.Header.Set(TimestampHeader, timestamp)
		req.Header.Set(SignatureHeader, Sign(c.secret, timestamp, body))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post to %s: %w", c.name, err)
	}
	return finish(resp, classify(resp, c.name))
}

// Sign produces the X-Kanea-Signature value.
//
// The timestamp is inside the MAC, joined with a byte that cannot appear in a
// decimal timestamp. Concatenating them without a separator would let a
// different (timestamp, body) split produce the same input — the classic length
// extension of a naive concatenation.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// ---- Telegram -----------------------------------------------------------

// TelegramChannel sends via the bot API.
type TelegramChannel struct {
	name   string
	base   string
	token  string
	chatID string
	client *http.Client
}

// TelegramConfig configures a Telegram channel.
type TelegramConfig struct {
	Name string
	// TokenRef names the bot token. Required: there is no anonymous bot API.
	TokenRef string
	ChatID   string
	Egress   EgressPolicy
	Timeout  time.Duration
	// APIBase overrides https://api.telegram.org, for tests.
	APIBase string
}

// NewTelegram builds a Telegram channel.
func NewTelegram(ctx context.Context, cfg TelegramConfig, secrets Resolver) (*TelegramChannel, error) {
	if cfg.ChatID == "" {
		return nil, errors.New("notify: a telegram channel needs a chat_id")
	}
	if cfg.TokenRef == "" {
		return nil, errors.New("notify: a telegram channel needs a bot token reference")
	}
	if secrets == nil {
		return nil, errors.New("notify: no secrets store is configured for the telegram token")
	}
	token, err := secrets.Resolve(ctx, cfg.TokenRef)
	if err != nil {
		return nil, fmt.Errorf("notify: resolve %s: %w", cfg.TokenRef, err)
	}

	base := cfg.APIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	if _, err := cfg.Egress.CheckURL(base); err != nil {
		return nil, err
	}
	return &TelegramChannel{
		name:   defaultName(cfg.Name, "telegram"),
		base:   strings.TrimSuffix(base, "/"),
		token:  strings.TrimSpace(string(token)),
		chatID: cfg.ChatID,
		client: cfg.Egress.HTTPClient(cfg.Timeout),
	}, nil
}

// Name identifies the channel.
func (c *TelegramChannel) Name() string { return c.name }

// Send posts one message for the batch.
//
// Form-encoded rather than JSON, and the token goes in the path because that is
// the API Telegram exposes — which is also why the URL must never be logged:
// it *is* the credential.
func (c *TelegramChannel) Send(ctx context.Context, batch []Event) error {
	form := url.Values{}
	form.Set("chat_id", c.chatID)
	form.Set("text", Render(batch))
	form.Set("disable_web_page_preview", "true")

	endpoint := c.base + "/bot" + c.token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return permanent(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		// The error from the transport can carry the URL, and the URL carries
		// the bot token. Only the channel name goes out.
		return fmt.Errorf("notify: post to %s failed", c.name)
	}
	return finish(resp, classify(resp, c.name))
}

// ---- Slack / Discord ----------------------------------------------------

// SlackChannel posts an incoming-webhook payload.
//
// Discord accepts the same `{"text": …}` shape on its `/slack` endpoint, which
// is why §11 lists them together and why this is one channel rather than two.
type SlackChannel struct {
	name   string
	url    string
	client *http.Client
}

// SlackConfig configures a Slack or Discord channel.
type SlackConfig struct {
	Name string
	// URLRef names the incoming-webhook URL. It is a `secret:` reference
	// because a Slack webhook URL is a credential in path form — anyone
	// holding it can post as the app.
	URLRef  string
	Egress  EgressPolicy
	Timeout time.Duration
}

// NewSlack builds a Slack/Discord channel.
func NewSlack(ctx context.Context, cfg SlackConfig, secrets Resolver) (*SlackChannel, error) {
	if cfg.URLRef == "" {
		return nil, errors.New("notify: a slack channel needs a webhook url reference")
	}
	if secrets == nil {
		return nil, errors.New("notify: no secrets store is configured for the slack webhook")
	}
	raw, err := secrets.Resolve(ctx, cfg.URLRef)
	if err != nil {
		return nil, fmt.Errorf("notify: resolve %s: %w", cfg.URLRef, err)
	}
	target, err := cfg.Egress.CheckURL(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	return &SlackChannel{
		name:   defaultName(cfg.Name, "slack"),
		url:    target.String(),
		client: cfg.Egress.HTTPClient(cfg.Timeout),
	}, nil
}

// Name identifies the channel.
func (c *SlackChannel) Name() string { return c.name }

// Send posts the batch as one message.
func (c *SlackChannel) Send(ctx context.Context, batch []Event) error {
	body, err := json.Marshal(map[string]string{"text": Render(batch)})
	if err != nil {
		return permanent(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return permanent(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		// Same reasoning as Telegram: the URL is the credential.
		return fmt.Errorf("notify: post to %s failed", c.name)
	}
	return finish(resp, classify(resp, c.name))
}

// ---- ntfy.sh ------------------------------------------------------------

// NtfyChannel publishes to an ntfy topic.
type NtfyChannel struct {
	name   string
	url    string
	token  string
	client *http.Client
}

// NtfyConfig configures an ntfy channel.
type NtfyConfig struct {
	Name string
	// URL is the full topic URL, e.g. https://ntfy.sh/my-topic.
	URL string
	// TokenRef optionally names a bearer token for a protected topic.
	TokenRef string
	Egress   EgressPolicy
	Timeout  time.Duration
}

// NewNtfy builds an ntfy channel.
func NewNtfy(ctx context.Context, cfg NtfyConfig, secrets Resolver) (*NtfyChannel, error) {
	target, err := cfg.Egress.CheckURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	ch := &NtfyChannel{
		name:   defaultName(cfg.Name, "ntfy"),
		url:    target.String(),
		client: cfg.Egress.HTTPClient(cfg.Timeout),
	}
	if cfg.TokenRef != "" {
		if secrets == nil {
			return nil, errors.New("notify: an ntfy token was named but no secrets store is configured")
		}
		token, err := secrets.Resolve(ctx, cfg.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("notify: resolve %s: %w", cfg.TokenRef, err)
		}
		ch.token = strings.TrimSpace(string(token))
	}
	return ch, nil
}

// Name identifies the channel.
func (c *NtfyChannel) Name() string { return c.name }

// Send publishes the batch.
//
// The severity becomes ntfy's priority, so a phone can be configured to make a
// noise for an error and stay quiet for a scale event — which is most of the
// reason to use ntfy rather than a webhook.
func (c *NtfyChannel) Send(ctx context.Context, batch []Event) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url,
		strings.NewReader(Render(batch)))
	if err != nil {
		return permanent(err)
	}
	req.Header.Set("Title", title(batch))
	req.Header.Set("Priority", ntfyPriority(worstOf(batch)))
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post to %s: %w", c.name, err)
	}
	return finish(resp, classify(resp, c.name))
}

// ntfyPriority maps a severity onto ntfy's 1–5 scale.
func ntfyPriority(s Severity) string {
	switch s {
	case SeverityError:
		return "4" // high — makes a phone notify
	case SeverityWarning:
		return "3" // default
	default:
		return "2" // low — no sound
	}
}

// ---- shared helpers -----------------------------------------------------

// Render turns a batch into the message body every text channel sends.
//
// One event renders as one line. A batch renders as a header and a line each,
// which is what makes a digest readable: "42 allocs restarted in 5m" is the
// header, and the lines say which.
func Render(batch []Event) string {
	if len(batch) == 0 {
		return ""
	}
	if len(batch) == 1 {
		return batch[0].String()
	}

	var b strings.Builder
	b.WriteString(title(batch))
	for _, e := range batch {
		b.WriteString("\n• ")
		b.WriteString(e.String())
	}
	return b.String()
}

// title is the one-line summary a batch leads with.
func title(batch []Event) string {
	switch len(batch) {
	case 0:
		return "kanea"
	case 1:
		e := batch[0]
		if subject := e.Subject(); subject != "" {
			return fmt.Sprintf("kanea: %s %s", e.Name, subject)
		}
		return "kanea: " + e.Name
	default:
		return fmt.Sprintf("kanea: %d events in %s",
			len(batch), span(batch).Round(time.Second))
	}
}

// span is how long a batch covers.
func span(batch []Event) time.Duration {
	if len(batch) < 2 {
		return 0
	}
	first, last := batch[0].At, batch[0].At
	for _, e := range batch[1:] {
		if e.At.Before(first) {
			first = e.At
		}
		if e.At.After(last) {
			last = e.At
		}
	}
	return last.Sub(first)
}

// worstOf is the highest severity in a batch — what a digest is filed under.
func worstOf(batch []Event) Severity {
	worst := SeverityInfo
	for _, e := range batch {
		if e.Severity > worst {
			worst = e.Severity
		}
	}
	return worst
}

func defaultName(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}

func orNow(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return time.Now
}
