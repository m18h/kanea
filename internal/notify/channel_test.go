package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// resolver is a stub secrets store.
type resolver struct {
	values map[string][]byte
	err    error
}

func (r *resolver) Resolve(_ context.Context, ref string) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	v, ok := r.values[ref]
	if !ok {
		return nil, errors.New("no such secret: " + ref)
	}
	return v, nil
}

// capture records what a channel actually sent.
type capture struct {
	mu     sync.Mutex
	path   string
	header http.Header
	body   []byte
	status int
	hits   int
}

func (c *capture) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		c.mu.Lock()
		c.path, c.header, c.body = r.URL.Path, r.Header.Clone(), body
		c.hits++
		status := c.status
		c.mu.Unlock()

		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testEgress allows loopback, because httptest has no other address.
func testEgress() notify.EgressPolicy {
	return notify.EgressPolicy{AllowPrivate: true, AllowHTTP: true}
}

func batch() []notify.Event {
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	return []notify.Event{
		notify.NewEvent(notify.EventDeployFailed, "shop", "web", "image pull failed", at),
	}
}

func TestWebhookSignsWhatItSends(t *testing.T) {
	sink := &capture{}
	srv := sink.server(t)

	ch, err := notify.NewWebhook(context.Background(), notify.WebhookConfig{
		URL: srv.URL + "/hook", SecretRef: "secret:shop/notify",
		Egress: testEgress(),
	}, &resolver{values: map[string][]byte{"secret:shop/notify": []byte("s3cret")}})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	if err := ch.Send(context.Background(), batch()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	timestamp := sink.header.Get(notify.TimestampHeader)
	if timestamp == "" {
		t.Fatal("no timestamp header")
	}
	// The signature must be over the exact bytes the receiver got. Recomputing
	// from a re-encoded payload would pass here and fail against any real
	// receiver, which is the bug this pins.
	want := notify.Sign([]byte("s3cret"), timestamp, sink.body)
	if got := sink.header.Get(notify.SignatureHeader); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}

	// The timestamp is inside the MAC, so a captured delivery cannot be
	// replayed later with the clock moved on.
	shifted := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	if notify.Sign([]byte("s3cret"), shifted, sink.body) == want {
		t.Fatal("the signature does not cover the timestamp")
	}

	var got struct {
		Version int             `json:"version"`
		Count   int             `json:"count"`
		Events  []notify.Event  `json:"events"`
		Raw     json.RawMessage `json:"-"`
	}
	if err := json.Unmarshal(sink.body, &got); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if got.Version != 1 || got.Count != 1 || len(got.Events) != 1 {
		t.Fatalf("payload = %+v", got)
	}
	// Severity travels as a name, not as Kanea's iota order.
	if !strings.Contains(string(sink.body), `"severity":"error"`) {
		t.Fatalf("severity is not a name: %s", sink.body)
	}
}

func TestWebhookWithoutASecretIsUnsigned(t *testing.T) {
	// A receiver that authenticates by URL alone is a legitimate setup, and
	// requiring a secret would only make people invent one and share it.
	sink := &capture{}
	srv := sink.server(t)

	ch, err := notify.NewWebhook(context.Background(), notify.WebhookConfig{
		URL: srv.URL + "/hook", Egress: testEgress(),
	}, nil)
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	if err := ch.Send(context.Background(), batch()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sink.header.Get(notify.SignatureHeader) != "" {
		t.Fatal("an unsigned webhook sent a signature header")
	}
}

func TestChannelsSeparateRetryableFromPermanent(t *testing.T) {
	// The distinction is the whole value of a retry policy: a 500 is worth
	// trying again, a 404 means the webhook was deleted and retrying it only
	// delays every other notification behind it.
	for _, tc := range []struct {
		status    int
		permanent bool
	}{
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusTooManyRequests, false},
		{http.StatusRequestTimeout, false},
		{http.StatusNotFound, true},
		{http.StatusUnauthorized, true},
		{http.StatusBadRequest, true},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			sink := &capture{status: tc.status}
			srv := sink.server(t)

			ch, err := notify.NewWebhook(context.Background(), notify.WebhookConfig{
				URL: srv.URL, Egress: testEgress(),
			}, nil)
			if err != nil {
				t.Fatalf("NewWebhook: %v", err)
			}
			err = ch.Send(context.Background(), batch())
			if err == nil {
				t.Fatalf("status %d produced no error", tc.status)
			}
			if got := errors.Is(err, notify.ErrPermanent); got != tc.permanent {
				t.Fatalf("permanent = %v, want %v (err = %v)", got, tc.permanent, err)
			}
		})
	}
}

func TestTelegramNeverPutsItsTokenInAnError(t *testing.T) {
	// The bot token is in the URL, because that is the API Telegram exposes.
	// A transport error carries the URL, so returning it verbatim would put a
	// credential into the daemon log (R3, §14 A09).
	secrets := &resolver{values: map[string][]byte{
		"secret:shop/bot": []byte("123456:AAHsuperSecretToken"),
	}}
	ch, err := notify.NewTelegram(context.Background(), notify.TelegramConfig{
		TokenRef: "secret:shop/bot", ChatID: "-100123",
		// A port nothing listens on, so Do fails in the transport.
		APIBase: "http://127.0.0.1:1", Egress: testEgress(),
	}, secrets)
	if err != nil {
		t.Fatalf("NewTelegram: %v", err)
	}

	err = ch.Send(context.Background(), batch())
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "AAHsuperSecretToken") {
		t.Fatalf("the bot token leaked into an error: %v", err)
	}
}

func TestTelegramPostsToTheChat(t *testing.T) {
	sink := &capture{}
	srv := sink.server(t)

	ch, err := notify.NewTelegram(context.Background(), notify.TelegramConfig{
		TokenRef: "secret:shop/bot", ChatID: "-100123",
		APIBase: srv.URL, Egress: testEgress(),
	}, &resolver{values: map[string][]byte{"secret:shop/bot": []byte("tok")}})
	if err != nil {
		t.Fatalf("NewTelegram: %v", err)
	}
	if err := ch.Send(context.Background(), batch()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sink.path != "/bottok/sendMessage" {
		t.Fatalf("path = %q", sink.path)
	}
	if !strings.Contains(string(sink.body), "chat_id=-100123") {
		t.Fatalf("body = %q", sink.body)
	}
}

func TestSlackURLComesFromTheSecretsStore(t *testing.T) {
	// A Slack incoming-webhook URL is a credential in path form: anyone holding
	// it can post as the app. It is a `secret:` reference for the same reason a
	// password is.
	sink := &capture{}
	srv := sink.server(t)

	ch, err := notify.NewSlack(context.Background(), notify.SlackConfig{
		URLRef: "secret:shop/slack", Egress: testEgress(),
	}, &resolver{values: map[string][]byte{"secret:shop/slack": []byte(srv.URL + "/services/T/B/x")}})
	if err != nil {
		t.Fatalf("NewSlack: %v", err)
	}
	if err := ch.Send(context.Background(), batch()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var got struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(sink.body, &got); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !strings.Contains(got.Text, "deploy.failed") {
		t.Fatalf("text = %q", got.Text)
	}

	// And an inlined URL is refused: there is no field to put one in.
	if _, err := notify.NewSlack(context.Background(), notify.SlackConfig{
		Egress: testEgress(),
	}, nil); err == nil {
		t.Fatal("a slack channel with no url reference was accepted")
	}
}

func TestNtfyMapsSeverityToPriority(t *testing.T) {
	// Most of the reason to use ntfy over a webhook: a phone can be told to
	// make a noise for an error and stay quiet for a scale event.
	for _, tc := range []struct {
		name     string
		priority string
	}{
		{notify.EventDeployFailed, "4"},
		{notify.EventServiceUnhealthy, "3"},
		{notify.EventScaleUp, "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &capture{}
			srv := sink.server(t)

			ch, err := notify.NewNtfy(context.Background(), notify.NtfyConfig{
				URL: srv.URL + "/kanea", Egress: testEgress(),
			}, nil)
			if err != nil {
				t.Fatalf("NewNtfy: %v", err)
			}
			at := time.Now()
			ev := notify.NewEvent(tc.name, "shop", "web", "x", at)
			if err := ch.Send(context.Background(), []notify.Event{ev}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if got := sink.header.Get("Priority"); got != tc.priority {
				t.Fatalf("priority = %q, want %q", got, tc.priority)
			}
		})
	}
}

func TestRenderDigestsABatch(t *testing.T) {
	// "42 allocs restarted in 5m" — one message, not 42. The header carries the
	// count and the span; the lines say which.
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	var events []notify.Event
	for i := range 3 {
		events = append(events, notify.NewEvent(notify.EventServiceCrashed, "shop", "web",
			"alloc exited", at.Add(time.Duration(i)*time.Minute)))
	}

	out := notify.Render(events)
	if !strings.Contains(out, "3 events") {
		t.Fatalf("no count in the digest header: %q", out)
	}
	if !strings.Contains(out, "2m") {
		t.Fatalf("no span in the digest header: %q", out)
	}
	if got := strings.Count(out, "\n• "); got != 3 {
		t.Fatalf("%d lines, want 3: %q", got, out)
	}

	// One event is one line, with no digest header on top of it.
	single := notify.Render(events[:1])
	if strings.Contains(single, "•") || strings.Contains(single, "events in") {
		t.Fatalf("a single event was rendered as a digest: %q", single)
	}
}

func TestChannelConstructorsEnforceEgress(t *testing.T) {
	// The policy has to be enforced where the channel is built, not only where
	// it sends: a target that can never be reached should fail at configuration
	// time, in front of the person who wrote it.
	var strict notify.EgressPolicy

	if _, err := notify.NewWebhook(context.Background(), notify.WebhookConfig{
		URL: "http://hooks.example.com/x", Egress: strict,
	}, nil); !errors.Is(err, notify.ErrInsecureScheme) {
		t.Fatalf("webhook: err = %v, want ErrInsecureScheme", err)
	}
	if _, err := notify.NewNtfy(context.Background(), notify.NtfyConfig{
		URL: "http://ntfy.sh/x", Egress: strict,
	}, nil); !errors.Is(err, notify.ErrInsecureScheme) {
		t.Fatalf("ntfy: err = %v, want ErrInsecureScheme", err)
	}
	if _, err := notify.NewSlack(context.Background(), notify.SlackConfig{
		URLRef: "secret:shop/slack", Egress: strict,
	}, &resolver{values: map[string][]byte{
		"secret:shop/slack": []byte("http://hooks.slack.com/x"),
	}}); !errors.Is(err, notify.ErrInsecureScheme) {
		t.Fatalf("slack: err = %v, want ErrInsecureScheme", err)
	}
}

func TestSMTPRefusesHeaderInjection(t *testing.T) {
	// A subject carries a service name and an error string, both of which can
	// hold a newline — and a newline in a header is a second header. That is
	// how an alert becomes a way to add recipients (§14 A03).
	ch, err := notify.NewSMTP(context.Background(), notify.SMTPConfig{
		Host: "mail.example.com", From: "kanea@example.com",
		To: []string{"ops@example.com"}, Egress: testEgress(),
	}, nil)
	if err != nil {
		t.Fatalf("NewSMTP: %v", err)
	}

	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	evil := notify.NewEvent(notify.EventDeployFailed, "shop",
		"web\r\nBcc: attacker@example.com", "boom", at)

	msg := string(notify.MessageForTest(ch, []notify.Event{evil}))
	headers, _, _ := strings.Cut(msg, "\r\n\r\n")

	// The property is that no new header *line* exists. The injected text
	// surviving inside the Subject value is harmless — it is one header with an
	// odd value, which is what folding a CRLF into a space is supposed to
	// produce. What must never happen is a line that starts with a field name.
	for _, line := range strings.Split(headers, "\r\n") {
		name, _, found := strings.Cut(line, ":")
		if !found {
			t.Fatalf("a header line has no field name: %q", line)
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "from", "to", "subject", "date", "mime-version",
			"content-type", "auto-submitted":
		default:
			t.Fatalf("a header was injected through the subject: %q", line)
		}
	}
	// Exactly the headers this builds, and no more.
	if got := len(strings.Split(headers, "\r\n")); got != 7 {
		t.Fatalf("%d header lines, want 7:\n%s", got, headers)
	}
}

func TestSMTPDotStuffsTheBody(t *testing.T) {
	// A line that is a single "." ends the DATA command. An event message
	// containing one would truncate the mail and leave the rest to be read as
	// SMTP commands.
	ch, err := notify.NewSMTP(context.Background(), notify.SMTPConfig{
		Host: "mail.example.com", From: "kanea@example.com",
		To: []string{"ops@example.com"}, Egress: testEgress(),
	}, nil)
	if err != nil {
		t.Fatalf("NewSMTP: %v", err)
	}

	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	ev := notify.NewEvent(notify.EventDeployFailed, "shop", "web", "before\n.\nafter", at)

	msg := string(notify.MessageForTest(ch, []notify.Event{ev}))
	_, body, _ := strings.Cut(msg, "\r\n\r\n")
	if strings.Contains(body, "\r\n.\r\n") {
		t.Fatalf("a bare dot line survived into the body:\n%q", body)
	}
	if !strings.Contains(body, "\r\n..\r\n") {
		t.Fatalf("the dot was not stuffed:\n%q", body)
	}
}

func TestSMTPRejectsMalformedAddresses(t *testing.T) {
	// Found at configuration time, not on the first alert — which is by
	// definition the moment something else is already wrong.
	for _, addr := range []string{
		"ops@example.com\r\nBcc: attacker@example.com",
		"Ops <ops@example.com>",
		"not-an-address",
		"ops@",
		"@example.com",
	} {
		if _, err := notify.NewSMTP(context.Background(), notify.SMTPConfig{
			Host: "mail.example.com", From: "kanea@example.com",
			To: []string{addr}, Egress: testEgress(),
		}, nil); err == nil {
			t.Errorf("address %q was accepted", addr)
		}
	}
}
