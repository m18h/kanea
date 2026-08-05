package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTP email (PRD §11).
//
// The one channel that is not HTTP, so the egress policy's dialer does not
// apply — but the reasoning does, and the same address check runs before the
// connection. A mail server on 169.254.169.254 is no more legitimate a
// destination than a webhook there.

// DefaultSMTPPort is the submission port. 587 rather than 25: submission
// expects authentication and STARTTLS, and 25 in 2026 is for server-to-server
// relay that a container should not be doing.
const DefaultSMTPPort = "587"

// SMTPChannel sends email.
type SMTPChannel struct {
	name    string
	addr    string
	host    string
	from    string
	to      []string
	auth    smtp.Auth
	timeout time.Duration
	egress  EgressPolicy
}

// SMTPConfig configures an email channel.
type SMTPConfig struct {
	Name string
	// Host is the mail server. Port defaults to DefaultSMTPPort.
	Host string
	Port string
	From string
	To   []string
	// Username and PasswordRef authenticate. Both empty means an unauthenticated
	// relay, which is legitimate on a host-local MTA and nowhere else.
	Username    string
	PasswordRef string
	Egress      EgressPolicy
	Timeout     time.Duration
}

// NewSMTP builds an email channel.
func NewSMTP(ctx context.Context, cfg SMTPConfig, secrets Resolver) (*SMTPChannel, error) {
	if cfg.Host == "" {
		return nil, errors.New("notify: an smtp channel needs a host")
	}
	if cfg.From == "" {
		return nil, errors.New("notify: an smtp channel needs a from address")
	}
	if len(cfg.To) == 0 {
		return nil, errors.New("notify: an smtp channel needs at least one recipient")
	}
	// Addresses are validated here rather than at send time. A malformed one is
	// a configuration mistake, and finding it on the first alert — which is by
	// definition when something else is already wrong — is the worst moment.
	if err := validateAddresses(append([]string{cfg.From}, cfg.To...)); err != nil {
		return nil, err
	}

	port := cfg.Port
	if port == "" {
		port = DefaultSMTPPort
	}
	ch := &SMTPChannel{
		name:    defaultName(cfg.Name, "smtp"),
		addr:    net.JoinHostPort(cfg.Host, port),
		host:    cfg.Host,
		from:    cfg.From,
		to:      cfg.To,
		timeout: cfg.Timeout,
		egress:  cfg.Egress,
	}
	if ch.timeout <= 0 {
		ch.timeout = DefaultEgressTimeout
	}

	if cfg.Username != "" {
		if cfg.PasswordRef == "" {
			return nil, errors.New("notify: an smtp username needs a password reference")
		}
		if secrets == nil {
			return nil, errors.New("notify: no secrets store is configured for the smtp password")
		}
		password, err := secrets.Resolve(ctx, cfg.PasswordRef)
		if err != nil {
			return nil, fmt.Errorf("notify: resolve %s: %w", cfg.PasswordRef, err)
		}
		// PlainAuth refuses to send credentials over an unencrypted connection
		// unless the server is localhost — a property of the stdlib worth
		// keeping rather than working around.
		ch.auth = smtp.PlainAuth("", cfg.Username, strings.TrimSpace(string(password)), cfg.Host)
	}
	return ch, nil
}

// Name identifies the channel.
func (c *SMTPChannel) Name() string { return c.name }

// Send delivers one message for the batch.
func (c *SMTPChannel) Send(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("notify: connect to %s: %w", c.name, err)
	}

	client, err := smtp.NewClient(conn, c.host)
	if err != nil {
		return errors.Join(fmt.Errorf("notify: smtp handshake with %s: %w", c.name, err), conn.Close())
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // Quit closes on the success path; this is the abort path

	// STARTTLS whenever the server offers it. Not optional-by-omission: a
	// notification carries service names, error text and a failure timeline,
	// which is reconnaissance for anyone on the path.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: c.host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("notify: starttls with %s: %w", c.name, err)
		}
	} else if c.auth != nil {
		// PlainAuth would refuse anyway; failing here says why.
		return permanent(fmt.Errorf("%s offers no STARTTLS but credentials are configured", c.name))
	}

	if c.auth != nil {
		if err := client.Auth(c.auth); err != nil {
			// Bad credentials will still be bad on the next attempt.
			return permanent(fmt.Errorf("authenticate to %s: %w", c.name, err))
		}
	}
	if err := client.Mail(c.from); err != nil {
		return fmt.Errorf("notify: MAIL FROM on %s: %w", c.name, err)
	}
	for _, rcpt := range c.to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("notify: RCPT TO on %s: %w", c.name, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("notify: DATA on %s: %w", c.name, err)
	}
	if _, err := w.Write(c.message(events)); err != nil {
		return errors.Join(fmt.Errorf("notify: write message to %s: %w", c.name, err), w.Close())
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: finish message to %s: %w", c.name, err)
	}
	return client.Quit()
}

// dial connects, checking the destination the same way the HTTP policy does.
func (c *SMTPChannel) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.timeout}
	if c.egress.AllowPrivate {
		return dialer.DialContext(ctx, "tcp", c.addr)
	}
	ips, err := (&net.Resolver{}).LookupIPAddr(ctx, c.host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", c.host, err)
	}
	for _, ip := range ips {
		if !AllowedIP(ip.IP) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrPrivateDestination, c.host, ip.IP)
		}
	}
	return dialer.DialContext(ctx, "tcp", c.addr)
}

// message builds the RFC 5322 message.
func (c *SMTPChannel) message(events []Event) []byte {
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(c.from)
	b.WriteString("\r\nTo: ")
	b.WriteString(strings.Join(c.to, ", "))
	b.WriteString("\r\nSubject: ")
	// Encoded, not merely stripped. A subject carries a service name and an
	// error string, both of which can hold a newline, and a newline in a header
	// is a second header — the classic SMTP header injection, which turns an
	// alert into a way to add recipients (§14 A03).
	b.WriteString(mime.QEncoding.Encode("utf-8", oneLine(title(events))))
	b.WriteString("\r\nDate: ")
	b.WriteString(events[len(events)-1].At.UTC().Format(time.RFC1123Z))
	b.WriteString("\r\nMIME-Version: 1.0")
	b.WriteString("\r\nContent-Type: text/plain; charset=utf-8")
	b.WriteString("\r\nAuto-Submitted: auto-generated")
	b.WriteString("\r\n\r\n")

	// The body needs dot-stuffing: a line consisting of a single "." ends the
	// DATA command, so an event message containing one would truncate the mail
	// and leave the rest to be interpreted as SMTP commands.
	for _, line := range strings.Split(Render(events), "\n") {
		if strings.HasPrefix(line, ".") {
			b.WriteString(".")
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// oneLine collapses anything that could break out of a header.
func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\x00", "").Replace(s)
}

// validateAddresses refuses anything that is not a plain addr-spec.
//
// Deliberately strict: display names and angle brackets are not needed for a
// notification, and every character not allowed here is one that cannot then
// appear in a header.
func validateAddresses(addrs []string) error {
	for _, addr := range addrs {
		if addr != oneLine(addr) {
			return fmt.Errorf("notify: address %q contains a line break", addr)
		}
		at := strings.LastIndexByte(addr, '@')
		if at <= 0 || at == len(addr)-1 || strings.ContainsAny(addr, "<>,; \t") {
			return fmt.Errorf("notify: %q is not a plain email address", addr)
		}
	}
	return nil
}

// MessageForTest exposes the assembled message to the package's tests.
//
// The alternative is a test that speaks SMTP to a fake server, which would
// exercise net/smtp rather than the two things here that are actually
// Kanea's: header injection and dot-stuffing.
func MessageForTest(c *SMTPChannel, events []Event) []byte { return c.message(events) }
