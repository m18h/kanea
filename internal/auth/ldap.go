package auth

// LDAP authentication (PRD v1.47, §13.2; docs/THREAT_MODEL.md §3.20).
//
// A simple bind rests on a different trust argument from the other two
// mechanisms: with a local account Kanea verifies the password itself, with
// OIDC a provider hands over a signed assertion — here Kanea learns only that
// the directory accepted the password on a channel Kanea configured. So the
// channel is mandatory TLS with no insecure flag, the RFC 4513
// unauthenticated-bind trap is closed before the network is touched, and both
// insertion points into a search filter are escaped.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// MethodLDAP is a caller whose password a directory verified.
const MethodLDAP Method = "ldap"

// Errors the login path distinguishes.
var (
	// ErrLDAPNoRole means the directory vouched for them and Kanea has no
	// role for them — the difference between "log in again" and "ask an
	// administrator", so it maps to 403 where every other refusal is 401
	// (the OIDC no-role rule).
	ErrLDAPNoRole = errors.New("auth: no role maps to this account's directory groups")
	// ErrLDAPUnavailable means the directory could not be reached or the
	// service bind failed: an operational failure, never an authentication
	// verdict, so it must not count against anyone's lockout.
	ErrLDAPUnavailable = errors.New("auth: the directory is unavailable")
)

// DefaultLDAPTimeout bounds each directory operation.
const DefaultLDAPTimeout = 10 * time.Second

// LDAPConfig configures directory authentication.
type LDAPConfig struct {
	// URL is ldaps://host[:port], or ldap://host[:port] with StartTLS forced.
	// Cleartext is refused at construction; there is no insecure option.
	URL string
	// BindDN and BindPassword are the service account the user search runs
	// as; both empty means an anonymous search. The password arrives resolved
	// — the `secret:` reference is the caller's to handle (R3).
	BindDN       string
	BindPassword string
	// UserBaseDN is where users are searched.
	UserBaseDN string
	// UserFilter locates one user; exactly one %s receives the escaped
	// typed name. E.g. (uid=%s), or (sAMAccountName=%s) for AD.
	UserFilter string
	// GroupBaseDN and GroupFilter enable a group search; both or neither.
	// Empty means groups come from the user entry's memberOf attribute.
	// The filter's one %s receives the escaped user DN, e.g. (member=%s).
	GroupBaseDN string
	GroupFilter string
	// AdminGroups and ViewerGroups are the group DNs that map to a role,
	// deny-by-default and admin checked first. Compared case-insensitively —
	// DNs are, and directories are inconsistent about the case they return.
	AdminGroups  []string
	ViewerGroups []string
	// CAFile trusts a private CA for the TLS channel.
	CAFile string
	// Timeout bounds each directory operation. Zero means the default.
	Timeout time.Duration
	Logger  *slog.Logger
}

// LDAP verifies passwords against a directory.
type LDAP struct {
	cfg LDAPConfig
	tls *tls.Config
	log *slog.Logger
}

// NewLDAP validates the configuration — no I/O, deliberately. Unlike OIDC
// discovery (which is config validation over the network), a directory's
// reachability is weather: it is checked once at startup as a warning
// (CheckConnection), never as a refusal to run.
func NewLDAP(cfg LDAPConfig) (*LDAP, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("auth: bad LDAP URL %q: %w", cfg.URL, err)
	}
	switch parsed.Scheme {
	case "ldaps", "ldap":
		// ldap:// gets StartTLS unconditionally in Verify. The wire carries
		// the user's actual password, which is a stronger reason than any
		// TLS default elsewhere — hence no insecure flag at all.
	default:
		return nil, fmt.Errorf(
			"auth: LDAP URL must be ldaps://host or ldap://host (StartTLS is forced); got %q", cfg.URL)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("auth: LDAP URL %q has no host", cfg.URL)
	}
	if cfg.UserBaseDN == "" {
		return nil, errors.New("auth: LDAP needs a user base DN")
	}
	if strings.Count(cfg.UserFilter, "%s") != 1 {
		return nil, fmt.Errorf(
			"auth: the LDAP user filter needs exactly one %%s for the username; got %q", cfg.UserFilter)
	}
	if (cfg.GroupBaseDN == "") != (cfg.GroupFilter == "") {
		// Refused by name (the v1.41 all-or-none style): a half-configured
		// group search would silently fall back to memberOf and look like it
		// worked.
		return nil, errors.New(
			"auth: --ldap-group-base-dn and --ldap-group-filter go together (both, or neither for memberOf)")
	}
	if cfg.GroupFilter != "" && strings.Count(cfg.GroupFilter, "%s") != 1 {
		return nil, fmt.Errorf(
			"auth: the LDAP group filter needs exactly one %%s for the user DN; got %q", cfg.GroupFilter)
	}
	if (cfg.BindDN == "") != (cfg.BindPassword == "") {
		return nil, errors.New("auth: an LDAP bind DN and its password go together")
	}
	if len(cfg.AdminGroups)+len(cfg.ViewerGroups) == 0 {
		return nil, errors.New(
			"auth: LDAP needs at least one admin or viewer group; without one, every login is refused")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultLDAPTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	tlsConfig := &tls.Config{ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) // #nosec G304 — an operator flag
		if err != nil {
			return nil, fmt.Errorf("auth: read --ldap-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("auth: %s holds no usable CA certificate", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	return &LDAP{cfg: cfg, tls: tlsConfig, log: cfg.Logger}, nil
}

// Server names the directory, for audit Detail and status surfaces — the
// Issuer() twin.
func (l *LDAP) Server() string { return l.cfg.URL }

// Verify checks a name and password against the directory.
//
// Per-login dial, no pool: one dial and two binds at dashboard-login frequency
// is nothing, and a pool is liveness, rebind and credential-refresh machinery
// for a property nobody would observe.
func (l *LDAP) Verify(ctx context.Context, name, password string) (subject string, role Role, err error) {
	// RFC 4513 §5.1.2: a bind with a DN and an empty password is an
	// "unauthenticated bind" many servers treat as anonymous success. Refused
	// before the network is touched — a directory's permissiveness must never
	// become a login. Whitespace-only gets the same door.
	if strings.TrimSpace(password) == "" {
		return "", "", fmt.Errorf("%w: empty password", ErrUnauthenticated)
	}
	if name == "" || len(name) > maxLDAPNameBytes {
		return "", "", fmt.Errorf("%w: bad username", ErrUnauthenticated)
	}

	conn, err := l.dial(ctx)
	if err != nil {
		return "", "", err
	}
	defer conn.Close() //nolint:errcheck // read-side close on the way out

	// The service bind. Its failure is operational — this is the operator's
	// credential, not the user's — and is logged loudly as such.
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			l.log.Error("the LDAP service bind failed",
				"server", l.cfg.URL, "bind_dn", l.cfg.BindDN, "error", err)
			// The %v is deliberate here and below: the sentinel is the only
			// error callers may match — a go-ldap cause in the chain would be
			// API surface nobody promised.
			return "", "", fmt.Errorf("%w: service bind: %v", ErrLDAPUnavailable, err) //nolint:errorlint // see above
		}
	}

	entry, err := l.findUser(conn, name)
	if err != nil {
		return "", "", err
	}

	// The user bind is the verification. Invalid credentials is the caller's
	// failure; anything else is the directory's.
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", "", fmt.Errorf("%w: the directory refused the password", ErrUnauthenticated)
		}
		return "", "", fmt.Errorf("%w: user bind: %v", ErrLDAPUnavailable, err) //nolint:errorlint // the sentinel is the API; the cause is context
	}

	groups, err := l.groupsFor(conn, entry)
	if err != nil {
		return "", "", err
	}
	mapped, ok := l.roleFor(groups)
	if !ok {
		l.log.Warn("directory login refused: no group maps to a role",
			"user", name, "dn", entry.DN, "groups", len(groups))
		return "", "", ErrLDAPNoRole
	}

	// The subject is the typed name, not the DN: it keys the limiter, the
	// audit target and the session, and it is the identity the operator
	// recognises. The DN lives in the log line.
	l.log.Info("directory login verified", "user", name, "dn", entry.DN, "role", mapped)
	return name, mapped, nil
}

// maxLDAPNameBytes bounds the typed name; nothing legitimate is longer.
const maxLDAPNameBytes = 256

// dial opens the connection with TLS established — ldaps natively, StartTLS
// forced on ldap. A StartTLS failure is a refusal, never a cleartext continue.
func (l *LDAP) dial(ctx context.Context) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: l.cfg.Timeout}
	conn, err := ldap.DialURL(l.cfg.URL,
		ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(l.tls))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLDAPUnavailable, err) //nolint:errorlint // the sentinel is the API; the cause is context
	}
	conn.SetTimeout(l.cfg.Timeout)

	if strings.HasPrefix(l.cfg.URL, "ldap://") {
		if err := conn.StartTLS(l.tls); err != nil {
			// The connection is being refused anyway; a close failure on top
			// changes nothing for the caller and is only worth a debug line.
			if closeErr := conn.Close(); closeErr != nil {
				l.log.Debug("closing a refused LDAP connection", "error", closeErr)
			}
			return nil, fmt.Errorf("%w: StartTLS: %v", ErrLDAPUnavailable, err) //nolint:errorlint // the sentinel is the API; the cause is context
		}
	}
	// The context's cancellation is respected between operations by the
	// per-operation timeout; go-ldap has no per-call context plumbing.
	_ = ctx
	return conn, nil
}

// findUser locates exactly one entry for the typed name.
func (l *LDAP) findUser(conn *ldap.Conn, name string) (*ldap.Entry, error) {
	filter := fmt.Sprintf(l.cfg.UserFilter, ldap.EscapeFilter(name))
	result, err := conn.Search(ldap.NewSearchRequest(
		l.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, // SizeLimit 2: enough to detect ambiguity, no more
		int(l.cfg.Timeout.Seconds()), false, filter,
		[]string{"dn", "memberOf"}, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("%w: user search: %v", ErrLDAPUnavailable, err) //nolint:errorlint // the sentinel is the API; the cause is context
	}
	switch len(result.Entries) {
	case 0:
		// The same generic refusal a wrong password gets: whether a name
		// exists in the directory is not this API's to reveal.
		return nil, fmt.Errorf("%w: no directory entry", ErrUnauthenticated)
	case 1:
		return result.Entries[0], nil
	default:
		// Ambiguity is refused, never resolved by order: binding the first of
		// two matches is an authentication decision made by sort order.
		l.log.Warn("directory login refused: the user filter matched more than one entry",
			"filter", l.cfg.UserFilter, "user", name)
		return nil, fmt.Errorf("%w: ambiguous directory entry", ErrUnauthenticated)
	}
}

// groupsFor extracts the user's groups — memberOf from the entry, or a group
// search re-bound as the service account (the connection is bound as the user
// by now, and group visibility must not depend on user self-visibility).
func (l *LDAP) groupsFor(conn *ldap.Conn, entry *ldap.Entry) ([]string, error) {
	if l.cfg.GroupBaseDN == "" {
		return entry.GetAttributeValues("memberOf"), nil
	}

	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("%w: service re-bind for the group search: %v", ErrLDAPUnavailable, err) //nolint:errorlint // the sentinel is the API; the cause is context
		}
	}
	filter := fmt.Sprintf(l.cfg.GroupFilter, ldap.EscapeFilter(entry.DN))
	result, err := conn.Search(ldap.NewSearchRequest(
		l.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		maxLDAPGroups, int(l.cfg.Timeout.Seconds()), false, filter,
		[]string{"dn"}, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("%w: group search: %v", ErrLDAPUnavailable, err) //nolint:errorlint // the sentinel is the API; the cause is context
	}
	groups := make([]string, 0, len(result.Entries))
	for _, g := range result.Entries {
		groups = append(groups, g.DN)
	}
	return groups, nil
}

// maxLDAPGroups bounds a group search result.
const maxLDAPGroups = 1000

// roleFor maps groups to a role, deny-by-default.
//
// Admin first: an account in both lists is an admin, because checking viewer
// first would demote every admin who is also in a viewer group — which is
// most of them (the OIDC rule, verbatim).
func (l *LDAP) roleFor(groups []string) (Role, bool) {
	for _, g := range groups {
		for _, admin := range l.cfg.AdminGroups {
			if strings.EqualFold(g, admin) {
				return RoleAdmin, true
			}
		}
	}
	for _, g := range groups {
		for _, viewer := range l.cfg.ViewerGroups {
			if strings.EqualFold(g, viewer) {
				return RoleViewer, true
			}
		}
	}
	return "", false
}

// CheckConnection dials and service-binds once, for the startup
// reachability warning. Failure here is weather, not configuration — the
// caller warns and serves.
func (l *LDAP) CheckConnection(ctx context.Context) error {
	conn, err := l.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck // probe connection
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return fmt.Errorf("%w: service bind: %v", ErrLDAPUnavailable, err) //nolint:errorlint // the sentinel is the API; the cause is context
		}
	}
	return nil
}
