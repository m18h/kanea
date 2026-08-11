package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/settings"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/secretsource"
)

// Client talks to a running kanead over its unix socket.
type Client struct {
	http   *http.Client
	socket string
}

// NewClient builds a client for the given socket path.
func NewClient(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	return &Client{
		socket: socket,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// Socket reports the path this client talks to, for error messages.
func (c *Client) Socket() string { return trimSocketPrefix(c.socket) }

// Health checks that kanead is up. The CLI calls it first so a stopped daemon
// produces "is kanead running?" rather than a bare dial error.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var out Health
	err := c.do(ctx, http.MethodGet, PathHealth, nil, &out)
	return out, err
}

// Functions lists wasm functions (v1.39).
func (c *Client) Functions(ctx context.Context) (FunctionsResponse, error) {
	var out FunctionsResponse
	err := c.do(ctx, http.MethodGet, PathFunctions, nil, &out)
	return out, err
}

// Services lists the declared services.
func (c *Client) Services(ctx context.Context) ([]reconciler.Desired, error) {
	var out ServicesResponse
	if err := c.do(ctx, http.MethodGet, PathServices, nil, &out); err != nil {
		return nil, err
	}
	return out.Services, nil
}

// Apply declares services. Services not named are left alone.
func (c *Client) Apply(
	ctx context.Context, services []reconciler.Desired, pipelines []gitops.Config,
) (ApplyResponse, error) {
	var out ApplyResponse
	err := c.do(ctx, http.MethodPut, PathServices,
		ApplyRequest{Services: services, Pipelines: pipelines}, &out)
	return out, err
}

// Runs lists pipeline runs, newest first. Empty project or service means all.
func (c *Client) Runs(ctx context.Context, project, service string, limit int) ([]gitops.Run, error) {
	q := url.Values{}
	if project != "" {
		q.Set("project", project)
	}
	if service != "" {
		q.Set("service", service)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := PathPipelines
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out RunsResponse
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out.Runs, err
}

// Run returns one pipeline run.
func (c *Client) Run(ctx context.Context, project, service, id string) (gitops.Run, error) {
	var out gitops.Run
	path := fmt.Sprintf("%s/%s/%s/%s", PathPipelines,
		url.PathEscape(project), url.PathEscape(service), url.PathEscape(id))
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// Build queues a build and returns the queued run.
func (c *Client) Build(ctx context.Context, project, service string, deploy bool) (gitops.Run, error) {
	var out gitops.Run
	path := fmt.Sprintf("%s/%s/%s/build", PathPipelines,
		url.PathEscape(project), url.PathEscape(service))
	err := c.do(ctx, http.MethodPost, path, BuildRequest{Deploy: deploy}, &out)
	return out, err
}

// Sync fetches a project's git source and applies what it finds.
func (c *Client) Sync(ctx context.Context, project string) (SyncResponse, error) {
	var out SyncResponse
	path := fmt.Sprintf("%s/%s/sync", PathProjects, url.PathEscape(project))
	err := c.do(ctx, http.MethodPost, path, nil, &out)
	return out, err
}

// BuildLogs streams a run's log to w, following it while the run is going.
//
// Streamed rather than fetched whole: a build log is written as it happens and
// the reason to watch one is to see it happen.
func (c *Client) BuildLogs(
	ctx context.Context, project, service, id string, follow bool, w io.Writer,
) (err error) {
	path := fmt.Sprintf("%s/%s/%s/%s/logs", PathPipelines,
		url.PathEscape(project), url.PathEscape(service), url.PathEscape(id))
	if follow {
		path += "?follow=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://kanead"+path, nil)
	if err != nil {
		return err
	}
	// Following has no deadline, like alloc logs: a build takes minutes and the
	// client streams until the run ends or the user stops it.
	client := c.http
	if follow {
		clone := *c.http
		clone.Timeout = 0
		client = &clone
	}

	resp, err := client.Do(req)
	if err != nil {
		return c.dialError(err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	if _, cerr := io.Copy(w, resp.Body); cerr != nil {
		if ctx.Err() != nil {
			return nil // the user stopped following; not an error
		}
		return cerr
	}
	return nil
}

// DeleteService removes a service and, in turn, its allocs.
func (c *Client) DeleteService(ctx context.Context, project, service string) (ApplyResponse, error) {
	var out ApplyResponse
	path := fmt.Sprintf("%s/%s/%s", PathServices, url.PathEscape(project), url.PathEscape(service))
	err := c.do(ctx, http.MethodDelete, path, nil, &out)
	return out, err
}

// Scale sets a service's replica count.
func (c *Client) Scale(ctx context.Context, project, service string, count int) (ApplyResponse, error) {
	var out ApplyResponse
	path := fmt.Sprintf("%s/%s/%s/scale", PathServices,
		url.PathEscape(project), url.PathEscape(service))
	err := c.do(ctx, http.MethodPost, path, ScaleRequest{Count: count}, &out)
	return out, err
}

// Allocs lists alloc records, optionally filtered.
func (c *Client) Allocs(ctx context.Context, project, service string) ([]reconciler.AllocRecord, error) {
	q := url.Values{}
	if project != "" {
		q.Set("project", project)
	}
	if service != "" {
		q.Set("service", service)
	}
	path := PathAllocs
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out AllocsResponse
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Allocs, nil
}

// Stats fetches one service's point-in-time sample, including the edge's
// labelled totals (§9.1.1).
func (c *Client) Stats(ctx context.Context, project, service string) (StatsSample, error) {
	q := url.Values{}
	q.Set("project", project)
	q.Set("service", service)
	var out StatsSample
	err := c.do(ctx, http.MethodGet, PathStats+"?"+q.Encode(), nil, &out)
	return out, err
}

// Logs streams alloc logs to w until the stream ends or the context is
// cancelled. With Follow set it does not return on its own.
func (c *Client) Logs(ctx context.Context, opts LogOptions, w io.Writer) (err error) {
	q := url.Values{}
	if opts.Project != "" {
		q.Set("project", opts.Project)
	}
	if opts.Service != "" {
		q.Set("service", opts.Service)
	}
	if opts.AllocID != "" {
		q.Set("alloc", opts.AllocID)
	}
	if opts.Follow {
		q.Set("follow", "true")
	}
	if opts.Tail > 0 {
		q.Set("tail", strconv.Itoa(opts.Tail))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://kanead"+PathLogs+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	// Following has no deadline: the client streams until the user stops it.
	client := c.http
	if opts.Follow {
		clone := *c.http
		clone.Timeout = 0
		client = &clone
	}

	resp, err := client.Do(req)
	if err != nil {
		return c.dialError(err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	if _, cerr := io.Copy(w, resp.Body); cerr != nil {
		if ctx.Err() != nil {
			return nil // the user stopped following; not an error
		}
		return cerr
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) (err error) {
	var reader io.Reader
	if body != nil {
		encoded, merr := json.Marshal(body)
		if merr != nil {
			return merr
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, "http://kanead"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return c.dialError(err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// dialError turns a connection failure into the question the user actually
// needs answered: "is kanead running?" rather than a bare ENOENT on a socket
// path most people have never seen.
func (c *Client) dialError(err error) error {
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return fmt.Errorf("cannot reach kanead at %s (is it running? try `kanea agent`): %w",
			c.Socket(), err)
	}
	return err
}

func decodeError(resp *http.Response) error {
	var body Error
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err == nil && body.Error != "" {
		return &StatusError{Status: resp.StatusCode, Message: body.Error}
	}
	return &StatusError{Status: resp.StatusCode, Message: resp.Status}
}

// StatusError is a refusal from the daemon, with the status it came with.
//
// The status is carried rather than folded into the message because callers act
// on it: a queued build refused with 429 is worth retrying in a moment, and the
// same refusal at 409 — no build block, no git source — never will be. Without
// the code the two are one indistinguishable string.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string { return "kanead: " + e.Message }

// Retryable reports whether trying the same call again could succeed.
func (e *StatusError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests ||
		e.Status == http.StatusServiceUnavailable ||
		e.Status >= http.StatusInternalServerError
}

// ListSecrets returns metadata for the secrets that exist.
//
// Metadata only — there is no client method to read a value, because there is
// no server route to read one (PRD §13.3).
func (c *Client) ListSecrets(ctx context.Context, prefix string) ([]secrets.Info, error) {
	path := PathSecrets
	if prefix != "" {
		path += "?prefix=" + url.QueryEscape(prefix)
	}
	var resp SecretsResponse
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Secrets, nil
}

// SecretProviders returns external-provider sync status (PRD §5.2.13) —
// metadata only, like everything on this surface.
func (c *Client) SecretProviders(ctx context.Context) ([]secretsource.ProviderStatus, error) {
	var resp SecretProvidersResponse
	if err := c.do(ctx, http.MethodGet, PathSecrets+"/providers", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Providers, nil
}

// PutSecret creates or replaces a secret.
func (c *Client) PutSecret(ctx context.Context, secretPath string, value []byte) error {
	clean, err := secrets.CleanPath(secretPath)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, PathSecrets+"/"+clean,
		SecretRequest{Value: string(value)}, nil)
}

// DeleteSecret removes a secret.
func (c *Client) DeleteSecret(ctx context.Context, secretPath string) error {
	clean, err := secrets.CleanPath(secretPath)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, PathSecrets+"/"+clean, nil, nil)
}

// Settings reads the node settings view (v1.46).
func (c *Client) Settings(ctx context.Context) (SettingsResponse, error) {
	var resp SettingsResponse
	err := c.do(ctx, http.MethodGet, PathSettings, nil, &resp)
	return resp, err
}

// PutBackupSettings replaces the backup destination.
func (c *Client) PutBackupSettings(ctx context.Context, rec settings.BackupSettings) (BackupSettingsView, error) {
	var view BackupSettingsView
	err := c.do(ctx, http.MethodPut, PathSettings+"/backup", rec, &view)
	return view, err
}

// ResetBackupSettings deletes the record, reverting to the daemon's flags.
func (c *Client) ResetBackupSettings(ctx context.Context) (BackupSettingsView, error) {
	var view BackupSettingsView
	err := c.do(ctx, http.MethodDelete, PathSettings+"/backup", nil, &view)
	return view, err
}

// PutNotificationSettings replaces the node-level channels.
func (c *Client) PutNotificationSettings(ctx context.Context, rec settings.NotificationSettings) (NotificationSettingsView, error) {
	var view NotificationSettingsView
	err := c.do(ctx, http.MethodPut, PathSettings+"/notifications", rec, &view)
	return view, err
}

// ResetNotificationSettings removes the node-level channels.
func (c *Client) ResetNotificationSettings(ctx context.Context) (NotificationSettingsView, error) {
	var view NotificationSettingsView
	err := c.do(ctx, http.MethodDelete, PathSettings+"/notifications", nil, &view)
	return view, err
}

// ProjectNotifications reads one project's channel config.
func (c *Client) ProjectNotifications(ctx context.Context, project string) (ProjectNotificationsView, error) {
	var view ProjectNotificationsView
	err := c.do(ctx, http.MethodGet, PathProjects+"/"+url.PathEscape(project)+"/notifications", nil, &view)
	return view, err
}

// PutProjectNotifications replaces one project's channel config.
func (c *Client) PutProjectNotifications(
	ctx context.Context, project string, n *jobspec.Notifications,
) (ProjectNotificationsView, error) {
	var view ProjectNotificationsView
	err := c.do(ctx, http.MethodPut, PathProjects+"/"+url.PathEscape(project)+"/notifications",
		map[string]any{"notifications": n}, &view)
	return view, err
}

// Users lists accounts, without password hashes.
func (c *Client) Users(ctx context.Context) ([]auth.User, error) {
	var resp UsersResponse
	if err := c.do(ctx, http.MethodGet, PathUsers, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// PutUser creates or replaces an account.
func (c *Client) PutUser(ctx context.Context, name, password string, role auth.Role) error {
	return c.do(ctx, http.MethodPut, PathUsers+"/"+url.PathEscape(name),
		UserRequest{Password: password, Role: role}, nil)
}

// DeleteUser removes an account.
func (c *Client) DeleteUser(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, PathUsers+"/"+url.PathEscape(name), nil, nil)
}

// Tokens lists tokens, without their hashes.
func (c *Client) Tokens(ctx context.Context) ([]auth.Token, error) {
	var resp TokensResponse
	if err := c.do(ctx, http.MethodGet, PathTokens, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Tokens, nil
}

// CreateToken mints a token and returns it with its one-time secret.
func (c *Client) CreateToken(ctx context.Context, name string, role auth.Role, expiresIn string) (TokenResponse, error) {
	var resp TokenResponse
	err := c.do(ctx, http.MethodPost, PathTokens,
		TokenRequest{Name: name, Role: role, ExpiresIn: expiresIn}, &resp)
	return resp, err
}

// RevokeToken deletes a token by id.
func (c *Client) RevokeToken(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, PathTokens+"/"+url.PathEscape(id), nil, nil)
}

// Backups lists archives and reports replication health.
func (c *Client) Backups(ctx context.Context) (BackupsResponse, error) {
	var out BackupsResponse
	err := c.do(ctx, http.MethodGet, PathBackups, nil, &out)
	return out, err
}

// CreateBackup takes an on-demand archive.
func (c *Client) CreateBackup(ctx context.Context, reason string) (backup.Manifest, error) {
	var out backup.Manifest
	err := c.do(ctx, http.MethodPost, PathBackups, BackupRequest{Reason: reason}, &out)
	return out, err
}

// VerifyBackup checks an archive against its manifest.
func (c *Client) VerifyBackup(ctx context.Context, id string) error {
	path := fmt.Sprintf("%s/%s/verify", PathBackups, url.PathEscape(id))
	return c.do(ctx, http.MethodGet, path, nil, nil)
}

// StageRestore asks the daemon to restore at its next start.
//
// There is no client method that restores in place, because there is no route
// that does: §15.3 puts a restore on a stopped node, and the shape of this API
// is what enforces it.
func (c *Client) StageRestore(ctx context.Context, archive string, skipReplay bool) (RestoreResponse, error) {
	var out RestoreResponse
	err := c.do(ctx, http.MethodPost, PathBackups+"/restore",
		RestoreRequest{Archive: archive, SkipReplay: skipReplay}, &out)
	return out, err
}

// CACertificate fetches this node's self-signed CA certificate (PRD §7.3).
//
// Raw bytes rather than a JSON envelope: what comes back is a PEM file that an
// operator redirects into `kanea-ca.crt` and hands to a device's trust store.
// Wrapping it would mean every caller has to unwrap it again.
func (c *Client) CACertificate(ctx context.Context) (body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://kanead"+PathCerts+"/ca", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.dialError(err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeError(resp)
	}
	// A CA certificate is a couple of kilobytes; the bound is there so a
	// misrouted response cannot be read into memory without limit.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// EdgePolicy is what a node lets a spec publish (R22).
type EdgePolicy struct {
	Enabled  bool   `json:"publish_enabled"`
	Spec     string `json:"publish_ports"`
	Reserved []int  `json:"reserved"`
	Ranges   []struct {
		From int `json:"from"`
		To   int `json:"to"`
	} `json:"ranges"`
}

// Allows reports whether this node permits a spec to bind a node port.
//
// The same rule the server enforces, asked in advance. It is a courtesy, not
// the boundary: the node re-checks at apply, because a GitOps sync never comes
// through here.
func (p EdgePolicy) Allows(port int) bool {
	for _, reserved := range p.Reserved {
		if port == reserved {
			return false
		}
	}
	for _, r := range p.Ranges {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}

// EdgePolicy reads the node's publishing policy.
func (c *Client) EdgePolicy(ctx context.Context) (EdgePolicy, error) {
	var out EdgePolicy
	err := c.do(ctx, http.MethodGet, PathEdgePolicy, nil, &out)
	return out, err
}
