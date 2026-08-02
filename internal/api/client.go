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

	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/secrets"
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

// Services lists the declared services.
func (c *Client) Services(ctx context.Context) ([]reconciler.Desired, error) {
	var out ServicesResponse
	if err := c.do(ctx, http.MethodGet, PathServices, nil, &out); err != nil {
		return nil, err
	}
	return out.Services, nil
}

// Apply declares services. Services not named are left alone.
func (c *Client) Apply(ctx context.Context, services []reconciler.Desired) (ApplyResponse, error) {
	var out ApplyResponse
	err := c.do(ctx, http.MethodPut, PathServices, ApplyRequest{Services: services}, &out)
	return out, err
}

// DeleteService removes a service and, in turn, its allocs.
func (c *Client) DeleteService(ctx context.Context, project, service string) (ApplyResponse, error) {
	var out ApplyResponse
	path := fmt.Sprintf("%s/%s/%s", PathServices, url.PathEscape(project), url.PathEscape(service))
	err := c.do(ctx, http.MethodDelete, path, nil, &out)
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
		return fmt.Errorf("kanead: %s", body.Error)
	}
	return fmt.Errorf("kanead: %s", resp.Status)
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
