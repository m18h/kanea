package edge

// The functions port (PRD §7.2.3): one node port dispatching
// /<project>/<function>/… to function VIPs, for a node with no base domain.
//
// This is a mode of the published-port machinery, not path routing: the host
// route table is untouched, the dispatch table is its own namespace, and the
// §7.2.1 middleware chain is reused by converting each FunctionRoute to a
// Route and compiling it; the Listener.asRoute trick, played again.
//
// Plaintext HTTP by design: a client connecting by IP sends no SNI, the same
// fact that keeps `tls` off published ports (§19.3). A function that needs TLS
// needs a name, and a name means the FQDN path.

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EntrypointFunctions names the functions port in the §9.1.1 metrics.
const EntrypointFunctions = "functions"

// functionsSet owns the functions port.
//
// One port, bound while the dispatch table is non-empty and released when it
// empties: a port held open for nothing is a port something else on the node
// cannot use.
type functionsSet struct {
	log   *slog.Logger
	proxy *Proxy
	port  int

	readHeaderTimeout time.Duration
	idleTimeout       time.Duration
	maxHeaderBytes    int
	// listen is injectable so tests run on :0.
	listen func(network, address string) (net.Listener, error)

	mu     sync.Mutex
	table  map[string]compiled // "/<project>/<function>" → compiled route
	ln     net.Listener
	srv    *http.Server
	warned bool
	// boundAddr is what the test asks after binding on :0.
	boundAddr string
}

func newFunctionsSet(proxy *Proxy, cfg Config) *functionsSet {
	return &functionsSet{
		log: cfg.Logger, proxy: proxy, port: cfg.FunctionsPort,
		readHeaderTimeout: cfg.ReadHeaderTimeout,
		idleTimeout:       cfg.IdleTimeout,
		maxHeaderBytes:    cfg.MaxHeaderBytes,
		listen:            net.Listen,
		table:             map[string]compiled{},
	}
}

// Apply swaps the dispatch table and reconciles the bind.
//
// Like listenerSet.Apply it returns no error: a bind failure is recorded and
// retried on the next snapshot poll, and must not reject the file.
func (f *functionsSet) Apply(routes []FunctionRoute) {
	f.mu.Lock()
	defer f.mu.Unlock()

	table := make(map[string]compiled, len(routes))
	for _, fr := range routes {
		c, err := compile(fr.asRoute())
		if err != nil {
			// Validate compiled this already, so it cannot normally fail; a
			// function whose middleware will not compile is skipped rather
			// than served unruled.
			f.log.Error("cannot compile a function's middleware",
				"function", fr.Name(), "error", err)
			continue
		}
		table[fr.Prefix()] = c
	}
	f.table = table

	switch {
	case len(table) == 0:
		if f.ln != nil {
			f.log.Info("releasing the functions port", "port", f.port)
			f.stopLocked()
		}
	case f.port <= 0:
		// Routes exist and nothing can serve them. Once, not per poll: a
		// warning per snapshot poll is a logging storm about a config file.
		if !f.warned {
			f.warned = true
			f.log.Warn("functions need path dispatch but no functions port is configured",
				"functions", len(table),
				"detail", "start kanea-edge with --functions-port, or give the node a base domain")
		}
	case f.ln == nil:
		f.bindLocked()
	}
}

func (f *functionsSet) bindLocked() {
	ln, err := f.listen("tcp", fmt.Sprintf(":%d", f.port))
	if err != nil {
		// The next snapshot poll is the retry, as with published ports.
		f.log.Error("cannot bind the functions port", "port", f.port, "error", err)
		return
	}
	f.ln, f.boundAddr = ln, ln.Addr().String()
	f.srv = &http.Server{
		ReadHeaderTimeout: f.readHeaderTimeout,
		IdleTimeout:       f.idleTimeout,
		MaxHeaderBytes:    f.maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(f.log.Handler(), slog.LevelDebug),
		ConnState:         connStateCounter(f.proxy.Metrics(), EntrypointFunctions),
		Handler:           http.HandlerFunc(f.serve),
	}
	go func(srv *http.Server, port int) {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			f.log.Error("functions listener stopped", "port", port, "error", err)
		}
	}(f.srv, f.port)
	f.log.Info("functions port bound", "port", f.port)
}

// serve dispatches one request by its first two path segments.
func (f *functionsSet) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	project, function, rest, ok := splitFunctionPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	prefix := "/" + project + "/" + function

	f.mu.Lock()
	route, found := f.table[prefix]
	f.mu.Unlock()
	if !found {
		http.NotFound(w, r)
		return
	}

	// Strip the prefix, the way http.StripPrefix would: the function's
	// wasi-http server sees /nightly, not /shop/report/nightly; its spec's
	// trigger paths are its own namespace (R26).
	r2 := new(http.Request)
	*r2 = *r
	u2 := *r.URL
	u2.Path = rest
	if u2.RawPath != "" {
		// A raw path that no longer matches the decoded one is worse than
		// none: let the URL re-encode.
		u2.RawPath = ""
	}
	r2.URL = &u2

	f.proxy.serveRoute(w, r2, route, "fn:"+prefix, EntrypointFunctions)
}

// splitFunctionPath parses /<project>/<function>[/rest]. rest is always
// rooted; a bare prefix means "/".
func splitFunctionPath(p string) (project, function, rest string, ok bool) {
	trimmed := strings.TrimPrefix(p, "/")
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	rest = "/"
	if len(parts) == 3 {
		rest += parts[2]
	}
	return parts[0], parts[1], rest, true
}

func (f *functionsSet) stopLocked() {
	if f.srv != nil {
		_ = f.srv.Close() //nolint:errcheck // cleanup path
	}
	f.ln, f.srv, f.boundAddr = nil, nil, ""
}

// Shutdown closes the port. Functions are HTTP: the server's Close drops what
// http.Server would drop, and the drain discipline of :443 does not apply to a
// LAN convenience port.
func (f *functionsSet) Shutdown() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopLocked()
}

// Addr reports the bound address, for tests and the status endpoint. Empty
// when unbound.
func (f *functionsSet) Addr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.boundAddr
}
