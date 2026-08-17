// Package dashboard embeds the built React SPA and serves it (PRD §12.1).
//
// The assets are compiled into the binary rather than read from disk: Kanea
// ships as one static binary (G1), and a dashboard that needed a directory
// alongside it would be a second thing to install, version and get wrong.
package dashboard

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// dist holds the Vite build output.
//
// `all:` so that files Vite may emit with a leading underscore or dot are
// included; the default embed rules skip those, which would silently drop an
// asset the page needs.
//
//go:embed all:dist
var dist embed.FS

// placeholderName is the committed stand-in that makes this package compile
// before the dashboard has ever been built. `go:embed` fails at compile time on
// an empty directory, so something has to be in there, and a file that
// explains itself beats an empty .gitkeep.
const placeholderName = "placeholder.html"

// indexName is the SPA entry point Vite produces.
const indexName = "index.html"

// Built reports whether a real dashboard build is embedded.
//
// Worth asking rather than assuming: a `go build` without `make dashboard`
// produces a working daemon with a placeholder page, and an operator seeing
// that page should be told why rather than left to wonder.
func Built() bool {
	_, err := fs.Stat(assets(), indexName)
	return err == nil
}

// assets returns the embedded files rooted at the dist directory.
func assets() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Unreachable: the directory is embedded at compile time.
		panic("dashboard: embedded assets are missing: " + err.Error())
	}
	return sub
}

// Handler serves the SPA under prefix.
//
// Two behaviours that a plain http.FileServer would get wrong for a
// single-page app:
//
//   - An unknown path falls back to index.html rather than 404ing, because the
//     router is client-side: a deep link is a real URL to the user and a
//     missing file to the server.
//   - A request for a *file* that does not exist still 404s. Falling back for
//     those too would answer a missing script with HTML, which the browser
//     reports as a syntax error and sends you looking in the wrong place.
//
// wsOrigins is the daemon's `--dashboard-origins` allowlist, and it is here
// for one reason: the CSP's connect-src must permit exactly the origins the
// websocket handshake accepts. The handshake takes same-origin plus that list
// (api.Server.checkOrigin), so a policy that named only the first would block,
// in the browser, a socket the daemon was configured to allow.
func Handler(prefix string, wsOrigins []string) http.Handler {
	files := assets()
	server := http.FileServer(http.FS(files))
	allowed := websocketSources(wsOrigins)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every answer carries these: the 200s, the 404s and the 405 alike;
		// because the headers protect the origin, not one page on it.
		setSecurityHeaders(w, r, allowed)

		// Registered on the bare prefix so the API's own patterns stay more
		// specific, which means the method check lands here rather than in the
		// route pattern. Static assets answer GET and HEAD and nothing else.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		upstream := strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(prefix, "/"))
		if upstream == "" {
			upstream = "/"
		}
		clean := path.Clean(strings.TrimPrefix(upstream, "/"))
		if clean == "." || clean == indexName {
			// Served directly rather than through the file server, which
			// redirects /index.html to / for canonical URLs and would bounce
			// this request straight back.
			serveIndex(w, r, files)
			return
		}

		if _, err := fs.Stat(files, clean); err != nil {
			if !errors.Is(err, fs.ErrNotExist) || looksLikeAsset(clean) {
				http.NotFound(w, r)
				return
			}
			serveIndex(w, r, files)
			return
		}

		// Long-lived caching is safe for hashed assets and wrong for the entry
		// point, which has to be re-fetched to learn the new hashes.
		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + clean
		server.ServeHTTP(w, r2)
	})
}

// serveIndex answers a client-side route with the SPA entry point.
func serveIndex(w http.ResponseWriter, r *http.Request, files fs.FS) {
	name := indexName
	if _, err := fs.Stat(files, name); err != nil {
		name = placeholderName
	}
	body, err := fs.ReadFile(files, name)
	if err != nil {
		http.Error(w, "dashboard is not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	// The response is the embedded entry point and nothing from the request, so
	// there is no user input on this path to escape.
	if _, err := w.Write(body); err != nil {
		_ = err // the client hung up; nothing useful to do or report
	}
	_ = r
}

// looksLikeAsset reports whether a path is asking for a file rather than a
// client-side route. A route has no extension; `/services/shop` is a page and
// `/assets/index-abc.js` is not.
func looksLikeAsset(name string) bool {
	return path.Ext(name) != ""
}

// cspCommon is every directive that does not depend on the request: the depth
// layer under the app's own discipline. connect-src is the one that does, and
// it is built per request just below.
//
// The dashboard renders attacker-influenced strings (log lines, service
// names, event messages) and React escapes all of them; the ESLint ban on
// dangerouslySetInnerHTML keeps it that way. This policy is what stops a
// future slip from becoming an exploit: no inline script exists in the build
// (Vite emits files, and only files) and script-src stays without an inline
// exception. style-src carries 'unsafe-inline' because the exception is not
// in the build but at runtime: xterm.js sets style attributes on its cursor
// and selection elements, and shadcn's primitives position dialogs the same
// way; a strict style-src blocks them and the terminal renders broken.
// The one data: URI is the favicon, which is why img-src carries the scheme
// and font-src does not; the build ships no @font-face at all. base-uri is
// 'none' rather than 'self': the page has no <base> element, and an injected
// one would repoint every relative URL on it. frame-ancestors is the
// clickjacking guard: an admin console with stop, restart and restore buttons
// is exactly what an invisible overlay wants.
//
// This is the ONLY place the dashboard's CSP is set. A second header on the
// same response is not redundancy: browsers intersect multiple policies, so
// a stricter duplicate silently wins.
const cspCommon = "default-src 'self'; " +
	"script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; " +
	"frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; " +
	"form-action 'self'; object-src 'none'"

// contentSecurityPolicy is the policy for one request, which is per request
// only because of connect-src.
//
// The app connects to its own origin and nowhere else: REST over fetch, and
// the live and exec sockets. `'self'` covers the fetches, but whether it also
// covers ws:/wss: to the same host is exactly the thing browsers have
// disagreed about, so the sockets are named. Naming them as the bare schemes
// (`connect-src 'self' ws: wss:`) is what this used to do, and it matches any
// host on the internet: it left connect-src; the directive whose whole job is
// to bound where a compromised page can send what it has read, with no bound
// at all on the one transport that is bidirectional. So the schemes are pinned
// to the host the request came in on, which is by construction the origin the
// page is running on, plus the daemon's configured extras.
//
// A Host that is not a plausible host[:port] gets neither: it cannot be the
// origin of a real page, and letting one compose into the header would put a
// `;` (a directive separator) under the client's control. Note that this is
// r.Host and deliberately not X-Forwarded-Host: a forwarded header is a claim,
// not evidence (the rule the edge is built on), and trusting one here would let
// a request name the host its own page may talk to. A reverse proxy that
// rewrites Host therefore needs `--dashboard-origins`: the same requirement
// checkOrigin already imposes on it, for the same socket.
func contentSecurityPolicy(host string, allowed []string) string {
	connect := "; connect-src 'self'"
	if isPlainHost(host) {
		connect += " ws://" + host + " wss://" + host
	}
	for _, src := range allowed {
		connect += " " + src
	}
	return cspCommon + connect
}

// websocketSources turns configured Origins into connect-src sources.
//
// The scheme is carried over rather than doubled: a page served over https can
// only open wss (mixed content stops the other), so emitting both would widen
// the policy past anything that could be used. Anything unparsable is dropped
// silently here: it is not a source, and checkOrigin will refuse it too, so
// the failure an operator sees is the one about the handshake rather than a
// second one about a header.
func websocketSources(origins []string) []string {
	var out []string
	for _, origin := range origins {
		u, err := url.Parse(strings.TrimSpace(origin))
		if err != nil || !isPlainHost(u.Host) {
			continue
		}
		switch u.Scheme {
		case "https", "wss":
			out = append(out, "wss://"+u.Host)
		case "http", "ws":
			out = append(out, "ws://"+u.Host)
		}
	}
	return out
}

// isPlainHost reports whether host is a bare host[:port]: a DNS name, an IPv4
// address or a bracketed IPv6 literal, and nothing that could be read as CSP
// syntax. Deliberately a byte allowlist rather than a parse: the question is
// not "is this a resolvable name" but "is every byte of this safe to
// concatenate into a header".
func isPlainHost(host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == ':' || c == '[' || c == ']' || c == '_':
		default:
			return false
		}
	}
	return true
}

// setSecurityHeaders writes the browser-side hardening for one response.
func setSecurityHeaders(w http.ResponseWriter, r *http.Request, allowed []string) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy(r.Host, allowed))
	// A 404 from here is plain text; nosniff keeps a browser from reading it
	// as something else.
	h.Set("X-Content-Type-Options", "nosniff")
	// The modern spelling is frame-ancestors above; this is the one older
	// browsers still read.
	h.Set("X-Frame-Options", "DENY")
	// The app never navigates away with a secret in the URL, and a referrer
	// would leak a session's path to whatever is embedded or linked.
	h.Set("Referrer-Policy", "no-referrer")
	// Browsers ignore it over plain HTTP, and a homelab node behind its own
	// proxy may legitimately serve HTTP, so it is only claimed under TLS.
	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}
