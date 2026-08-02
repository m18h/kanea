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
// an empty directory, so something has to be in there — and a file that
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
func Handler(prefix string) http.Handler {
	files := assets()
	server := http.FileServer(http.FS(files))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
