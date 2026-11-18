package api

import (
	"bytes"
	"io/fs"
	"net/http"
	"time"

	"github.com/kazuhahub/rackbook/internal/config"
)

// Branding images. The sign-in page needs them before anyone is signed in, so
// these two paths are served outside authentication (see New). They are
// GET/HEAD only and come from memory: the files were read and checked when
// rackbook.yml was (re)loaded.
const (
	brandingLogoPath    = "/branding/logo"
	brandingFaviconPath = "/branding/favicon"
)

func (s *server) brandingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+brandingLogoPath, func(w http.ResponseWriter, r *http.Request) {
		a := s.o.Store.Config().BrandLogo()
		if a == nil {
			// No custom logo: the console shows its own mark and does not ask.
			writeError(w, http.StatusNotFound, "not_found", "no custom logo is configured")
			return
		}
		serveAsset(w, r, a)
	})
	mux.HandleFunc("GET "+brandingFaviconPath, func(w http.ResponseWriter, r *http.Request) {
		if a := s.o.Store.Config().BrandFavicon(); a != nil {
			serveAsset(w, r, a)
			return
		}
		// Default: the favicon that ships with the console.
		data, err := fs.ReadFile(s.o.Web, "favicon.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		serveAsset(w, r, config.NewAsset(data, "image/svg+xml"))
	})
}

func isBrandingPath(p string) bool { return p == brandingLogoPath || p == brandingFaviconPath }

// serveAsset sends an image with the exact type, nosniff and a CSP that stops
// an SVG opened directly in a tab from running anything. The console only ever
// shows it through <img>, which never runs SVG scripts.
func serveAsset(w http.ResponseWriter, r *http.Request, a *config.Asset) {
	h := w.Header()
	h.Set("Content-Type", a.ContentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	h.Set("Cache-Control", "no-cache") // cache it, but ask again before use
	h.Set("ETag", a.ETag)
	// ServeContent answers If-None-Match with 304 and HEAD without a body.
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(a.Data))
}
