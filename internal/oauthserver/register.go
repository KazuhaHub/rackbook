package oauthserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/kazuhahub/rackbook/internal/clientip"
)

// Limits of dynamic client registration (RFC 7591), which anyone who can reach
// the server may call: the file stays small and cannot be filled by a flood.
const (
	maxRegistrations  = 100
	maxRegisterBody   = 16 << 10
	registerWindow    = 10 * time.Minute
	registerPerWindow = 30
	unusedClientTTL   = 24 * time.Hour      // registered, never authorized
	idleClientTTL     = 30 * 24 * time.Hour // authorized before, no grant left
	clientIDPrefix    = "rbc_"
)

type registerRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
	AuthMethod   string   `json:"token_endpoint_auth_method"`
	GrantTypes   []string `json:"grant_types"`
	ResponseType []string `json:"response_types"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return
	}
	if !s.dcrOn() {
		oauthError(w, http.StatusNotFound, "registration_not_supported", "dynamic client registration is turned off; use a client ID metadata document")
		return
	}
	var req registerRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRegisterBody))
	if err := dec.Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body must be a JSON object")
		return
	}
	if req.AuthMethod != "" && req.AuthMethod != "none" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public clients are supported (token_endpoint_auth_method none)")
		return
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "grant_types may only be authorization_code and refresh_token")
			return
		}
	}
	for _, t := range req.ResponseType {
		if t != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "response_types may only be code")
			return
		}
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirects {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must list 1 to 10 URIs")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirect(u); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	name := cleanName(req.ClientName, "MCP client")
	now := s.now()

	// A registration that already exists costs nothing and is not limited, so a
	// client that registers at every start never uses up anyone's allowance.
	ip := clientip.Of(r, s.o.TrustedProxies)
	var out *Client
	err := s.store.mutate(func(d *fileData) error {
		pruneClients(d, now)
		for _, c := range d.Clients {
			if c.Name == name && slices.Equal(c.RedirectURIs, req.RedirectURIs) {
				out = c
				return errNoChange
			}
		}
		if blocked, wait := s.regLimit.Blocked(ip); blocked {
			return &rateError{wait}
		}
		s.regLimit.Fail(ip) // charged in the same critical section as the check
		if len(d.Clients) >= maxRegistrations && !evictOldestUnused(d) {
			return errRegistryFull
		}
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		out = &Client{ID: clientIDPrefix + base64.RawURLEncoding.EncodeToString(b[:]), Name: name, RedirectURIs: req.RedirectURIs, Created: now}
		d.Clients[out.ID] = out
		return nil
	})
	var re *rateError
	if errors.As(err, &re) {
		w.Header().Set("Retry-After", strconv.Itoa(re.wait))
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations from this address, try again later")
		return
	}
	status := http.StatusCreated
	switch {
	case errors.Is(err, errNoChange):
		status = http.StatusOK
	case errors.Is(err, errRegistryFull):
		w.Header().Set("Retry-After", "3600")
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", errRegistryFull.Error())
		return
	case err != nil:
		s.fail(w, "registration", err)
		return
	}
	s.log.Info("oauth client registered", "client", out.ID, "name", out.Name)
	writeJSON(w, status, map[string]any{
		"client_id": out.ID, "client_id_issued_at": out.Created.Unix(), "client_name": out.Name,
		"redirect_uris": out.RedirectURIs, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
	})
}

// errNoChange stops a mutation that found nothing to write.
var errNoChange = errors.New("no change")

var errRegistryFull = errors.New("too many clients are registered, try again later")

// rateError carries the seconds until a client address may register again.
type rateError struct{ wait int }

func (e *rateError) Error() string { return "too many registrations" }

// evictOldestUnused makes room by dropping the oldest registration that was
// never used for a grant. It reports false when every registration is in use.
func evictOldestUnused(d *fileData) bool {
	inUse := map[string]bool{}
	for _, g := range d.Grants {
		inUse[g.ClientID] = true
	}
	oldest := ""
	for id, c := range d.Clients {
		if inUse[id] || !c.LastUsed.IsZero() {
			continue
		}
		if oldest == "" || c.Created.Before(d.Clients[oldest].Created) {
			oldest = id
		}
	}
	if oldest == "" {
		return false
	}
	delete(d.Clients, oldest)
	return true
}

// pruneClients drops registrations nobody uses: never authorized after a day,
// or authorized once and without a grant for 30 days. Clients with a grant stay.
func pruneClients(d *fileData, now time.Time) {
	inUse := map[string]bool{}
	for _, g := range d.Grants {
		inUse[g.ClientID] = true
	}
	for id, c := range d.Clients {
		if inUse[id] {
			continue
		}
		switch {
		case c.LastUsed.IsZero() && now.Sub(c.Created) > unusedClientTTL:
			delete(d.Clients, id)
		case !c.LastUsed.IsZero() && now.Sub(c.LastUsed) > idleClientTTL:
			delete(d.Clients, id)
		}
	}
}
