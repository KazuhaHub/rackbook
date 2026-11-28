// Package localauth is the sign-in of local accounts (docs/design-local-accounts.md, piece 4): the one-step
// sign-in, opening invite and reset links, first setup with a mandatory second factor, re-authentication, the
// sign-in protection (throttle, locks, the NIST cap, the second-factor limits, the dummy-hash budget), the
// aggregated events, and the admin channel the online command line uses. It sees the account store and the state
// key, which the HTTP-facing packages must not: the session itself is issued through login.Service.IssueLocal.
package localauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/clientip"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/login"
	"github.com/kazuhahub/rackbook/internal/routes"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Options configures the Service.
type Options struct {
	Store *accounts.Store
	Key   *statekey.Key
	Audit *audit.Log
	Login *login.Service
	// Config returns the current rackbook.yml, which changes when the data repository is pulled. The sign-in
	// settings are read from it on every request.
	Config  func() *config.Config
	BaseURL string
	// Trusted are the --trusted-proxy CIDRs.
	Trusted []netip.Prefix
	// SSO says single sign-on is configured and enabled (never "healthy", 2.1).
	SSO bool
	// IsAdmin says whether the local account holds the admin role now; nil = nobody does.
	IsAdmin func(username string) bool
	// Hasher runs argon2id; nil = the server's (three slots, 64 MiB).
	Hasher *accounts.Hasher
	// GrantAdmin commits local:<username> to auth.roles.admin for the online `recover --grant-admin`; nil = not
	// available online (the command prints the line to add).
	GrantAdmin func(ctx context.Context, username, operator string) error
	// StateDir is where the admin channel's socket lives.
	StateDir string
	Now      func() time.Time
	Sleep    func(time.Duration) // a test seam; nil = time.Sleep
	Logger   *slog.Logger
	// SkipCalibration leaves the hash-only sample empty at start (tests fill it themselves).
	SkipCalibration bool
}

// Service implements the sign-in of local accounts.
type Service struct {
	o      Options
	log    *slog.Logger
	now    func() time.Time
	sleep  func(time.Duration)
	base   *url.URL
	hasher *accounts.Hasher
	store  *accounts.Store

	tables  *tables
	budget  *budget
	sample  *sample
	refused *aggregator
	sealer  *sealer
	replay  *replaySet
	pk      *passkeyKit

	// counterFailed is set when a counter write of an answered attempt could not be made: the next attempt is
	// refused with 503 audit_unavailable (8.6).
	counterFailed atomic.Bool

	problemMu   sync.Mutex
	problemSeen bool

	stop chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

// New validates the options and starts the calibration of the hash-only sample and the minute flush.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Key == nil || o.Login == nil || o.Config == nil {
		return nil, errors.New("localauth: the account store, the state key, the login service and the config are required")
	}
	base, err := url.Parse(o.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, errors.New("localauth: --base-url must be an https origin")
	}
	s := &Service{o: o, log: o.Logger, now: o.Now, sleep: o.Sleep, base: &url.URL{Scheme: "https", Host: base.Host}, hasher: o.Hasher, store: o.Store, stop: make(chan struct{})}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.sleep == nil {
		s.sleep = time.Sleep
	}
	if s.hasher == nil {
		s.hasher = accounts.NewHasher()
	}
	s.tables, s.budget, s.sample = newTables(s.now), newBudget(s.now), &sample{}
	s.refused = newAggregator("login_refused", func(e audit.Event) { s.o.Audit.Record(e) })
	s.sealer = newSealer(o.Key)
	s.replay = newReplaySet(s.now)
	if s.pk, err = newPasskeyKit(s.base, o.Store, o.Key, s.sealer, s.now, s.replay); err != nil {
		return nil, err
	}
	if !o.SkipCalibration {
		s.wg.Add(1)
		go s.calibrate()
	}
	s.wg.Add(1)
	go s.flusher()
	return s, nil
}

// Close stops the background work and writes the summaries of the minute that is running.
func (s *Service) Close() {
	s.once.Do(func() { close(s.stop) })
	s.wg.Wait()
	s.refused.Flush(s.now(), true)
}

// calibrate runs the hash-only sample's first runs through the slots, in the background (8.6).
func (s *Service) calibrate() {
	defer s.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-s.stop; cancel() }()
	for i := 0; i < calibrationRuns; i++ {
		d, err := s.hasher.DummyTimed(ctx, accounts.ClassNormal, "rackbook calibration")
		if err != nil {
			return
		}
		s.sample.Add(d, "", "")
	}
}

func (s *Service) flusher() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.refused.Flush(s.now(), false)
		}
	}
}

// Mount registers the pages and endpoints under /auth/local/.
func (s *Service) Mount(mux routes.Mux, static http.Handler) {
	page := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, r)
	}
	mux.HandleFunc("GET /auth/local/setup", page)
	mux.HandleFunc("GET /auth/local/reauth", page)
	mux.HandleFunc("POST /auth/local/attempt", s.attempt)
	mux.HandleFunc("POST /auth/local/login", s.signIn)
	mux.HandleFunc("POST /auth/local/setup/open", s.setupOpen)
	mux.HandleFunc("POST /auth/local/setup/totp", s.setupTOTP)
	mux.HandleFunc("POST /auth/local/setup/passkey", s.setupPasskey)
	mux.HandleFunc("POST /auth/local/setup/finish", s.setupFinish)
	mux.HandleFunc("POST /auth/local/reauth", s.reauth)
}

// ---- settings

func (s *Service) settings() config.SignInSettings { return s.o.Config().Auth.SignInSettings() }

// ssoOnly says sso_only is in force: it is on, the page offers single sign-on, and a local administrator exists. When
// it is on but no local administrator with a password and a second factor does, it is treated as off and a
// settings_problem is written once (2.1): the break-glass path must never be lost to a push.
func (s *Service) ssoOnly(set config.SignInSettings) bool {
	if !set.SSOOnlyConfigured(s.o.SSO) {
		s.setProblem(false)
		return false
	}
	if s.localAdminExists() {
		s.setProblem(false)
		return true
	}
	s.setProblem(true)
	return false
}

func (s *Service) setProblem(on bool) {
	s.problemMu.Lock()
	changed := s.problemSeen != on
	s.problemSeen = on
	s.problemMu.Unlock()
	if changed && on {
		s.o.Audit.Record(audit.Event{Event: "settings_problem", Code: "sso_only_without_local_admin", Area: "security"})
		s.log.Warn("auth.login.sso_only is on but no active local administrator with a second factor exists: it is treated as off")
	}
}

// LocalAdminExists says an active local account holds the admin role and has a password and a second factor.
func (s *Service) LocalAdminExists() bool { return s.localAdminExists() }

func (s *Service) localAdminExists() bool {
	if s.o.IsAdmin == nil {
		return false
	}
	var names []string
	s.store.Peek(func(st *accounts.State) {
		for n, a := range st.Accounts {
			if a.State == accounts.StateActive && a.Password != "" && (a.TOTP != nil || len(a.Passkeys) > 0) {
				names = append(names, n)
			}
		}
	})
	for _, n := range names {
		if s.o.IsAdmin(n) {
			return true
		}
	}
	return false
}

// ---- HTTP helpers

const (
	msgFailed      = "Username, password or code is wrong."
	msgSSORequired = "Use your organisation's sign-in."
	msgTooMany     = "Too many attempts, try later."
	msgAuditDown   = "Sign-in is unavailable: the server cannot write its audit log. An administrator must check the server."
	msgBusy        = "Try again shortly."
	msgBadRequest  = "The request is not valid."
	maxBody        = 64 << 10
	refusalDelay   = 250 * time.Millisecond
)

// reply writes a JSON answer with its length known and sends it at once, so that work after the answer (the counter
// writes of a failed attempt, 8.6) does not delay it.
func reply(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(b)+1))
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	reply(w, status, map[string]string{"error": code, "message": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", msgBadRequest)
		return false
	}
	return true
}

// where is the client: the bucket for the protection (IPv6 by /48) and the address the audit log keeps.
func (s *Service) where(r *http.Request) (bucket, addr string) {
	return clientip.Bucket(r, s.o.Trusted, 48), clientip.Addr(r, s.o.Trusted)
}

// auditOK refuses an attempt when the audit log cannot be written, or when the counters of the last answered
// attempt could not be (the next attempt is the one refused, 8.6).
func (s *Service) auditOK() bool {
	if s.counterFailed.CompareAndSwap(true, false) {
		return false
	}
	return s.o.Audit.Writable()
}

// normalise is the username as typed, folded to the form accounts use. Whether it is an account is not decided here.
func normalise(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func (s *Service) classFor(a *accounts.Account, bucket string) accounts.Class {
	if a != nil && inGoodBuckets(a, bucket, s.now()) {
		return accounts.ClassPriority
	}
	return accounts.ClassNormal
}

const goodBucketAge = 30 * 24 * time.Hour

func inGoodBuckets(a *accounts.Account, bucket string, now time.Time) bool {
	for _, g := range a.GoodBuckets {
		if g.Bucket == bucket && now.Sub(g.Last) < goodBucketAge {
			return true
		}
	}
	return false
}

func withGoodBucket(a *accounts.Account, bucket string, now time.Time) {
	var keep []accounts.GoodBucket
	for _, g := range a.GoodBuckets {
		if g.Bucket != bucket && now.Sub(g.Last) < goodBucketAge {
			keep = append(keep, g)
		}
	}
	keep = append(keep, accounts.GoodBucket{Bucket: bucket, Last: now.UTC()})
	if len(keep) > 10 {
		keep = keep[len(keep)-10:]
	}
	a.GoodBuckets = keep
}
