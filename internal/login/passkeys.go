package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/authcore/passkey"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/clientip"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/secretscan"
)

const (
	maxPasskeysPerUser = 10
	maxCeremonyBody    = 64 << 10
	ceremonyTTL        = 5 * time.Minute
	maxEnrols          = 1000
)

type actorKey struct{}

// actor is who a credential write is committed for.
type actor struct {
	who  *auth.Identity
	nick string
}

type enrolInfo struct {
	identity string
	handle   []byte
	nick     string
	expires  time.Time
}

type passkeys struct {
	s     *Service
	svc   *passkey.Service // login ceremonies
	enrol *passkey.Service // registration ceremonies, with a store of their own so a flood of logins cannot evict them
	store *fileStore

	mu     sync.Mutex
	enrols map[string]enrolInfo // ceremony id -> who started it
}

func newPasskeys(s *Service) (*passkeys, error) {
	rpid := s.base.Hostname()
	uv := protocol.VerificationPreferred
	if s.o.Login.Passkeys.UserVerification == "required" {
		uv = protocol.VerificationRequired
	}
	st := &fileStore{files: s.o.Files, now: s.now}
	mk := func() (*passkey.Service, error) {
		return passkey.New(passkey.Config{
			RPID: rpid, RPDisplayName: "Rackbook", RPOrigins: []string{s.base.String()},
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
				UserVerification: uv,
			},
			UserVerification: uv,
			Credentials:      st,
			Sessions:         passkey.NewMemoryStore(passkey.DefaultSessionCapacity, passkey.DefaultSessionTTL),
			Now:              s.now,
		})
	}
	svc, err := mk()
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	enrol, err := mk()
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	return &passkeys{s: s, svc: svc, enrol: enrol, store: st, enrols: map[string]enrolInfo{}}, nil
}

// fileStore is a passkey.CredentialStore on .rackbook/passkeys.yml. Sign
// counts are not persisted (docs/design-v0.2.md, section 1).
type fileStore struct {
	files StateFiles
	now   func() time.Time
}

func (f *fileStore) load() (*pkFile, error) {
	b, _, err := f.files.StateFile(PasskeysPath)
	if err != nil {
		return nil, err
	}
	return parsePasskeys(b)
}

func toStored(u *pkUser, c *pkCred) (passkey.StoredCredential, error) {
	id, err := base64.RawURLEncoding.DecodeString(c.ID)
	if err != nil {
		return passkey.StoredCredential{}, err
	}
	pub, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
	if err != nil {
		return passkey.StoredCredential{}, err
	}
	aaguid, _ := base64.RawURLEncoding.DecodeString(c.AAGUID)
	handle, err := base64.RawURLEncoding.DecodeString(u.Handle)
	if err != nil {
		return passkey.StoredCredential{}, err
	}
	var tr []protocol.AuthenticatorTransport
	for _, t := range c.Transports {
		tr = append(tr, protocol.AuthenticatorTransport(t))
	}
	return passkey.StoredCredential{UserHandle: handle, Credential: webauthn.Credential{
		ID: id, PublicKey: pub, AttestationType: c.Type, Transport: tr,
		Flags:         webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(c.Flags)),
		Authenticator: webauthn.Authenticator{AAGUID: aaguid, Attachment: protocol.AuthenticatorAttachment(c.Attachment)},
	}}, nil
}

func (f *fileStore) FindByID(_ context.Context, credentialID []byte) (passkey.StoredCredential, error) {
	file, err := f.load()
	if err != nil {
		return passkey.StoredCredential{}, err
	}
	u, c := file.findCred(base64.RawURLEncoding.EncodeToString(credentialID))
	if c == nil {
		return passkey.StoredCredential{}, passkey.ErrCredentialNotFound
	}
	return toStored(u, c)
}

func (f *fileStore) FindByUserHandle(_ context.Context, handle []byte) ([]passkey.StoredCredential, error) {
	file, err := f.load()
	if err != nil {
		return nil, err
	}
	u := file.userByHandle(base64.RawURLEncoding.EncodeToString(handle))
	if u == nil {
		return nil, nil
	}
	var out []passkey.StoredCredential
	for i := range u.Credentials {
		sc, err := toStored(u, &u.Credentials[i])
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

// Save commits a new credential for the actor in ctx.
func (f *fileStore) Save(ctx context.Context, cred passkey.StoredCredential) error {
	a, ok := ctx.Value(actorKey{}).(actor)
	if !ok || a.who == nil || a.who.ID == "" {
		return errors.New("no acting user for the passkey")
	}
	c := cred.Credential
	var tr []string
	for _, t := range c.Transport {
		tr = append(tr, string(t))
	}
	nick := a.nick
	if nick == "" {
		nick = "Passkey " + f.now().UTC().Format("2006-01-02")
	}
	entry := pkCred{
		ID: base64.RawURLEncoding.EncodeToString(c.ID), Name: nick, Created: f.now().UTC().Format(time.RFC3339),
		PublicKey: base64.RawURLEncoding.EncodeToString(c.PublicKey), Type: c.AttestationType, Transports: tr,
		Flags: uint8(c.Flags.ProtocolValue()), AAGUID: base64.RawURLEncoding.EncodeToString(c.Authenticator.AAGUID),
		Attachment: string(c.Authenticator.Attachment),
	}
	handle := base64.RawURLEncoding.EncodeToString(cred.UserHandle)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	_, err := f.files.MutateStateFile(ctx, PasskeysPath, "rackbook(auth): add passkey for "+a.who.ID, a.who, func(old []byte, _ bool) ([]byte, error) {
		file, err := parsePasskeys(old)
		if err != nil {
			return nil, err
		}
		if _, dup := file.findCred(entry.ID); dup != nil {
			return nil, errors.New("passkey already registered")
		}
		u := file.userByHandle(handle)
		if u == nil {
			if file.userByIdentity(a.who.ID) != nil {
				return nil, errors.New("this identity already has another user handle, start again")
			}
			file.Users = append(file.Users, pkUser{Identity: a.who.ID, Name: a.who.Name, Handle: handle})
			u = &file.Users[len(file.Users)-1]
		} else if u.Identity != a.who.ID {
			return nil, errors.New("user handle belongs to another identity")
		}
		if len(u.Credentials) >= maxPasskeysPerUser {
			return nil, fmt.Errorf("at most %d passkeys per user", maxPasskeysPerUser)
		}
		u.Credentials = append(u.Credentials, entry)
		return file.marshal()
	}, gitstore.Direct())
	return err
}

// UpdateSignCount is deliberately a no-op: counters are not persisted.
func (f *fileStore) UpdateSignCount(context.Context, []byte, webauthn.Credential, time.Time) error {
	return nil
}

// credentialState reports whether a credential id is in the file. It is a
// transient error (errUnavailable) when the file is unreadable, does not load,
// or is missing while an update is in progress; a file that loads without the
// credential, or is missing at a settled commit, means it was revoked.
func (p *passkeys) credentialState(id string) (bool, error) {
	b, exists, err := p.store.files.StateFile(PasskeysPath)
	if err != nil {
		return false, errUnavailable
	}
	if !exists {
		// Missing is "no passkeys" only at a settled, loaded commit; during a
		// pull or replay it is transient.
		if p.store.files.StateSettled() {
			return false, nil
		}
		return false, errUnavailable
	}
	file, err := parsePasskeys(b)
	if err != nil {
		return false, errUnavailable
	}
	_, c := file.findCred(id)
	return c != nil, nil
}

// Responses -----------------------------------------------------------------

type passkeyOut struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

func passkeysOf(u *pkUser) []passkeyOut {
	out := []passkeyOut{}
	if u != nil {
		for _, c := range u.Credentials {
			out = append(out, passkeyOut{ID: c.ID, Name: c.Name, Created: c.Created})
		}
	}
	return out
}

func (p *passkeys) jsonBody(w http.ResponseWriter, r *http.Request) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCeremonyBody)
	return true
}

// Login ----------------------------------------------------------------------

func (p *passkeys) loginBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !p.s.limit.allow(clientip.Of(r, p.s.trusted)) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, wait a minute")
		return
	}
	assertion, id, err := p.svc.BeginDiscoverableLogin(r.Context())
	if err != nil {
		p.s.log.Error("passkey login begin failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start the passkey login")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": assertion})
}

func (p *passkeys) loginFinish(w http.ResponseWriter, r *http.Request) {
	if !p.jsonBody(w, r) {
		return
	}
	fail := func(status int, code, msg string, args ...any) {
		p.s.log.Warn("passkey login refused", append([]any{"reason", code, "remote", r.RemoteAddr}, args...)...)
		writeErr(w, status, code, msg)
	}
	refused := func(reason string, id *auth.Identity) {
		e := audit.Event{Event: "login_refused", Reason: reason, Method: auth.MethodPasskey}
		if id != nil {
			e.Identity, e.Name = id.ID, id.Name
		}
		p.s.record(r, e)
	}
	res, err := p.svc.FinishDiscoverableLogin(r.Context(), r.URL.Query().Get("ceremony"), r)
	if err != nil {
		fail(http.StatusUnauthorized, "passkey_failed", "passkey login failed", "err", sanitizeLog(err.Error()))
		refused("passkey_failed", nil)
		return
	}
	file, err := p.store.load()
	if err != nil {
		p.s.log.Error("passkey file unreadable", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "passkey_unavailable", "passkeys are unavailable: the credential file does not load")
		return
	}
	u := file.userByHandle(base64.RawURLEncoding.EncodeToString(res.UserHandle))
	if u == nil {
		fail(http.StatusUnauthorized, "passkey_failed", "passkey login failed", "err", "no user for handle")
		refused("passkey_failed", nil)
		return
	}
	id := &auth.Identity{ID: u.Identity, Name: u.Name, Method: auth.MethodPasskey}
	if strings.Contains(u.Identity, "@") {
		id.Email = u.Identity
	}
	role := p.s.roleOf(id)
	if role == roles.None {
		fail(http.StatusForbidden, "no_role", "you are not allowed to use this ledger", "identity", id.ID)
		refused("no_role", id)
		return
	}
	sess, _, err := p.s.issue(w, id, auth.MethodPasskey, base64.RawURLEncoding.EncodeToString(res.Credential.ID))
	if err != nil {
		fail(http.StatusInternalServerError, "session_too_large", "the session does not fit a cookie", "identity", id.ID)
		refused("session_too_large", id)
		return
	}
	p.s.log.Info("login", "identity", id.ID, "method", auth.MethodPasskey, "remote", r.RemoteAddr)
	p.s.record(r, audit.Event{Event: "login", Identity: id.ID, Name: id.Name, Method: auth.MethodPasskey, Role: role.String()})
	p.s.observeRole(r, id, audit.CauseSignIn, true)
	p.s.markObserved(sess)
	writeJSON(w, http.StatusOK, map[string]string{"return": SafeReturn(r.URL.Query().Get("return"))})
}

// Enrolment --------------------------------------------------------------------

// enrolGuard checks what adding a passkey needs: an editable server and an
// OIDC login within the last 10 minutes.
func (p *passkeys) enrolGuard(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	if p.s.o.ReadOnly {
		writeErr(w, http.StatusForbidden, "read_only", "the ledger is read-only")
		return nil, false
	}
	who := auth.FromContext(r.Context())
	sess, err := p.s.readSession(r)
	if who == nil || err != nil || who.Method != auth.MethodOIDC || sess.OIDCAt == 0 || p.s.now().Sub(time.Unix(sess.OIDCAt, 0)) > enrolWindow {
		writeErr(w, http.StatusForbidden, "recent_login_required", "log in again with your organisation account to add a passkey")
		return nil, false
	}
	return who, true
}

func (p *passkeys) enrolBegin(w http.ResponseWriter, r *http.Request) {
	who, ok := p.enrolGuard(w, r)
	if !ok || !p.jsonBody(w, r) {
		return
	}
	var b struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	nick := cleanName(b.Name)
	if len(nick) > 100 {
		nick = strings.ToValidUTF8(nick[:100], "")
	}
	// Refuse a nickname that is a secret before the authenticator is involved;
	// the state file write checks again.
	if sc, ok := p.s.o.Files.(interface{ SecretScanner() *secretscan.Scanner }); ok {
		if bad := sc.SecretScanner().ScanRecord(PasskeysPath, "", map[string]any{"name": nick, "user_name": who.Name}); len(bad) > 0 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "secret_detected", "message": "a possible secret was found in the passkey name; nothing was written", "findings": bad})
			return
		}
	}
	file, err := p.store.load()
	if err != nil {
		p.s.log.Error("passkey file unreadable", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "passkey_unavailable", "passkeys are unavailable: the credential file does not load")
		return
	}
	var handle []byte
	if u := file.userByIdentity(who.ID); u != nil {
		if len(u.Credentials) >= maxPasskeysPerUser {
			writeErr(w, http.StatusConflict, "too_many", fmt.Sprintf("at most %d passkeys per user", maxPasskeysPerUser))
			return
		}
		handle, _ = base64.RawURLEncoding.DecodeString(u.Handle)
	} else {
		handle = make([]byte, 32)
		if _, err := rand.Read(handle); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "no randomness")
			return
		}
	}
	display := who.Name
	if display == "" {
		display = who.ID
	}
	creation, id, err := p.enrol.BeginRegistration(r.Context(), handle, who.ID, display)
	if err != nil {
		p.s.log.Error("passkey enrol begin failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start the passkey registration")
		return
	}
	p.mu.Lock()
	now := p.s.now()
	for k, e := range p.enrols {
		if !now.Before(e.expires) {
			delete(p.enrols, k)
		}
	}
	if len(p.enrols) >= maxEnrols {
		p.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "busy", "too many registrations in progress, try again in a few minutes")
		return
	}
	p.enrols[id] = enrolInfo{identity: who.ID, handle: handle, nick: nick, expires: now.Add(ceremonyTTL)}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": creation})
}

func (p *passkeys) enrolFinish(w http.ResponseWriter, r *http.Request) {
	who, ok := p.enrolGuard(w, r)
	if !ok || !p.jsonBody(w, r) {
		return
	}
	cer := r.URL.Query().Get("ceremony")
	p.mu.Lock()
	info, found := p.enrols[cer]
	delete(p.enrols, cer)
	p.mu.Unlock()
	if !found || info.identity != who.ID || !p.s.now().Before(info.expires) {
		writeErr(w, http.StatusBadRequest, "ceremony_expired", "the registration expired, start again")
		return
	}
	ctx := context.WithValue(r.Context(), actorKey{}, actor{who: who, nick: info.nick})
	if _, err := p.enrol.FinishRegistration(ctx, info.handle, cer, r); err != nil {
		p.s.log.Warn("passkey registration failed", "identity", who.ID, "err", sanitizeLog(err.Error()))
		writeErr(w, http.StatusBadRequest, "registration_failed", "the passkey could not be registered")
		return
	}
	p.s.log.Info("passkey added", "identity", who.ID)
	file, _ := p.store.load()
	var list []passkeyOut
	if file != nil {
		list = passkeysOf(file.userByIdentity(who.ID))
	}
	writeJSON(w, http.StatusCreated, map[string]any{"passkeys": list})
}

// Removal ------------------------------------------------------------------------

func (p *passkeys) remove(w http.ResponseWriter, r *http.Request, own bool) {
	if p.s.o.ReadOnly {
		writeErr(w, http.StatusForbidden, "read_only", "the ledger is read-only")
		return
	}
	who := auth.FromContext(r.Context())
	if who == nil {
		writeErr(w, http.StatusUnauthorized, "login_required", "log in to continue")
		return
	}
	if !own && !auth.Can(r.Context(), roles.Manage) {
		writeErr(w, http.StatusForbidden, "forbidden", "only administrators may delete other people's passkeys")
		return
	}
	id := r.PathValue("id")
	file, err := p.store.load()
	if err != nil {
		p.s.log.Error("passkey file unreadable", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "passkey_unavailable", "passkeys are unavailable: the credential file does not load")
		return
	}
	owner, c := file.findCred(id)
	if c == nil || (own && owner.Identity != who.ID) {
		writeErr(w, http.StatusNotFound, "not_found", "no such passkey")
		return
	}
	target := owner.Identity
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Minute)
	defer cancel()
	_, err = p.s.o.Files.MutateStateFile(ctx, PasskeysPath, "rackbook(auth): remove passkey for "+target, who, func(old []byte, _ bool) ([]byte, error) {
		f, err := parsePasskeys(old)
		if err != nil {
			return nil, err
		}
		u, _ := f.findCred(id)
		if u == nil || (own && u.Identity != who.ID) {
			return nil, errNoSuchCredential
		}
		f.removeCred(id)
		return f.marshal()
	}, gitstore.Direct())
	switch {
	case errors.Is(err, errNoSuchCredential):
		writeErr(w, http.StatusNotFound, "not_found", "no such passkey")
	case err != nil:
		p.s.log.Error("could not remove a passkey", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "write_failed", "the passkey could not be removed: "+sanitizeLog(err.Error()))
	default:
		p.s.log.Info("passkey removed", "identity", target, "by", who.ID)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (p *passkeys) removeOwn(w http.ResponseWriter, r *http.Request) { p.remove(w, r, true) }
func (p *passkeys) removeAny(w http.ResponseWriter, r *http.Request) { p.remove(w, r, false) }

// Account and users ------------------------------------------------------------------

func (s *Service) account(w http.ResponseWriter, r *http.Request) {
	who := auth.FromContext(r.Context())
	if who == nil {
		writeErr(w, http.StatusUnauthorized, "login_required", "log in to continue")
		return
	}
	out := map[string]any{
		"id": who.ID, "name": who.Name, "email": who.Email, "role": who.EffectiveRole().String(), "auditor": who.IsAuditor(),
		"authMethod": who.Method, "passkeysEnabled": s.pk != nil, "canEnrol": false, "passkeys": []passkeyOut{},
	}
	if l := s.o.Prefs.Locale(who.ID); l != "" {
		out["locale"] = l
	}
	if s.authn != nil {
		// which kinds of entry in auth.roles and auth.auditors grant this person what they have
		rf, af := s.authn.Sources(who)
		out["roleFrom"], out["auditorFrom"] = nonNil(rf), nonNil(af)
	}
	if s.o.Infra != nil && who.Method == auth.MethodOIDC {
		// the effective /infra capability: an administrator outranks an auditor, and a name outranks a
		// claim. Only a capability that rests on a group or app role lapses, so only it has an end.
		now := s.now()
		admin, aud := s.o.Infra.Via(who, now)
		l := s.o.Infra.Admins
		if admin != "" {
			// superseded: the administrator's capability is the one in force; a named auditor
			// stays when an administrator by group or app role lapses, and the page says so
			if aud == auth.InfraViaIdentity && admin != auth.InfraViaIdentity {
				out["infraAuditorRemains"] = true
			}
			aud = ""
		} else {
			l = s.o.Infra.Auditors
		}
		if admin != "" || aud != "" {
			out["infraFrom"], out["infraAuditorFrom"] = admin, aud
			if admin != auth.InfraViaIdentity && aud != auth.InfraViaIdentity {
				out["infraEnds"] = l.ClaimEnds(who).UTC().Format(time.RFC3339)
				out["infraClaimsAbsolute"] = int(l.ClaimsAbsolute().Seconds())
			}
		}
	}
	if sess, err := s.readSession(r); err == nil && s.claimsLimited(sess) {
		// the role (or the auditor capability) was read from the claims at sign-in, so a
		// removal at the provider is seen at the next sign-in and at the latest when the session ends
		out["claimsAbsolute"] = int(s.limitOf(sess).Seconds())
		out["sessionEnds"] = time.Unix(sess.Issued, 0).Add(s.limitOf(sess)).UTC().Format(time.RFC3339)
	}
	if s.pk != nil {
		if sess, err := s.readSession(r); err == nil && sess.Method == auth.MethodOIDC && sess.OIDCAt != 0 {
			until := time.Unix(sess.OIDCAt, 0).Add(enrolWindow)
			out["enrolUntil"] = until.UTC().Format(time.RFC3339)
			out["canEnrol"] = !s.o.ReadOnly && s.now().Before(until)
		}
		if file, err := s.pk.store.load(); err != nil {
			out["passkeyError"] = "the credential file does not load"
			s.log.Error("passkey file unreadable", "err", err)
		} else {
			out["passkeys"] = passkeysOf(file.userByIdentity(who.ID))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type userOut struct {
	ID        string       `json:"id"`
	Name      string       `json:"name,omitempty"`
	Method    string       `json:"method,omitempty"`
	Role      string       `json:"role"`
	Auditor   bool         `json:"auditor,omitempty"` // on auth.auditors: a capability next to the role
	Seen      bool         `json:"seen"`
	FirstSeen *time.Time   `json:"firstSeen,omitempty"`
	LastSeen  *time.Time   `json:"lastSeen,omitempty"`
	Passkeys  []passkeyOut `json:"passkeys"`
	groups    []string     // the last groups seen (memory only), for group: entries
	appRoles  []string     // the last app roles seen (memory only), for app-role: entries
}

func (s *Service) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !auth.Can(r.Context(), roles.Manage) {
		writeErr(w, http.StatusForbidden, "forbidden", "only administrators may list users")
		return
	}
	byID := map[string]*userOut{}
	var order []string
	for _, u := range s.users.list() {
		u := u
		byID[u.ID] = &userOut{ID: u.ID, Name: u.Name, Method: u.Method, Seen: true, FirstSeen: &u.FirstSeen, LastSeen: &u.LastSeen, Passkeys: []passkeyOut{}, groups: u.Groups, appRoles: u.AppRoles}
		order = append(order, u.ID)
	}
	resp := map[string]any{"passkeysEnabled": s.pk != nil}
	if s.pk != nil {
		file, err := s.pk.store.load()
		if err != nil {
			resp["passkeyError"] = "the credential file does not load"
			s.log.Error("passkey file unreadable", "err", err)
			file = &pkFile{}
		}
		for i := range file.Users {
			u := &file.Users[i]
			e := byID[u.Identity]
			if e == nil {
				e = &userOut{ID: u.Identity, Name: u.Name, Passkeys: []passkeyOut{}}
				byID[u.Identity] = e
				order = append(order, u.Identity)
			}
			e.Passkeys = passkeysOf(u)
		}
	}
	users := make([]userOut, 0, len(order))
	for _, id := range order {
		e := byID[id]
		who := &auth.Identity{ID: e.ID, Method: auth.MethodOIDC, Email: emailOf(e.ID), Groups: e.groups, AppRoles: e.appRoles}
		if e.Method == auth.MethodLocal {
			who = &auth.Identity{ID: e.ID, Method: auth.MethodLocal}
		}
		e.Role, e.Auditor = s.roleOf(who).String(), s.auditorOf(who)
		users = append(users, *e)
	}
	resp["users"] = users
	writeJSON(w, http.StatusOK, resp)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func emailOf(id string) string {
	if strings.Contains(id, "@") {
		return id
	}
	return ""
}
