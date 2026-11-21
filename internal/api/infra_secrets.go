package api

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/auth"
)

// The secrets editor (README, "Editing secrets"): the key names of a host's
// SOPS file, and revealing, replacing and deleting one value. Like the other
// editors it is open only to the infra administrators with a recent browser
// sign-in, never to API tokens, and never on /mcp. A value is returned only by
// reveal, never cached, and never written to the audit or the log.

const (
	maxSecretBody = 64 << 10
	// revealsPerMinute is how many values one administrator may reveal per minute.
	revealsPerMinute = 10
)

func (s *server) infraSecretsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/infra/hosts/{name}/secrets", s.infraSecrets)
	mux.HandleFunc("POST /api/infra/hosts/{name}/secrets/reveal", s.infraRevealSecret)
	mux.HandleFunc("POST /api/infra/hosts/{name}/secrets/set", s.infraSetSecret)
	mux.HandleFunc("POST /api/infra/hosts/{name}/secrets/unset", s.infraUnsetSecret)
}

// secretsOn: Rackbook has an age key to edit the SOPS files with.
func (s *server) secretsOn() bool { return s.o.Infra != nil && s.o.Infra.Repo.SecretsEnabled() }

// infraSecretsAudit records what was asked of one SOPS file: who, what, when and the outcome, never a value.
func (s *server) infraSecretsAudit(who *auth.Identity, host, file, action, outcome string) {
	if s.o.Infra == nil || s.o.Infra.Audit == nil {
		return
	}
	id := ""
	if who != nil {
		id = who.ID
	}
	s.o.Infra.Audit.Record(ansiblerepo.AuditEntry{Time: s.now(), Who: id, Action: "infra(secrets/" + host + "): " + action, Outcome: outcome, Files: []string{file}})
}

// revealLimiter allows revealsPerMinute reveals per identity in any minute.
type revealLimiter struct {
	mu sync.Mutex
	at map[string][]time.Time
}

func (l *revealLimiter) allow(id string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.at == nil {
		l.at = map[string][]time.Time{}
	}
	recent := l.at[id][:0]
	for _, t := range l.at[id] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= revealsPerMinute {
		l.at[id] = recent
		return false
	}
	l.at[id] = append(recent, now)
	return true
}

// infraSecretsGate admits a secrets request that changes or reveals something:
// an infra administrator with a recent sign-in, and secrets set up. needWrite
// also asks for the editors to be on (they commit).
func (s *server) infraSecretsGate(w http.ResponseWriter, r *http.Request, needWrite bool) (*auth.Identity, bool) {
	if !s.infraAdmin(w, r) {
		s.infraAudit(s.who(r), r.Method+" "+r.URL.Path, "forbidden")
		return nil, false
	}
	if !s.secretsOn() {
		writeError(w, http.StatusForbidden, "secrets_off", "editing secrets is not set up here")
		return nil, false
	}
	if needWrite && !s.writesOn() {
		writeError(w, http.StatusForbidden, "read_only", "editing the infra repository is switched off here")
		return nil, false
	}
	who := s.who(r)
	if !s.o.Infra.Admins.Fresh(who, s.now()) {
		s.infraAudit(who, r.Method+" "+r.URL.Path, "reauth_required")
		writeError(w, http.StatusForbidden, "reauth_required", "sign in again to use the secrets",
			"maxAgeSeconds", int64(s.o.Infra.Admins.WriteAge()/time.Second))
		return nil, false
	}
	return who, true
}

func (s *server) infraSecrets(w http.ResponseWriter, r *http.Request) {
	if !s.infraAdmin(w, r) {
		return
	}
	sf, err := s.o.Infra.Repo.SecretsFile(r.Context(), r.PathValue("name"))
	if err != nil {
		s.writeInfraError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"file":      sf,
		"enabled":   s.secretsOn(),
		"canWrite":  s.secretsOn() && s.writesOn(),
		"publicKey": s.o.Infra.Repo.SecretsPublicKey(),
	})
}

type secretBody struct {
	Base  string `json:"base"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

func readSecretBody(w http.ResponseWriter, r *http.Request, b *secretBody) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretBody)
	return readInfraBody(w, r, b)
}

func (s *server) infraRevealSecret(w http.ResponseWriter, r *http.Request) {
	who, ok := s.infraSecretsGate(w, r, false)
	if !ok {
		return
	}
	var b secretBody
	if !readSecretBody(w, r, &b) {
		return
	}
	repo, host := s.o.Infra.Repo, r.PathValue("name")
	file, err := repo.SecretsPath(host)
	if err != nil {
		s.writeInfraError(w, err)
		return
	}
	action := "reveal " + b.Key
	if !ansiblerepo.ValidSecretKey(b.Key) {
		writeError(w, http.StatusNotFound, "no_such_key", "no such key")
		return
	}
	id := ""
	if who != nil {
		id = who.ID
	}
	if !s.reveals.allow(id, s.now()) {
		s.infraSecretsAudit(who, host, file, action, "rate_limited")
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many reveals; wait a minute")
		return
	}
	v, err := repo.RevealSecret(r.Context(), host, b.Key)
	if err != nil {
		outcome := "reveal_failed"
		if errors.Is(err, ansiblerepo.ErrNoSecret) {
			outcome = "no_such_key"
		}
		s.infraSecretsAudit(who, host, file, action, outcome)
		s.writeInfraError(w, err)
		return
	}
	s.infraSecretsAudit(who, host, file, action, "revealed")
	// the value must not be kept by the browser, a proxy or an intermediate
	// cache: writeJSON answers with Cache-Control: no-store
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{"key": b.Key, "value": v})
}

func (s *server) infraSetSecret(w http.ResponseWriter, r *http.Request) {
	s.changeSecret(w, r, false)
}

func (s *server) infraUnsetSecret(w http.ResponseWriter, r *http.Request) {
	s.changeSecret(w, r, true)
}

// changeSecret sets or deletes one key: one commit.
func (s *server) changeSecret(w http.ResponseWriter, r *http.Request, del bool) {
	who, ok := s.infraSecretsGate(w, r, true)
	if !ok {
		return
	}
	var b secretBody
	if !readSecretBody(w, r, &b) {
		return
	}
	repo, host := s.o.Infra.Repo, r.PathValue("name")
	op := ansiblerepo.SecretOp{Key: b.Key, Value: b.Value, Delete: del}
	fe, err := repo.SecretsFileEdit(host, b.Base, []ansiblerepo.SecretOp{op})
	if err != nil {
		s.writeInfraError(w, err)
		return
	}
	e := ansiblerepo.Edit{Scope: "secrets/" + host, Action: ansiblerepo.SecretsAction([]ansiblerepo.SecretOp{op}), Who: who, Files: []ansiblerepo.FileEdit{fe}}
	s.finishEdit(w, r, e, false)
}
