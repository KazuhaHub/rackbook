package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/fsutil"
)

// The secrets editor (README, "Editing secrets"): the key names of a host's
// SOPS file, and revealing, replacing and deleting one value. Like the other
// editors it is open only to the infra administrators with a recent browser
// sign-in, never to API tokens, and never on /mcp. A value is returned only by
// reveal, never cached, and never written to the audit or the log.

const (
	maxSecretBody = 64 << 10
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
func (s *server) infraSecretsAudit(who *auth.Identity, host, file, action, outcome string, detail ...string) {
	if s.o.Infra == nil || s.o.Infra.Audit == nil {
		return
	}
	id := ""
	if who != nil {
		id = who.ID
	}
	s.o.Infra.Audit.Record(ansiblerepo.AuditEntry{Time: s.now(), Who: id, Action: "infra(secrets/" + host + "): " + action, Outcome: outcome, Files: []string{file}, Detail: detail})
}

// revealLimit is one ceiling on the reveals of one person.
type revealLimit struct {
	name   string
	window time.Duration
	max    int
}

// revealLimits: per person, 10 a minute, 30 an hour, 100 a day.
var revealLimits = []revealLimit{{"minute", time.Minute, 10}, {"hour", time.Hour, 30}, {"day", 24 * time.Hour, 100}}

// revealLimiter counts the reveals of each identity. With a path it keeps them
// in a file (the state directory), so a restart does not reset the counts.
type revealLimiter struct {
	Path string
	log  *slog.Logger

	mu     sync.Mutex
	at     map[string][]int64 // identity -> unix seconds of its reveals in the last day
	loaded bool
}

func (l *revealLimiter) load() {
	if l.loaded {
		return
	}
	l.loaded = true
	l.at = map[string][]int64{}
	if l.Path == "" {
		return
	}
	b, err := os.ReadFile(l.Path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && l.log != nil {
			l.log.Error("could not read the reveal counts", "path", l.Path, "err", err)
		}
		return
	}
	if err := json.Unmarshal(b, &l.at); err != nil {
		l.at = map[string][]int64{}
		if l.log != nil {
			l.log.Error("the reveal counts file is not valid; counting from zero", "path", l.Path, "err", err)
		}
	}
}

// allow records a reveal and returns "" or the name of the limit that refuses
// it (nothing is recorded then) and how long until it clears.
func (l *revealLimiter) allow(id string, now time.Time) (string, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	cutoff := now.Add(-24 * time.Hour).Unix()
	for who, ts := range l.at {
		keep := ts[:0]
		for _, t := range ts {
			if t > cutoff {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(l.at, who)
		} else {
			l.at[who] = keep
		}
	}
	for _, lim := range revealLimits {
		var in []int64
		for _, t := range l.at[id] {
			if now.Unix()-t < int64(lim.window/time.Second) {
				in = append(in, t)
			}
		}
		if len(in) >= lim.max {
			wait := time.Duration(in[0]+int64(lim.window/time.Second)-now.Unix()) * time.Second
			return lim.name, max(wait, time.Second)
		}
	}
	l.at[id] = append(l.at[id], now.Unix())
	l.save()
	return "", 0
}

func (l *revealLimiter) save() {
	if l.Path == "" {
		return
	}
	b, err := json.Marshal(l.at)
	if err == nil {
		err = fsutil.WriteFileAtomic(l.Path, b, 0o600)
	}
	if err != nil && l.log != nil {
		l.log.Error("could not save the reveal counts", "path", l.Path, "err", err)
	}
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
	if !s.secretsOn() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "canWrite": false, "publicKey": ""})
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
	// --read-only is the emergency switch: it stops reading secrets too
	if s.o.ReadOnly {
		writeError(w, http.StatusForbidden, "read_only", "secrets cannot be revealed on a read-only server")
		return
	}
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
	if hit, wait := s.reveals.allow(id, s.now()); hit != "" {
		s.infraSecretsAudit(who, host, file, action, "rate_limited", hit)
		s.log.Warn("infra secret reveal limit reached", "who", id, "limit", hit, "host", host, "key", b.Key)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many reveals this "+hit+"; try again later")
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
