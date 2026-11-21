package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/hubstatus"
)

// The infra pages (README, "Infrastructure"): a read-only view of an Ansible +
// SOPS repository and of the infra hub's status. They are not part of the
// ledger and never appear on /mcp. Only a person named in --infra-admins who
// signed in through the OIDC login may read them; roles, API tokens and OAuth
// tokens do not count.

// InfraOptions turns the infra pages on.
type InfraOptions struct {
	Repo   *ansiblerepo.Repo
	Admins *auth.InfraAdmins
	// StatusFile is the hub's status.json (`infra-hub status -o json`), kept
	// fresh by a timer outside Rackbook. Empty = no hub status.
	StatusFile string
	// Write turns the editors on (the Repo must have a write credential). They
	// are open to the same people as the pages, and only to a session younger
	// than Admins.WriteAge().
	Write bool
	// Audit receives the actions that did not end in a commit (nil = none).
	Audit ansiblerepo.Auditor
	// RevealStatePath keeps the counts of revealed secrets across restarts
	// (a file in --state-dir; empty = memory only).
	RevealStatePath string
}

func (s *server) infraRoutes(mux *http.ServeMux) {
	if s.o.Infra == nil {
		return
	}
	mux.HandleFunc("GET /api/infra/hosts", s.infraHosts)
	mux.HandleFunc("GET /api/infra/hosts/{name}", s.infraHost)
	mux.HandleFunc("GET /api/infra/certs", s.infraCerts)
	mux.HandleFunc("GET /api/infra/iplists", s.infraIPLists)
	mux.HandleFunc("GET /api/infra/commits", s.infraCommits)
	s.infraWriteRoutes(mux)
	s.infraSecretsRoutes(mux)
}

// canInfra reports whether the caller may use the infra pages.
func (s *server) canInfra(r *http.Request) bool {
	return s.o.Infra != nil && s.o.Infra.Admins.Allows(s.who(r))
}

func (s *server) infraAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !s.canInfra(r) {
		writeError(w, http.StatusForbidden, "forbidden", "the infra pages are for the infra administrators who signed in with the console login")
		return false
	}
	return true
}

type hubOut struct {
	State      string `json:"state"`
	Error      string `json:"error,omitempty"`
	Time       string `json:"time,omitempty"`
	AgeSeconds int64  `json:"ageSeconds"`
}

func (s *server) hubSnapshot() (hubstatus.Snapshot, hubOut) {
	if s.o.Infra.StatusFile == "" {
		return hubstatus.Snapshot{State: hubstatus.StateMissing}, hubOut{State: hubstatus.StateMissing}
	}
	snap := hubstatus.Load(s.o.Infra.StatusFile, s.now())
	out := hubOut{State: snap.State, Error: snap.Error, AgeSeconds: snap.AgeSeconds}
	if !snap.Time.IsZero() {
		out.Time = snap.Time.UTC().Format(time.RFC3339)
	}
	return snap, out
}

// behind: the host's applied commit is not the commit the clone follows.
// A short hash counts only from seven characters, so "a" is not "any commit".
func behind(applied, head string) bool {
	if head == "" {
		return false
	}
	if len(applied) < 7 {
		return true
	}
	return !strings.HasPrefix(head, applied) && !strings.HasPrefix(applied, head)
}

// behindMain: the head is only trusted while the last refresh worked; after a failed one the clone may be older than
// what the hosts applied.
func behindMain(applied string, repo ansiblerepo.State) bool {
	return repo.Error == "" && behind(applied, repo.Head)
}

type infraHostOut struct {
	ansiblerepo.Host
	Features []string          `json:"features"`
	Report   *hubstatus.Report `json:"report,omitempty"`
	Behind   bool              `json:"behind"`
}

func (s *server) infraHosts(w http.ResponseWriter, r *http.Request) {
	if !s.infraAdmin(w, r) {
		return
	}
	hosts, err := s.o.Infra.Repo.HostDetails()
	if err != nil {
		s.internal(w, err)
		return
	}
	state := s.o.Infra.Repo.State()
	snap, hub := s.hubSnapshot()
	reports := map[string]*hubstatus.Report{}
	if snap.Available() {
		for _, h := range snap.Status.Hosts {
			reports[h.Name] = h.Report
		}
	}
	out := make([]infraHostOut, 0, len(hosts))
	for _, h := range hosts {
		o := infraHostOut{Host: h.Host, Features: []string{}}
		for _, f := range h.Features {
			if f.Enabled {
				o.Features = append(o.Features, f.Name)
			}
		}
		if rep := reports[h.Name]; rep != nil {
			o.Report = rep
			o.Behind = behindMain(rep.AppliedCommit, state)
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"repo": state, "hub": hub, "hosts": out})
}

func (s *server) infraHost(w http.ResponseWriter, r *http.Request) {
	if !s.infraAdmin(w, r) {
		return
	}
	d, err := s.o.Infra.Repo.Host(r.PathValue("name"))
	if errors.Is(err, ansiblerepo.ErrNoHost) {
		writeError(w, http.StatusNotFound, "not_found", "no such host")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	state := s.o.Infra.Repo.State()
	snap, hub := s.hubSnapshot()
	out := map[string]any{"repo": state, "hub": hub, "host": d, "behind": false}
	if snap.Available() {
		for _, h := range snap.Status.Hosts {
			if h.Name == d.Name && h.Report != nil {
				out["report"] = h.Report
				out["behind"] = behindMain(h.Report.AppliedCommit, state)
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) infraCerts(w http.ResponseWriter, r *http.Request) {
	if !s.infraAdmin(w, r) {
		return
	}
	snap, hub := s.hubSnapshot()
	certs := []hubstatus.Cert{}
	if snap.Available() {
		certs = append(certs, snap.Status.Certs...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"hub": hub, "certs": certs})
}

func (s *server) infraIPLists(w http.ResponseWriter, r *http.Request) {
	if !s.infraAdmin(w, r) {
		return
	}
	snap, hub := s.hubSnapshot()
	lists := []hubstatus.IPList{}
	if snap.Available() && snap.Status.IPLists != nil {
		for _, l := range snap.Status.IPLists.Lists {
			if l.Warnings == nil {
				l.Warnings = []string{}
			}
			lists = append(lists, l)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hub": hub, "lists": lists})
}

func (s *server) infraCommits(w http.ResponseWriter, r *http.Request) {
	if !s.infraAdmin(w, r) {
		return
	}
	history, err := s.o.Infra.Repo.History(r.Context(), 50)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repo": s.o.Infra.Repo.State(), "commits": history, "canRevert": s.writesOn()})
}
