package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func roleEvents(t *testing.T, dir string) []Event {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	var out []Event
	for _, f := range files {
		for _, l := range lines(t, f) {
			var e Event
			if err := json.Unmarshal(l, &e); err != nil {
				t.Fatal(err)
			}
			if e.Event == "role_changed" {
				out = append(out, e)
			}
		}
	}
	return out
}

func signIn(id, role string, auditor bool) RoleObservation {
	return RoleObservation{Identity: id, Name: "Name of " + id, Method: "oidc", Role: role, Auditor: auditor, Cause: CauseSignIn, SignedIn: true}
}

func TestIdentitiesFileIsPrivateAtomicAndKeepsNoClaims(t *testing.T) {
	clk := &fakeClock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, Options{Now: clk.Now})
	if l.ObserveRole(signIn("a@example.com", "editor", false)) {
		t.Fatal("nothing to compare with the first time")
	}
	p := filepath.Join(dir, "identities.json")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, st)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("the temp file of the atomic write must not be left behind")
	}
	var f struct {
		Version    int
		Identities map[string]IdentityRecord
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 {
		t.Fatalf("%v %s", err, b)
	}
	if r := f.Identities["a@example.com"]; r.Role != "editor" || r.Name != "Name of a@example.com" || r.Method != "oidc" || !r.LastSignIn.Equal(clk.t) || r.Auditor {
		t.Fatalf("%+v", r)
	}
	// an old file with another mode is brought to 0600 by the next write
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Hour)
	l.ObserveRole(signIn("a@example.com", "editor", false))
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("%v", st.Mode())
	}
	// the chain is untouched by the file: it verifies, and the directory has no other new file
	if r := mustVerify(t, dir); len(r.Problems) != 0 {
		t.Fatalf("%v", kinds(r))
	}
}

func TestRoleChangedAtSignInAndLazily(t *testing.T) {
	clk := &fakeClock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, Options{Now: clk.Now})
	l.ObserveRole(signIn("a@example.com", "viewer", false))
	clk.t = clk.t.Add(time.Hour)
	if !l.ObserveRole(signIn("a@example.com", "admin", true)) {
		t.Fatal("a different role and capability at sign-in is a change")
	}
	evs := roleEvents(t, dir)
	if len(evs) != 1 {
		t.Fatalf("%+v", evs)
	}
	e := evs[0]
	if e.Identity != "a@example.com" || e.From != "viewer" || e.To != "admin" || e.Cause != CauseSignIn || e.AuditorFrom == nil || *e.AuditorFrom || !*e.AuditorTo || e.Method != "oidc" {
		t.Fatalf("%+v", e)
	}
	// lazily after a config change: compared once, then the stored role is the new one
	obs := RoleObservation{Identity: "a@example.com", Name: "A", Method: "oidc", Role: "editor", Auditor: true, Cause: CauseConfig, Session: clk.t}
	if !l.ObserveRole(obs) {
		t.Fatal("expected a change")
	}
	if l.ObserveRole(obs) {
		t.Fatal("written once")
	}
	evs = roleEvents(t, dir)
	if len(evs) != 2 || evs[1].Cause != CauseConfig || evs[1].From != "admin" || evs[1].To != "editor" {
		t.Fatalf("%+v", evs)
	}
	// a lazy look does not move the last sign-in
	if got := l.Identities()[0]; !got.LastSignIn.Equal(clk.t) || got.Role != "editor" {
		t.Fatalf("%+v", got)
	}
	// somebody never seen is not created by a lazy look
	if l.ObserveRole(RoleObservation{Identity: "ghost@example.com", Role: "admin", Cause: CauseConfig}) || len(l.Identities()) != 1 {
		t.Fatalf("%+v", l.Identities())
	}
	// a session older than the person's last sign-in leaves the change to the newer one
	old := RoleObservation{Identity: "a@example.com", Role: "viewer", Cause: CauseConfig, Session: clk.t.Add(-time.Minute)}
	if l.ObserveRole(old) || l.Identities()[0].Role != "editor" {
		t.Fatal("a session from before the last sign-in must not write the role back")
	}
	// the chain still verifies
	if r := mustVerify(t, dir); len(r.Problems) != 0 {
		t.Fatalf("%v", kinds(r))
	}
}

func TestRefusedSignInStillCountsAsAChangeButNotAsASignIn(t *testing.T) {
	clk := &fakeClock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, Options{Now: clk.Now})
	l.ObserveRole(signIn("a@example.com", "editor", false))
	first := l.Identities()[0].LastSignIn
	clk.t = clk.t.Add(time.Hour)
	if !l.ObserveRole(RoleObservation{Identity: "a@example.com", Role: "none", Cause: CauseSignIn}) {
		t.Fatal("losing the role is a change")
	}
	if got := l.Identities()[0]; got.Role != "none" || !got.LastSignIn.Equal(first) {
		t.Fatalf("%+v", got)
	}
	if evs := roleEvents(t, dir); len(evs) != 1 || evs[0].To != "none" {
		t.Fatalf("%+v", evs)
	}
}

func TestIdentitiesAreBoundedAndTheOldestSignInIsEvicted(t *testing.T) {
	clk := &fakeClock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, Options{Now: clk.Now})
	l.ids.max = 5
	for i := 0; i < 8; i++ {
		clk.t = clk.t.Add(time.Minute)
		l.ObserveRole(signIn(fmt.Sprintf("u%d@example.com", i), "viewer", false))
	}
	got := l.Identities()
	if len(got) != 5 {
		t.Fatalf("%d entries", len(got))
	}
	// the newest first, and the three oldest sign-ins are the ones gone
	for i, e := range got {
		if want := fmt.Sprintf("u%d@example.com", 7-i); e.Identity != want {
			t.Fatalf("%d: %s, want %s", i, e.Identity, want)
		}
	}
	// the file holds the same five
	var f struct{ Identities map[string]IdentityRecord }
	b, _ := os.ReadFile(filepath.Join(dir, "identities.json"))
	if err := json.Unmarshal(b, &f); err != nil || len(f.Identities) != 5 {
		t.Fatalf("%v %d", err, len(f.Identities))
	}
	// somebody who signs in again is kept, and an evicted person is simply new: no event
	clk.t = clk.t.Add(time.Minute)
	l.ObserveRole(signIn("u3@example.com", "viewer", false)) // the oldest kept
	l.ObserveRole(signIn("u0@example.com", "admin", false))  // evicted earlier: a first sign-in again
	if n := len(roleEvents(t, dir)); n != 0 {
		t.Fatalf("%d events", n)
	}
	ids := map[string]bool{}
	for _, e := range l.Identities() {
		ids[e.Identity] = true
	}
	if !ids["u3@example.com"] || !ids["u0@example.com"] || ids["u4@example.com"] || len(ids) != 5 {
		t.Fatalf("%v", ids)
	}
	if MaxIdentities != 5000 {
		t.Fatalf("the documented cap is 5000, got %d", MaxIdentities)
	}
}

func TestIdentitiesSurviveARestartAndAnUnreadableFileIsSetAside(t *testing.T) {
	clk := &fakeClock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	l, dir := newLog(t, Options{Now: clk.Now})
	l.ObserveRole(signIn("a@example.com", "viewer", false))
	l.Close()
	l2, err := Open(dir, Options{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if !l2.ObserveRole(signIn("a@example.com", "editor", false)) {
		t.Fatal("the stored role must be read back after a restart")
	}
	// garbage: set aside, never deleted, and the store starts empty
	if err := os.WriteFile(filepath.Join(dir, "identities.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l3, err := Open(dir, Options{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l3.Close()
	if got := l3.Identities(); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "identities.json.unreadable")); err != nil || !strings.Contains(string(b), "not json") {
		t.Fatalf("%v %s", err, b)
	}
	// a nil log does nothing
	var nl *Log
	if nl.ObserveRole(signIn("a@example.com", "x", false)) || nl.Identities() != nil {
		t.Fatal("nil log")
	}
}
