package login

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/kazuhahub/rackbook/internal/api"
)

// device is a software authenticator.
type device struct {
	e    *env
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

func (e *env) newDevice() *device {
	u, _ := url.Parse(e.base)
	return &device{
		e:    e,
		rp:   virtualwebauthn.RelyingParty{Name: "Rackbook", ID: u.Hostname(), Origin: e.base},
		auth: virtualwebauthn.NewAuthenticator(),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

type ceremony struct {
	Ceremony string          `json:"ceremony"`
	Options  json.RawMessage `json:"options"`
}

// enrol runs the registration ceremony from the account page.
func (d *device) enrol(b *browser, name string) resp {
	d.e.t.Helper()
	begin := b.postJSON("/api/account/passkeys/begin", `{"name":`+jsonStr(name)+`}`)
	if begin.StatusCode != 200 {
		return begin
	}
	var c ceremony
	if err := json.Unmarshal([]byte(begin.Body), &c); err != nil {
		d.e.t.Fatal(err)
	}
	opts, err := virtualwebauthn.ParseAttestationOptions(string(c.Options))
	if err != nil {
		d.e.t.Fatal(err)
	}
	d.auth.Options.UserHandle = []byte(opts.UserID)
	body := virtualwebauthn.CreateAttestationResponse(d.rp, d.auth, d.cred, *opts)
	fin := b.postJSON("/api/account/passkeys/finish?ceremony="+url.QueryEscape(c.Ceremony), body)
	if fin.StatusCode == 201 {
		d.auth.AddCredential(d.cred)
	}
	return fin
}

// login runs a discoverable login on the login page.
func (d *device) login(b *browser, ret string) resp {
	d.e.t.Helper()
	begin := b.postJSON("/auth/passkey/begin", `{}`)
	if begin.StatusCode != 200 {
		d.e.t.Fatalf("begin: %d %s", begin.StatusCode, begin.Body)
	}
	var c ceremony
	if err := json.Unmarshal([]byte(begin.Body), &c); err != nil {
		d.e.t.Fatal(err)
	}
	opts, err := virtualwebauthn.ParseAssertionOptions(string(c.Options))
	if err != nil {
		d.e.t.Fatal(err)
	}
	body := virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *opts)
	target := "/auth/passkey/finish?ceremony=" + url.QueryEscape(c.Ceremony)
	if ret != "" {
		target += "&return=" + url.QueryEscape(ret)
	}
	return b.postJSON(target, body)
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return b2s(b) }
func b2s(b []byte) string     { return string(b) }

func TestPasskeyEnrolAndLogin(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, remote: true})
	b := e.browser()
	if r := b.get("/auth/config"); !strings.Contains(r.Body, `"passkeys":true`) {
		t.Fatalf("config: %s", r.Body)
	}
	b.login("admin", "")

	r := b.get("/api/account")
	var acc map[string]any
	_ = json.Unmarshal([]byte(r.Body), &acc)
	if acc["id"] != "kazuha@kazuha.org" || acc["role"] != "admin" || acc["authMethod"] != "oidc" || acc["canEnrol"] != true || acc["passkeysEnabled"] != true {
		t.Fatalf("account: %s", r.Body)
	}

	dev := e.newDevice()
	if fin := dev.enrol(b, "MacBook"); fin.StatusCode != 201 || !strings.Contains(fin.Body, `"MacBook"`) {
		t.Fatalf("enrol: %d %s\n%s", fin.StatusCode, fin.Body, e.logs)
	}

	// One commit on the remote, authored by the user.
	log := git(t, e.bare, "log", "-1", "--format=%an <%ae>|%cn|%B", "main")
	want := "Kazuha M <kazuha@kazuha.org>|Rackbook|rackbook(auth): add passkey for kazuha@kazuha.org\n\nEdited-by: kazuha@kazuha.org\nEdited-via: rackbook (oidc)"
	if log != want {
		t.Fatalf("commit:\n%s\nwant:\n%s", log, want)
	}
	file := git(t, e.bare, "show", "main:"+PasskeysPath)
	for _, s := range []string{"identity: kazuha@kazuha.org", "name: MacBook", "public_key:", "handle:"} {
		if !strings.Contains(file, s) {
			t.Errorf("passkeys.yml lacks %q:\n%s", s, file)
		}
	}
	if git(t, e.dir, "status", "--porcelain") != "" {
		t.Fatal("the server clone must stay clean")
	}
	commits := git(t, e.bare, "rev-list", "--count", "main")

	// Log in with the passkey on a fresh browser.
	b2 := e.browser()
	lr := dev.login(b2, "/c/devices")
	if lr.StatusCode != 200 || !strings.Contains(lr.Body, `"return":"/c/devices"`) {
		t.Fatalf("passkey login: %d %s\n%s", lr.StatusCode, lr.Body, e.logs)
	}
	_, m := b2.meta()
	u := userOf(t, m)
	if u["id"] != "kazuha@kazuha.org" || u["authMethod"] != "passkey" || u["role"] != "admin" || u["name"] != "Kazuha M" {
		t.Fatalf("user = %v", u)
	}
	// Sign counts are not persisted: logging in made no commit.
	if got := git(t, e.bare, "rev-list", "--count", "main"); got != commits {
		t.Fatalf("login created commits: %s -> %s", commits, got)
	}

	// A passkey session cannot enrol (it needs a recent OIDC login) ...
	if fin := e.newDevice().enrol(b2, "Another"); fin.StatusCode != 403 || !strings.Contains(fin.Body, "recent_login_required") {
		t.Fatalf("enrol from a passkey session: %d %s", fin.StatusCode, fin.Body)
	}
	// ... but it can open the account page.
	var acc2 map[string]any
	_ = json.Unmarshal([]byte(b2.get("/api/account").Body), &acc2)
	if acc2["authMethod"] != "passkey" || acc2["canEnrol"] != false {
		t.Fatalf("account via passkey: %v", acc2)
	}
}

func TestPasskeyEnrolNeedsARecentOIDCLogin(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true})
	b := e.browser()
	b.login("admin", "")
	e.clk.Advance(enrolWindow - time.Minute)
	if fin := e.newDevice().enrol(b, "ok"); fin.StatusCode != 201 {
		t.Fatalf("within the window: %d %s", fin.StatusCode, fin.Body)
	}
	e.clk.Advance(2 * time.Minute)
	var acc map[string]any
	_ = json.Unmarshal([]byte(b.get("/api/account").Body), &acc)
	if acc["canEnrol"] != false {
		t.Fatalf("canEnrol after the window: %v", acc)
	}
	if fin := e.newDevice().enrol(b, "late"); fin.StatusCode != 403 || !strings.Contains(fin.Body, "recent_login_required") {
		t.Fatalf("after the window: %d %s", fin.StatusCode, fin.Body)
	}
	// Logging in again with OIDC opens the window again.
	b.login("admin", "")
	if fin := e.newDevice().enrol(b, "again"); fin.StatusCode != 201 {
		t.Fatalf("after a new login: %d %s", fin.StatusCode, fin.Body)
	}
}

func TestPasskeyLoginFollowsRoles(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true})
	b := e.browser()
	b.login("editor", "")
	dev := e.newDevice()
	if fin := dev.enrol(b, "key"); fin.StatusCode != 201 {
		t.Fatalf("enrol: %d %s", fin.StatusCode, fin.Body)
	}
	b2 := e.browser()
	if r := dev.login(b2, ""); r.StatusCode != 200 {
		t.Fatalf("login: %d %s", r.StatusCode, r.Body)
	}
	if _, m := b2.meta(); userOf(t, m)["role"] != "editor" {
		t.Fatalf("role: %v", m)
	}
	// Removed from roles: the passkey no longer logs in, and the open session dies.
	e.rewriteRoles("  roles:\n    admin: [kazuha@kazuha.org]\n")
	if r := b2.get("/api/meta"); r.StatusCode != 403 {
		t.Fatalf("open session after removal: %d", r.StatusCode)
	}
	b3 := e.browser()
	if r := dev.login(b3, ""); r.StatusCode != 403 || !strings.Contains(r.Body, "no_role") || b3.cookie(SessionCookie) != nil {
		t.Fatalf("login after removal: %d %s", r.StatusCode, r.Body)
	}
}

func TestPasskeyFailures(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true})
	// An authenticator nobody enrolled.
	stranger := e.newDevice()
	stranger.auth.Options.UserHandle = []byte("whoever")
	stranger.auth.AddCredential(stranger.cred)
	b := e.browser()
	if r := stranger.login2(b); r.StatusCode != 401 || b.cookie(SessionCookie) != nil {
		t.Fatalf("unknown credential: %d %s", r.StatusCode, r.Body)
	}
	// A replayed assertion: the ceremony is gone after one use.
	owner := e.browser()
	owner.login("admin", "")
	dev := e.newDevice()
	dev.enrol(owner, "k")
	begin := e.browser().postJSON("/auth/passkey/begin", `{}`)
	var c ceremony
	_ = json.Unmarshal([]byte(begin.Body), &c)
	opts, _ := virtualwebauthn.ParseAssertionOptions(string(c.Options))
	body := virtualwebauthn.CreateAssertionResponse(dev.rp, dev.auth, dev.cred, *opts)
	b1, b2 := e.browser(), e.browser()
	if r := b1.postJSON("/auth/passkey/finish?ceremony="+url.QueryEscape(c.Ceremony), body); r.StatusCode != 200 {
		t.Fatalf("first: %d %s", r.StatusCode, r.Body)
	}
	if r := b2.postJSON("/auth/passkey/finish?ceremony="+url.QueryEscape(c.Ceremony), body); r.StatusCode != 401 {
		t.Fatalf("replay: %d %s", r.StatusCode, r.Body)
	}
	// A bad content type and an assertion for another origin.
	if r := e.browser().do("POST", "/auth/passkey/finish?ceremony="+url.QueryEscape(c.Ceremony), map[string]string{"Sec-Fetch-Site": "same-origin"}, strings.NewReader(body)); r.StatusCode != 415 {
		t.Fatalf("content type: %d", r.StatusCode)
	}
	evil := e.newDevice()
	evil.rp.Origin = "https://evil.example"
	evil.cred, evil.auth = dev.cred, dev.auth
	if r := evil.login(e.browser(), ""); r.StatusCode != 401 {
		t.Fatalf("wrong origin: %d %s", r.StatusCode, r.Body)
	}
	// Cross-site posts are refused by the write guard.
	if r := e.browser().do("POST", "/auth/passkey/begin", map[string]string{"Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"}, strings.NewReader("{}")); r.StatusCode != 403 {
		t.Fatalf("cross-site: %d", r.StatusCode)
	}
}

// login2 is login without failing the test on a refused begin.
func (d *device) login2(b *browser) resp { return d.login(b, "") }

func TestPasskeyDeleteOwnAndOthers(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, remote: true})
	admin, ed := e.browser(), e.browser()
	admin.login("admin", "")
	ed.login("editor", "")
	adminDev, edDev := e.newDevice(), e.newDevice()
	if r := adminDev.enrol(admin, "admin key"); r.StatusCode != 201 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	if r := edDev.enrol(ed, "ed key"); r.StatusCode != 201 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	// Different users get different handles.
	file, _ := os.ReadFile(filepath.Join(e.dir, PasskeysPath))
	pf, err := parsePasskeys(file)
	if err != nil || len(pf.Users) != 2 || pf.Users[0].Handle == pf.Users[1].Handle {
		t.Fatalf("file: %v %s", err, file)
	}
	// Each login resolves to the right identity.
	for dev, want := range map[*device]string{adminDev: "kazuha@kazuha.org", edDev: "ed@kazuha.org"} {
		b := e.browser()
		dev.login(b, "")
		if _, m := b.meta(); userOf(t, m)["id"] != want {
			t.Fatalf("login resolved to %v, want %s", userOf(t, m)["id"], want)
		}
	}
	edID := pf.Users[1].Credentials[0].ID
	adminID := pf.Users[0].Credentials[0].ID

	// An editor cannot delete the admin's passkey (it does not exist for them) ...
	if r := ed.do("DELETE", "/api/account/passkeys/"+adminID, map[string]string{"Sec-Fetch-Site": "same-origin"}, nil); r.StatusCode != 404 {
		t.Fatalf("editor deleting another's: %d %s", r.StatusCode, r.Body)
	}
	// ... nor use the admin endpoint.
	if r := ed.do("DELETE", "/api/admin/passkeys/"+adminID, map[string]string{"Sec-Fetch-Site": "same-origin"}, nil); r.StatusCode != 403 {
		t.Fatalf("editor on the admin endpoint: %d", r.StatusCode)
	}
	if r := ed.get("/api/admin/users"); r.StatusCode != 403 {
		t.Fatalf("editor listing users: %d", r.StatusCode)
	}

	// The admin sees everyone, with roles and passkeys.
	r := admin.get("/api/admin/users")
	var users struct {
		Users []struct {
			ID       string `json:"id"`
			Role     string `json:"role"`
			Seen     bool   `json:"seen"`
			Passkeys []struct{ ID, Name string }
		}
	}
	if err := json.Unmarshal([]byte(r.Body), &users); err != nil || len(users.Users) != 2 {
		t.Fatalf("users: %v %s", err, r.Body)
	}
	for _, u := range users.Users {
		want := map[string]string{"kazuha@kazuha.org": "admin", "ed@kazuha.org": "editor"}[u.ID]
		if u.Role != want || !u.Seen || len(u.Passkeys) != 1 {
			t.Errorf("user %+v, want role %s", u, want)
		}
	}

	// The editor deletes their own; the commit says so.
	if r := ed.do("DELETE", "/api/account/passkeys/"+edID, map[string]string{"Sec-Fetch-Site": "same-origin"}, nil); r.StatusCode != 200 {
		t.Fatalf("delete own: %d %s", r.StatusCode, r.Body)
	}
	if got := git(t, e.bare, "log", "-1", "--format=%an|%s", "main"); got != "Ed|rackbook(auth): remove passkey for ed@kazuha.org" {
		t.Fatalf("commit: %q", got)
	}
	if r := edDev.login(e.browser(), ""); r.StatusCode != 401 {
		t.Fatalf("login with a deleted passkey: %d", r.StatusCode)
	}
	// The admin deletes the admin's own through the admin endpoint; the last
	// credential removes the user entry, and the commit is by the admin.
	if r := admin.do("DELETE", "/api/admin/passkeys/"+adminID, map[string]string{"Sec-Fetch-Site": "same-origin"}, nil); r.StatusCode != 200 {
		t.Fatalf("admin delete: %d %s", r.StatusCode, r.Body)
	}
	if got := git(t, e.bare, "show", "main:"+PasskeysPath); strings.Contains(got, "identity:") {
		t.Fatalf("file should have no users left:\n%s", got)
	}
	if r := admin.do("DELETE", "/api/admin/passkeys/"+adminID, map[string]string{"Sec-Fetch-Site": "same-origin"}, nil); r.StatusCode != 404 {
		t.Fatalf("delete twice: %d", r.StatusCode)
	}
}

func TestPasskeysReadOnlyAndCorruptFile(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true, readOnly: true})
	b := e.browser()
	b.login("admin", "")
	if r := e.newDevice().enrol(b, "x"); r.StatusCode != 403 || !strings.Contains(r.Body, "read_only") {
		t.Fatalf("read-only enrol: %d %s", r.StatusCode, r.Body)
	}

	e = newEnv(t, options{passkeys: true, nogit: true})
	b = e.browser()
	b.login("admin", "")
	dev := e.newDevice()
	dev.enrol(b, "k")
	if err := os.WriteFile(filepath.Join(e.dir, PasskeysPath), []byte("users: nonsense\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := dev.login(e.browser(), ""); r.StatusCode == 200 {
		t.Fatalf("a corrupt file must not log anyone in: %d", r.StatusCode)
	}
	var acc map[string]any
	_ = json.Unmarshal([]byte(b.get("/api/account").Body), &acc)
	if acc["passkeyError"] == nil {
		t.Fatalf("the account page should report the broken file: %v", acc)
	}
}

func TestParsePasskeysSchema(t *testing.T) {
	t.Parallel()
	h := strings.Repeat("A", 43)
	h2 := strings.Repeat("B", 43)
	ok := "users:\n  - identity: a@b.c\n    handle: " + h + "\n    credentials:\n      - {id: abc, name: k, created: '2026-11-18T10:00:00Z', public_key: AAAA, flags: 5}\n"
	if f, err := parsePasskeys([]byte(ok)); err != nil || len(f.Users) != 1 {
		t.Fatalf("valid: %v", err)
	}
	if f, err := parsePasskeys(nil); err != nil || len(f.Users) != 0 {
		t.Fatalf("empty: %v", err)
	}
	cred := "      - {id: abc, name: k, created: '2026-11-18T10:00:00Z', public_key: AAAA, flags: 5}\n"
	bad := map[string]string{
		"not a mapping":      "- a\n",
		"unknown key":        ok + "extra: 1\n",
		"unknown user key":   strings.Replace(ok, "    handle:", "    admin: true\n    handle:", 1),
		"uppercase identity": strings.Replace(ok, "a@b.c", "A@B.c", 1),
		"short handle":       strings.Replace(ok, h, "AAAA", 1),
		"no credentials":     "users:\n  - identity: a@b.c\n    handle: " + h + "\n    credentials: []\n",
		"bad time":           strings.Replace(ok, "2026-11-18T10:00:00Z", "yesterday", 1),
		"flags too big":      strings.Replace(ok, "flags: 5", "flags: 300", 1),
		"dup credential":     ok + "  - identity: d@e.f\n    handle: " + h2 + "\n    credentials:\n" + cred,
		"dup identity":       ok + "  - identity: a@b.c\n    handle: " + h2 + "\n    credentials:\n      - {id: other, name: k, created: '2026-11-18T10:00:00Z', public_key: AAAA, flags: 5}\n",
		"dup handle":         ok + "  - identity: d@e.f\n    handle: " + h + "\n    credentials:\n      - {id: other, name: k, created: '2026-11-18T10:00:00Z', public_key: AAAA, flags: 5}\n",
		"bad base64":         strings.Replace(ok, "public_key: AAAA", "public_key: 'AA=='", 1),
	}
	for name, src := range bad {
		if _, err := parsePasskeys([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestDeletingAPasskeyEndsItsSessions(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true})
	owner := e.browser()
	owner.login("admin", "")
	dev := e.newDevice()
	dev.enrol(owner, "stolen laptop")
	thief := e.browser()
	if r := dev.login(thief, ""); r.StatusCode != 200 {
		t.Fatalf("login: %d %s", r.StatusCode, r.Body)
	}
	if st, _ := thief.meta(); st != 200 {
		t.Fatalf("session before revocation: %d", st)
	}
	var acc struct{ Passkeys []struct{ ID string } }
	_ = json.Unmarshal([]byte(owner.get("/api/account").Body), &acc)
	if r := owner.do("DELETE", "/api/account/passkeys/"+acc.Passkeys[0].ID, map[string]string{"Sec-Fetch-Site": "same-origin"}, nil); r.StatusCode != 200 {
		t.Fatalf("delete: %d %s", r.StatusCode, r.Body)
	}
	if st, _ := thief.meta(); st != 401 {
		t.Fatalf("a session made with a deleted passkey must end, got %d", st)
	}
	// The login page does not bounce it around either.
	if r := thief.get("/auth/login"); r.StatusCode != 200 {
		t.Fatalf("login page: %d %q", r.StatusCode, r.Loc())
	}
	// OIDC sessions are unaffected.
	if st, _ := owner.meta(); st != 200 {
		t.Fatalf("owner: %d", st)
	}
}

func TestPasskeyFileNeverGetsWrittenInvalid(t *testing.T) {
	t.Parallel()
	// Non-ASCII capitals are not folded at login, so they must be valid in the file.
	f := &pkFile{Users: []pkUser{{Identity: "\u00c4rzte@x.de", Handle: strings.Repeat("A", 43), Credentials: []pkCred{{
		ID: "abc", Name: "k", Created: "2026-11-18T10:00:00Z", PublicKey: "AAAA", Flags: 1}}}}}
	b, err := f.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePasskeys(b); err != nil {
		t.Fatal(err)
	}
	// A credential that would break the schema is refused before it is committed.
	f.Users[0].Credentials[0].ID = strings.Repeat("A", 2000)
	if _, err := f.marshal(); err == nil {
		t.Fatal("an invalid file must not be produced")
	}
	// ASCII capitals are still refused in the file (they are folded at login).
	f.Users[0].Credentials[0].ID = "abc"
	f.Users[0].Identity = "Admin@x.de"
	if _, err := f.marshal(); err == nil {
		t.Fatal("identity must be folded")
	}
}

func TestUnreadablePasskeyFileIsTransientNotRevocation(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true})
	owner := e.browser()
	owner.login("admin", "")
	dev := e.newDevice()
	dev.enrol(owner, "laptop")
	b := e.browser()
	if r := dev.login(b, ""); r.StatusCode != 200 {
		t.Fatalf("login: %d %s", r.StatusCode, r.Body)
	}
	file := filepath.Join(e.dir, PasskeysPath)
	good, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// During a pull or replay the file can be missing or half written.
	for name, mangle := range map[string]func(){
		"corrupt": func() { os.WriteFile(file, []byte("users: nonsense\n"), 0o644) },
	} {
		mangle()
		if st, _ := b.meta(); st != 503 {
			t.Fatalf("%s: want a transient 503, got %d", name, st)
		}
		os.WriteFile(file, good, 0o644)
		if st, _ := b.meta(); st != 200 {
			t.Fatalf("%s: the session (cookie kept) must work again once the file is back: %d", name, st)
		}
	}
}

func TestMissingPasskeyFileAtASettledCommitRevokes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true})
	owner := e.browser()
	owner.login("admin", "")
	dev := e.newDevice()
	dev.enrol(owner, "laptop")
	b := e.browser()
	dev.login(b, "")
	if err := os.Remove(filepath.Join(e.dir, PasskeysPath)); err != nil {
		t.Fatal(err)
	}
	if st, _ := b.meta(); st != 401 {
		t.Fatalf("no passkeys file at a settled commit means no passkeys: %d", st)
	}
}

// loginRouteClass says what each route that Service mounts is. A route that is
// not here fails the walk below until it is classified.
//
//	admin   an admin acts on anybody's object: an auditor is refused
//	own     acts on the caller's own object: another person's id is a 404
//	self    the caller's own session or ceremony; not about anybody else's object
var loginRouteClass = map[string]string{
	"POST /auth/logout":                 "self",
	"POST /auth/passkey/begin":          "self",
	"POST /auth/passkey/finish":         "self",
	"POST /api/account/passkeys/begin":  "self",
	"POST /api/account/passkeys/finish": "self",
	"DELETE /api/account/passkeys/{id}": "own",
	"DELETE /api/admin/passkeys/{id}":   "admin",
}

// An auditor with no role walks every non-GET route the login service mounts:
// the admin ones are 403, the ones on a passkey are 404 for somebody else's,
// and nothing the auditor does changes another person's credentials.
func TestAuditorCannotTouchAnotherPersonsPasskeyOnAnyLoginRoute(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, remote: true, nogit: false,
		roles: "  roles:\n    admin: [kazuha@kazuha.org]\n  auditors: [\"group:audit\"]\n"})
	e.idp.Users["editor"]["groups"] = []string{"audit"}
	admin, aud := e.browser(), e.browser()
	admin.login("admin", "")
	aud.login("editor", "")
	if _, m := aud.meta(); userOf(t, m)["auditor"] != true || userOf(t, m)["role"] != "viewer" {
		t.Fatalf("%v", m)
	}
	if r := e.newDevice().enrol(admin, "admin key"); r.StatusCode != 201 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	file, _ := os.ReadFile(filepath.Join(e.dir, PasskeysPath))
	pf, err := parsePasskeys(file)
	if err != nil || len(pf.Users) != 1 {
		t.Fatalf("%v %s", err, file)
	}
	adminKey := pf.Users[0].Credentials[0].ID

	// reading the users list is for admins; an auditor is refused
	if r := aud.get("/api/admin/users"); r.StatusCode != 403 {
		t.Fatalf("users list as an auditor: %d", r.StatusCode)
	}
	walked := 0
	seen := map[string]bool{}
	pats := api.RoutePatterns(e.apiOpts)
	// the auditor's own logout goes last: it ends the session the others use
	sort.SliceStable(pats, func(i, j int) bool { return pats[j] == "POST /auth/logout" && pats[i] != pats[j] })
	for _, pat := range pats {
		method, path, ok := strings.Cut(pat, " ")
		if !ok || method == "GET" || !(strings.HasPrefix(path, "/auth/") || strings.HasPrefix(path, "/api/account/") || strings.HasPrefix(path, "/api/admin/")) {
			continue
		}
		class := loginRouteClass[pat]
		if class == "" {
			// /api/admin/tokens, /api/admin/roles (the role editor: internal/api/roles_admin_test.go walks who may use it) and friends belong to the API: only the login service's own routes are classed here
			if strings.HasPrefix(path, "/api/admin/tokens") || strings.HasPrefix(path, "/api/admin/roles") || path == "/api/admin/accept-remote" || path == "/api/account/preferences" || strings.HasPrefix(path, "/api/account/grants") {
				continue
			}
			t.Errorf("%s is mounted by the login service and is not classified", pat)
			continue
		}
		seen[pat] = true
		walked++
		target := strings.ReplaceAll(path, "{id}", adminKey)
		r := aud.do(method, target, map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"}, strings.NewReader("{}"))
		switch class {
		case "admin":
			if r.StatusCode != 403 {
				t.Errorf("%s as an auditor: %d %s", pat, r.StatusCode, r.Body)
			}
		case "own":
			if r.StatusCode != 404 {
				t.Errorf("%s with somebody else's key: %d %s", pat, r.StatusCode, r.Body)
			}
		}
	}
	for pat := range loginRouteClass {
		if !seen[pat] {
			t.Errorf("%s is classified but is not a route", pat)
		}
	}
	if walked < len(loginRouteClass) {
		t.Fatalf("walked %d of %d", walked, len(loginRouteClass))
	}
	// the admin's key is still there
	after, _ := os.ReadFile(filepath.Join(e.dir, PasskeysPath))
	if pf2, err := parsePasskeys(after); err != nil || len(pf2.Users) != 1 || len(pf2.Users[0].Credentials) != 1 || pf2.Users[0].Credentials[0].ID != adminKey {
		t.Fatalf("an auditor changed somebody's credentials: %v %s", err, after)
	}
}
