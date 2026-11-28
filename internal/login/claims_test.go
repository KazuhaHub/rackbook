package login

import (
	"encoding/json"
	"fmt"
	"github.com/kazuhahub/rackbook/internal/roles"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

const claimRoles = "  roles:\n    admin: [\"group:ops\", \"app-role:Rackbook.Admin\"]\n    viewer: [\"*@kazuha.org\"]\n"

// kinds returns the events of one kind, oldest first.
func (e *env) kinds(kind string) []audit.Event {
	e.t.Helper()
	var out []audit.Event
	for _, ev := range e.events() {
		if ev.Event == kind {
			out = append(out, ev)
		}
	}
	return out
}

func roleOfMeta(t *testing.T, b *browser) string {
	t.Helper()
	st, m := b.meta()
	if st != 200 {
		t.Fatalf("meta: %d", st)
	}
	return userOf(t, m)["role"].(string)
}

func TestAppRoleClaimGrantsARole(t *testing.T) {
	e := newEnv(t, options{roles: claimRoles})
	e.idp.Users["admin"]["roles"] = []string{"Viewer", "Rackbook.Admin"}
	b := e.browser()
	if r := b.login("admin", ""); r.StatusCode != 303 {
		t.Fatalf("%d", r.StatusCode)
	}
	if got := roleOfMeta(t, b); got != "admin" {
		t.Fatalf("an app role must give an app-role: entry its role: %s", got)
	}
	// Matching is exact and case-sensitive, like Entra app role values.
	e.idp.Users["editor"]["roles"] = []string{"rackbook.admin", "RACKBOOK.ADMIN"}
	b2 := e.browser()
	b2.login("editor", "")
	if got := roleOfMeta(t, b2); got != "viewer" {
		t.Fatalf("app roles must match case-sensitively: %s", got)
	}
	// Only the top-level roles claim is read: Keycloak's resource_access is not.
	e.idp.Users["plain"] = map[string]any{"sub": "sub-p", "preferred_username": "plain@kazuha.org", "name": "Plain", "tid": tenant,
		"resource_access": map[string]any{"rackbook": map[string]any{"roles": []string{"Rackbook.Admin"}}}}
	b3 := e.browser()
	b3.login("plain", "")
	if got := roleOfMeta(t, b3); got != "viewer" {
		t.Fatalf("resource_access must not be read: %s", got)
	}
	// A group id does not match an app-role entry and the reverse.
	e.idp.Users["nobody"]["groups"] = []string{"Rackbook.Admin"}
	e.idp.Users["nobody"]["roles"] = []string{"ops"}
	if r := e.browser().login("nobody", ""); r.Loc() != "/auth/login?error=no_role" {
		t.Fatalf("a group is not an app role: %d %q", r.StatusCode, r.Loc())
	}
}

func TestAppRoleOnAuditors(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org]\n  auditors: [\"app-role:Rackbook.Auditor\"]\n"})
	e.idp.Users["editor"]["roles"] = []string{"Rackbook.Auditor"}
	b := e.browser()
	b.login("editor", "")
	_, m := b.meta()
	if u := userOf(t, m); u["role"] != "viewer" || u["auditor"] != true {
		t.Fatalf("an auditor by app role gets the viewer floor and the capability: %v", u)
	}
}

func TestSessionKeepsGroupsAndAppRolesWithinTheCookie(t *testing.T) {
	// 20 GUIDs fill the groups budget, 22 long role values the roles budget: both lists at their cap,
	// and the cookie must still be one the browser stores and the server accepts.
	var groups, appRoles []string
	for i := 0; i < 20; i++ {
		groups = append(groups, fmt.Sprintf("%08d-aaaa-bbbb-cccc-%012d", i, i))
	}
	groups = append(groups, "ops") // past the 700 bytes: must not matter
	for i := 0; i < 22; i++ {
		appRoles = append(appRoles, fmt.Sprintf("Rackbook.Some.Long.Role.Value.%02d", i))
	}
	e := newEnv(t, options{roles: claimRoles})
	e.idp.Users["admin"]["groups"] = groups
	e.idp.Users["admin"]["roles"] = append(appRoles, "Rackbook.Admin")
	b := e.browser()
	b.login("admin", "")
	if got := roleOfMeta(t, b); got != "viewer" {
		t.Fatalf("values past the cap are ignored: %s", got)
	}
	if n := len(b.cookie(SessionCookie).Value); n > maxCookieBytes || n > 3700 {
		t.Fatalf("the cookie is %d bytes", n)
	}
}

// setCookieLens are the lengths of the whole Set-Cookie headers of a response for the session cookie.
func setCookieLens(r resp) []int {
	var out []int
	for _, c := range r.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, SessionCookie+"=") {
			out = append(out, len(c))
		}
	}
	return out
}

// Worst case: the longest name and identity made of characters JSON escapes, and both lists at
// their limit made of quotes. Every Set-Cookie header, at sign-in and on refresh, fits the limit.
func TestSessionCookieAlwaysFitsTheLimit(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    viewer: [\"*\"]\n"})
	quotes := strings.Repeat(`"`, 100)
	var groups, appRoles []string
	for i := 0; i < 8; i++ {
		groups = append(groups, quotes+fmt.Sprint(i))
		appRoles = append(appRoles, quotes+fmt.Sprint(i))
	}
	e.idp.Users["admin"] = map[string]any{"sub": "s", "preferred_username": strings.Repeat(`"`, 310) + "@x.org", "name": strings.Repeat(`&"\`, 66),
		"tid": tenant, "groups": groups, "roles": appRoles}
	b := e.browser()
	r := b.login("admin", "")
	if r.StatusCode != 303 || r.Loc() != "/" {
		t.Fatalf("%d %q\n%s", r.StatusCode, r.Loc(), e.logs.String())
	}
	lens := setCookieLens(r)
	if len(lens) == 0 {
		t.Fatal("no session cookie")
	}
	e.clk.Advance(10 * time.Minute)
	rr := b.get("/api/meta") // a refresh of the cookie
	lens = append(lens, setCookieLens(rr)...)
	for _, n := range lens {
		if n > maxSetCookieBytes {
			t.Fatalf("a Set-Cookie header of %d bytes", n)
		}
	}
	if st, _ := b.meta(); st != 200 {
		t.Fatalf("the cookie must be accepted: %d", st)
	}
}

// When the cookie is too long, claim values go, last first from the longer list, and the sign-in
// says so; when even empty lists do not fit the sign-in is refused with a reason, never a loop.
func TestSessionCookieDropsClaimsThenRefuses(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    viewer: [\"*\"]\n    admin: [\"group:g0\"]\n"})
	var groups, appRoles []string
	for i := 0; i < 10; i++ {
		groups = append(groups, fmt.Sprintf("g%d-%s", i, strings.Repeat("x", 60)))
		appRoles = append(appRoles, fmt.Sprintf("r%d-%s", i, strings.Repeat("y", 60)))
	}
	e.idp.Users["admin"]["groups"] = groups
	e.idp.Users["admin"]["roles"] = appRoles
	r := e.browser().login("admin", "") // the full size
	fullLen := setCookieLens(r)[0]
	old := maxSetCookieBytes
	defer func() { maxSetCookieBytes = old }()
	maxSetCookieBytes = fullLen - 300
	b := e.browser()
	r = b.login("admin", "")
	if r.StatusCode != 303 || r.Loc() != "/" {
		t.Fatalf("%d %q", r.StatusCode, r.Loc())
	}
	if n := setCookieLens(r)[0]; n > maxSetCookieBytes {
		t.Fatalf("%d > %d", n, maxSetCookieBytes)
	}
	sess, err := e.svc.codec.open(b.cookie(SessionCookie).Value)
	if err != nil || len(sess.Groups)+len(sess.Roles) >= 20 || len(sess.Groups) == 0 && len(sess.Roles) == 0 {
		t.Fatalf("%v %d groups %d roles", err, len(sess.Groups), len(sess.Roles))
	}
	// the longer list loses first: neither is emptied while the other is as long
	if d := len(sess.Groups) - len(sess.Roles); d > 1 || d < -1 {
		t.Fatalf("%d groups %d roles", len(sess.Groups), len(sess.Roles))
	}
	// the first values are kept
	if sess.Groups[0] != groups[0] || sess.Roles[0] != appRoles[0] {
		t.Fatalf("%v %v", sess.Groups, sess.Roles)
	}
	if ev := e.kinds("login"); ev[len(ev)-1].Groups != "overage" || ev[len(ev)-1].AppRoles != "overage" {
		t.Fatalf("the login event must say the lists were cut: %+v", ev[len(ev)-1])
	}
	// nothing fits
	maxSetCookieBytes = 100
	r = e.browser().login("admin", "")
	if r.Loc() != "/auth/login?error=session_too_large" {
		t.Fatalf("%d %q", r.StatusCode, r.Loc())
	}
	if ev := e.last(); ev.Event != "login_refused" || ev.Reason != "session_too_large" || ev.Identity == "" {
		t.Fatalf("%+v", ev)
	}
	if len(setCookieLens(r)) != 0 {
		t.Fatal("no session cookie may be sent")
	}
}

func TestBoundAppRolesKeepValuesExactly(t *testing.T) {
	out, cut := boundAppRoles([]string{" Padded ", "Rackbook.Admin", "", "   "})
	if cut || len(out) != 2 || out[0] != " Padded " || out[1] != "Rackbook.Admin" {
		t.Fatalf("%q cut %v", out, cut)
	}
	var many []string
	for i := 0; i < 100; i++ {
		many = append(many, fmt.Sprintf("role-%d", i))
	}
	out, cut = boundAppRoles(many)
	if !cut || len(out) != roles.MaxClaimValues {
		t.Fatalf("%d values, cut %v", len(out), cut)
	}
}

func TestGroupOverageSignals(t *testing.T) {
	var many []string
	for i := 0; i < 60; i++ {
		many = append(many, fmt.Sprintf("g%02d", i))
	}
	for name, tc := range map[string]struct {
		claims  map[string]any
		role    string // the role after sign-in; "" = refused
		overage bool
	}{
		"within the cap":                         {map[string]any{"groups": []string{"ops"}}, "admin", false},
		"entra _claim_names":                     {map[string]any{"_claim_names": map[string]any{"groups": "src1"}, "_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.example/users/x/getMemberObjects"}}}, "viewer", true},
		"entra hasgroups":                        {map[string]any{"hasgroups": true}, "viewer", true},
		"hasgroups as string":                    {map[string]any{"hasgroups": "true"}, "viewer", true},
		"hasgroups false":                        {map[string]any{"hasgroups": false, "groups": []string{"ops"}}, "admin", false},
		"other claim names":                      {map[string]any{"_claim_names": map[string]any{"other": "src1"}, "_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.example/x"}}, "groups": []string{"ops"}}, "admin", false},
		"overage with some groups still present": {map[string]any{"hasgroups": true, "groups": []string{"ops"}}, "viewer", true},
		"past 40 values, first kept":             {map[string]any{"groups": append([]string{"ops"}, many...)}, "admin", true},
		"past 40 values, wanted one cut off":     {map[string]any{"groups": append(append([]string{}, many...), "ops")}, "viewer", true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, options{roles: claimRoles, nogit: true})
			for k, v := range tc.claims {
				e.idp.Users["admin"][k] = v
			}
			b := e.browser()
			if r := b.login("admin", ""); r.StatusCode != 303 || r.Loc() != "/" {
				t.Fatalf("the sign-in must succeed: %d %q\n%s", r.StatusCode, r.Loc(), e.logs.String())
			}
			if got := roleOfMeta(t, b); got != tc.role {
				t.Fatalf("role %s, want %s", got, tc.role)
			}
			ev := e.kinds("login")[0]
			want := ""
			if tc.overage {
				want = "overage"
			}
			if ev.Groups != want || ev.AppRoles != "" {
				t.Fatalf("the login event must carry groups: %q: %+v", want, ev)
			}
		})
	}
}

func TestGroupOverageWithOnlyGroupRolesRefusesWithTheNoteAndNoRole(t *testing.T) {
	// Entra's overage leaves a group-only person without a role: the sign-in is refused,
	// and the refusal says why.
	e := newEnv(t, options{roles: "  roles:\n    admin: [\"group:ops\"]\n", nogit: true})
	e.idp.Users["admin"]["hasgroups"] = true
	if r := e.browser().login("admin", ""); r.Loc() != "/auth/login?error=no_role" {
		t.Fatalf("%d %q", r.StatusCode, r.Loc())
	}
	if ev := e.last(); ev.Event != "login_refused" || ev.Reason != "no_role" || ev.Groups != "overage" {
		t.Fatalf("%+v", ev)
	}
	if !strings.Contains(e.logs.String(), "more groups or app roles") {
		t.Fatalf("the server log must say so:\n%s", e.logs.String())
	}
}

func TestAppRoleOverage(t *testing.T) {
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, fmt.Sprintf("Role.%02d", i))
	}
	e := newEnv(t, options{roles: claimRoles, nogit: true})
	e.idp.Users["admin"]["roles"] = many
	b := e.browser()
	b.login("admin", "")
	ev := e.kinds("login")[0]
	if ev.AppRoles != "overage" || ev.Groups != "" || ev.Role != "viewer" {
		t.Fatalf("%+v", ev)
	}
	raw, _ := json.Marshal(ev)
	if !strings.Contains(string(raw), `"app_roles":"overage"`) {
		t.Fatalf("%s", raw)
	}
	// both at once
	e2 := newEnv(t, options{roles: claimRoles, nogit: true})
	e2.idp.Users["admin"]["roles"] = many
	e2.idp.Users["admin"]["hasgroups"] = true
	e2.browser().login("admin", "")
	if ev := e2.kinds("login")[0]; ev.AppRoles != "overage" || ev.Groups != "overage" {
		t.Fatalf("%+v", ev)
	}
}

// auth.passkeys beside an OIDC provider is ignored: a warning at start, every passkey
// route refuses, and the login page and the account page know there are none.
func TestPasskeysAreIgnoredUnderOIDC(t *testing.T) {
	e := newEnv(t, options{passkeysIgnored: true, nogit: true})
	if !strings.Contains(e.logs.String(), "auth.passkeys is ignored") {
		t.Fatalf("no warning at start:\n%s", e.logs.String())
	}
	b := e.browser()
	var cfg map[string]any
	_ = json.Unmarshal([]byte(b.get("/auth/config").Body), &cfg)
	if cfg["passkeys"] != false {
		t.Fatalf("the login page must not offer passkeys: %v", cfg)
	}
	// the routes refuse, signed in or not
	for _, tc := range []struct{ method, path string }{
		{"POST", "/auth/passkey/begin"}, {"POST", "/auth/passkey/finish"},
	} {
		r := b.do(tc.method, tc.path, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}, strings.NewReader("{}"))
		if r.StatusCode != 403 || !strings.Contains(r.Body, "passkey_sso") {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, r.StatusCode, r.Body)
		}
	}
	b.login("admin", "")
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/account/passkeys/begin"}, {"POST", "/api/account/passkeys/finish?ceremony=x"},
		{"DELETE", "/api/account/passkeys/abc"}, {"DELETE", "/api/admin/passkeys/abc"},
	} {
		r := b.do(tc.method, tc.path, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}, strings.NewReader("{}"))
		if r.StatusCode != 403 || !strings.Contains(r.Body, "passkey_sso") {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, r.StatusCode, r.Body)
		}
	}
	var acc map[string]any
	_ = json.Unmarshal([]byte(b.get("/api/account").Body), &acc)
	if acc["passkeysEnabled"] != false || acc["canEnrol"] != false || acc["authMethod"] != "oidc" {
		t.Fatalf("%v", acc)
	}
	if _, err := os.Stat(filepath.Join(e.dir, ".rackbook", "passkeys.yml")); err == nil {
		t.Fatal("nothing may be written")
	}
	// without auth.passkeys there are no passkey routes at all
	e2 := newEnv(t, options{nogit: true})
	b2 := e2.browser()
	if r := b2.postJSON("/auth/passkey/begin", "{}"); r.StatusCode == 403 && strings.Contains(r.Body, "passkey_sso") {
		t.Fatalf("no routes expected: %d", r.StatusCode)
	}
}

// A session whose role came from claims lives claims_absolute (24h by default); a role an
// identity entry grants keeps the normal limit, even when a group entry also matches.
func TestClaimsAbsoluteAppliesOnlyToClaimDerivedRoles(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [\"group:eng\", ed@kazuha.org]\n    viewer: [guest@example.com]\n"})
	e.idp.Users["admin"]["groups"] = []string{"eng"}  // identity admin, group editor: the identity wins
	e.idp.Users["editor"]["groups"] = []string{"eng"} // identity editor and group editor: the identity wins
	e.idp.Users["viewer"]["groups"] = []string{"eng"} // identity viewer, group editor: the role is from the group
	users := map[string]*browser{}
	for _, u := range []string{"admin", "editor", "viewer"} {
		users[u] = e.browser()
		users[u].login(u, "")
	}
	for u, want := range map[string]bool{"admin": false, "editor": false, "viewer": true} {
		sess, err := e.svc.codec.open(users[u].cookie(SessionCookie).Value)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.svc.claimsLimited(sess); got != want {
			t.Fatalf("%s: claims-limited %v, want %v", u, got, want)
		}
	}
	alive := func(u string) bool { st, _ := users[u].meta(); return st == 200 }
	step := func(d time.Duration) {
		for left := d; left > 0; left -= 5 * time.Hour { // activity keeps the 12 h idle limit away
			e.clk.Advance(min(left, 5*time.Hour))
			for u := range users {
				alive(u)
			}
		}
	}
	step(23 * time.Hour)
	for u := range users {
		if !alive(u) {
			t.Fatalf("%s must still be signed in after 23h", u)
		}
	}
	step(2 * time.Hour)
	if alive("viewer") {
		t.Fatal("a session whose role came from a group must end after claims_absolute (24h)")
	}
	if !alive("admin") || !alive("editor") {
		t.Fatal("a role from an identity entry keeps the normal limit")
	}
	step(5 * 24 * time.Hour)
	if !alive("admin") {
		t.Fatal("still inside 7 days")
	}
	step(2 * 24 * time.Hour)
	if alive("admin") || alive("editor") {
		t.Fatal("the normal absolute limit still applies")
	}
}

func TestClaimsAbsoluteIsConfigurable(t *testing.T) {
	e := newEnv(t, options{nogit: true, session: "    claims_absolute: 2h\n", roles: "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [\"app-role:Eng\"]\n"})
	e.idp.Users["editor"]["roles"] = []string{"Eng"}
	b := e.browser()
	b.login("editor", "")
	e.clk.Advance(100 * time.Minute)
	if st, _ := b.meta(); st != 200 {
		t.Fatalf("%d", st)
	}
	e.clk.Advance(30 * time.Minute)
	if st, _ := b.meta(); st != 401 {
		t.Fatalf("an app-role session must end after claims_absolute: %d", st)
	}
}

func TestAccountSaysWhereTheRoleComesFrom(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [\"app-role:Eng\", \"group:eng\"]\n    viewer: [guest@example.com]\n  auditors: [\"group:audit\"]\n"})
	e.idp.Users["admin"]["roles"] = []string{"Eng"}
	e.idp.Users["editor"]["roles"] = []string{"Eng"}
	e.idp.Users["editor"]["groups"] = []string{"eng", "audit"}
	acct := func(user string) map[string]any {
		b := e.browser()
		b.login(user, "")
		var m map[string]any
		if err := json.Unmarshal([]byte(b.get("/api/account").Body), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	a := acct("admin")
	if fmt.Sprint(a["roleFrom"]) != "[identity]" || a["claimsAbsolute"] != nil {
		t.Fatalf("an identity entry: %v", a)
	}
	ed := acct("editor")
	if fmt.Sprint(ed["roleFrom"]) != "[app-role group]" || fmt.Sprint(ed["auditorFrom"]) != "[group]" || ed["claimsAbsolute"] != float64(24*3600) || ed["sessionEnds"] == nil {
		t.Fatalf("claims: %v", ed)
	}
	if v := acct("viewer"); fmt.Sprint(v["roleFrom"]) != "[identity]" {
		t.Fatalf("%v", v)
	}
}

// identities.json and role_changed ---------------------------------------------------

func (e *env) identitiesFile() map[string]any {
	e.t.Helper()
	p := filepath.Join(e.audit, "identities.json")
	st, err := os.Stat(p)
	if err != nil {
		e.t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		e.t.Fatalf("identities.json has mode %v", st.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		e.t.Fatalf("%v: %s", err, b)
	}
	return m
}

func TestIdentitiesFileAndRoleChangedAtSignIn(t *testing.T) {
	const before = "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [\"group:eng\"]\n"
	e := newEnv(t, options{nogit: true, roles: before})
	e.idp.Users["editor"]["groups"] = []string{"eng", "secret-group"}
	e.idp.Users["editor"]["roles"] = []string{"Some.Role"}
	b := e.browser()
	b.login("editor", "")
	if n := len(e.kinds("role_changed")); n != 0 {
		t.Fatalf("a first sign-in has nothing to be compared with: %d events", n)
	}
	m := e.identitiesFile()
	ids := m["identities"].(map[string]any)
	rec := ids["ed@kazuha.org"].(map[string]any)
	if rec["role"] != "editor" || rec["method"] != "oidc" || rec["name"] != "Ed" || rec["lastSignIn"] == nil {
		t.Fatalf("%v", rec)
	}
	raw, _ := os.ReadFile(filepath.Join(e.audit, "identities.json"))
	for _, forbidden := range []string{"eng", "secret-group", "Some.Role", "groups", "roles\":["} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("identities.json must keep no groups and no claims (%q):\n%s", forbidden, raw)
		}
	}
	// claims differ at the next sign-in: the group is gone, the role with it. The person
	// is refused (no role), which is a change all the same.
	e.idp.Users["editor"]["groups"] = []string{"other"}
	e.browser().login("editor", "")
	evs := e.kinds("role_changed")
	if len(evs) != 1 {
		t.Fatalf("%+v", evs)
	}
	ev := evs[0]
	if ev.Identity != "ed@kazuha.org" || ev.From != "editor" || ev.To != "none" || ev.Cause != audit.CauseSignIn ||
		ev.AuditorFrom == nil || ev.AuditorTo == nil || *ev.AuditorFrom || *ev.AuditorTo {
		t.Fatalf("%+v", ev)
	}
	// and they come back with the group: none -> editor
	e.idp.Users["editor"]["groups"] = []string{"eng"}
	e.browser().login("editor", "")
	evs = e.kinds("role_changed")
	if len(evs) != 2 || evs[1].From != "none" || evs[1].To != "editor" || evs[1].Cause != audit.CauseSignIn {
		t.Fatalf("%+v", evs)
	}
	// the same sign-in again changes nothing
	e.browser().login("editor", "")
	if n := len(e.kinds("role_changed")); n != 2 {
		t.Fatalf("%d", n)
	}
}

func TestRoleChangedLazilyAfterAConfigChange(t *testing.T) {
	eachStore(t, func(t *testing.T, o options) {
		const before = "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [ed@kazuha.org]\n    viewer: [guest@example.com]\n"
		o.roles = before
		e := newEnv(t, o)
		ed, guest := e.browser(), e.browser()
		ed.login("editor", "")
		guest.login("viewer", "")
		for i := 0; i < 3; i++ {
			ed.meta()
			guest.meta()
		}
		if n := len(e.kinds("role_changed")); n != 0 {
			t.Fatalf("nothing changed: %d", n)
		}
		// rackbook.yml changes: ed is demoted, guest is promoted. Nobody has asked for anything yet.
		e.setRoles("  roles:\n    admin: [kazuha@kazuha.org, guest@example.com]\n    viewer: [ed@kazuha.org]\n")
		if n := len(e.kinds("role_changed")); n != 0 {
			t.Fatalf("it is lazy: %d events before anybody comes back", n)
		}
		// ed comes back (three requests); guest never does
		for i := 0; i < 3; i++ {
			if got := roleOfMeta(t, ed); got != "viewer" {
				t.Fatal(got)
			}
		}
		evs := e.kinds("role_changed")
		if len(evs) != 1 {
			t.Fatalf("written once, only for the person who came back: %+v", evs)
		}
		if ev := evs[0]; ev.Identity != "ed@kazuha.org" || ev.From != "editor" || ev.To != "viewer" || ev.Cause != audit.CauseConfig {
			t.Fatalf("%+v", ev)
		}
		// the stored role moved on, so a sign-in afterwards writes nothing again
		e.browser().login("editor", "")
		if n := len(e.kinds("role_changed")); n != 1 {
			t.Fatalf("%d", n)
		}
		rec := e.identitiesFile()["identities"].(map[string]any)
		if rec["ed@kazuha.org"].(map[string]any)["role"] != "viewer" || rec["guest@example.com"].(map[string]any)["role"] != "viewer" {
			t.Fatalf("people who never come back are not recomputed: %v", rec)
		}
		// guest returns later, after another change: only then is the difference seen
		guest.meta()
		evs = e.kinds("role_changed")
		if len(evs) != 2 || evs[1].Identity != "guest@example.com" || evs[1].From != "viewer" || evs[1].To != "admin" || evs[1].Cause != audit.CauseConfig {
			t.Fatalf("%+v", evs)
		}
	})
}

func TestRoleChangedFollowsTheAuditorFlag(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [ed@kazuha.org]\n"})
	b := e.browser()
	b.login("editor", "")
	e.rewriteRoles("  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [ed@kazuha.org]\n  auditors: [ed@kazuha.org]\n")
	b.meta()
	evs := e.kinds("role_changed")
	if len(evs) != 1 {
		t.Fatalf("%+v", evs)
	}
	if ev := evs[0]; ev.From != "editor" || ev.To != "editor" || ev.AuditorFrom == nil || *ev.AuditorFrom || ev.AuditorTo == nil || !*ev.AuditorTo || ev.Cause != audit.CauseConfig {
		t.Fatalf("%+v", ev)
	}
}

func TestRoleChangedStaysQuietWhileTheConfigDoesNotLoad(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [ed@kazuha.org]\n"})
	b := e.browser()
	b.login("editor", "")
	p := filepath.Join(e.dir, "rackbook.yml")
	good, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte("collections: [not valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.meta() // degraded: roles are capped at viewer, which says nothing about the person
	if n := len(e.kinds("role_changed")); n != 0 {
		t.Fatalf("a degraded config must not write role_changed: %d", n)
	}
	if err := os.WriteFile(p, good, 0o644); err != nil {
		t.Fatal(err)
	}
	b.meta()
	if n := len(e.kinds("role_changed")); n != 0 {
		t.Fatalf("the config is back as it was: %d", n)
	}
}

func TestIdentitiesAPIVisibility(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [ed@kazuha.org]\n    viewer: [guest@example.com]\n  auditors: [\"group:audit\"]\n"})
	e.idp.Users["viewer"]["groups"] = []string{"audit"} // guest is a viewer and an auditor
	e.idp.Users["nobody"]["groups"] = []string{"audit"} // an auditor with no role at all: the viewer floor
	get := func(user string) (int, map[string]any) {
		e.clk.Advance(time.Second)
		b := e.browser()
		b.login(user, "")
		r := b.get("/api/audit/identities")
		var m map[string]any
		_ = json.Unmarshal([]byte(r.Body), &m)
		return r.StatusCode, m
	}
	if st, _ := get("editor"); st != 403 {
		t.Fatalf("an editor must not see the identities: %d", st)
	}
	st, m := get("admin")
	if st != 200 || m["enabled"] != true {
		t.Fatalf("%d %v", st, m)
	}
	list := m["identities"].([]any)
	if len(list) != 2 { // editor and admin had signed in by then
		t.Fatalf("%v", list)
	}
	first := list[0].(map[string]any)
	if first["identity"] != "kazuha@kazuha.org" || first["role"] != "admin" || first["method"] != "oidc" || first["lastSignIn"] == nil {
		t.Fatalf("most recent first: %v", first)
	}
	for _, k := range []string{"groups", "claims", "roles"} {
		if _, has := first[k]; has {
			t.Fatalf("no %s may be listed: %v", k, first)
		}
	}
	if st, _ := get("viewer"); st != 200 {
		t.Fatalf("an auditor sees the sign-in identities, as they see the sign-in events: %d", st)
	}
	if st, _ := get("nobody"); st != 200 {
		t.Fatalf("%d", st)
	}
	// the unauthenticated and API tokens see nothing
	if r := e.browser().get("/api/audit/identities"); r.StatusCode != 401 {
		t.Fatalf("%d", r.StatusCode)
	}
}

// Tokens ------------------------------------------------------------------------------

func TestTokenCreationIsRefusedWhenTheRoleComesOnlyFromClaims(t *testing.T) {
	e := newEnv(t, options{roles: "  roles:\n    admin: [kazuha@kazuha.org, \"group:ops\", \"app-role:Rackbook.Admin\"]\n    editor: [ed@kazuha.org]\n    viewer: [\"viewer@kazuha.org\"]\n"})
	create := func(b *browser, name, scope string) resp {
		return b.postJSON("/api/admin/tokens", `{"name":"`+name+`","scope":"`+scope+`"}`)
	}
	user := func(key, mail string, claims map[string]any) {
		c := map[string]any{"sub": "sub-" + key, "preferred_username": mail, "name": key, "tid": tenant}
		for k, v := range claims {
			c[k] = v
		}
		e.idp.Users[key] = c
	}
	user("bygroup", "g@kazuha.org", map[string]any{"groups": []string{"ops"}})
	user("byrole", "r@kazuha.org", map[string]any{"roles": []string{"Rackbook.Admin"}})
	user("mixed", "viewer@kazuha.org", map[string]any{"groups": []string{"ops"}}) // viewer by name, admin by group
	for _, key := range []string{"bygroup", "byrole"} {
		b := e.browser()
		b.login(key, "")
		if got := roleOfMeta(t, b); got != "admin" {
			t.Fatalf("%s: %s", key, got)
		}
		r := create(b, "t-"+key, "read")
		if r.StatusCode != 403 || !strings.Contains(r.Body, `"creator_role_from_claims"`) {
			t.Fatalf("%s: %d %s", key, r.StatusCode, r.Body)
		}
	}
	// viewer by name: a read token follows that entry, a write token would not get the editor role it asks for
	bm := e.browser()
	bm.login("mixed", "")
	if r := create(bm, "mixed-write", "write"); r.StatusCode != 403 || !strings.Contains(r.Body, `"creator_role_from_claims"`) {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	if r := create(bm, "mixed-read", "read"); r.StatusCode != 201 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	// editor by name, admin by group: a write token is fine, a push token needs admin by identity
	user("pusher", "ed@kazuha.org", map[string]any{"groups": []string{"ops"}})
	bp := e.browser()
	bp.login("pusher", "")
	if r := bp.postJSON("/api/admin/tokens", `{"name":"push","scope":"write","writeMode":"push","collections":["todo"]}`); r.StatusCode != 403 || !strings.Contains(r.Body, `"creator_role_from_claims"`) {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	if r := create(bp, "plain-write", "write"); r.StatusCode != 201 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	// admin by name (and by group as well): allowed
	e.idp.Users["admin"]["groups"] = []string{"ops"}
	bn := e.browser()
	bn.login("admin", "")
	if r := create(bn, "by-name", "write"); r.StatusCode != 201 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
}

// Identities store ----------------------------------------------------------------------

func TestRoleChangedEventShapeInTheLog(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org]\n    editor: [ed@kazuha.org]\n"})
	b := e.browser()
	b.login("editor", "")
	e.rewriteRoles("  roles:\n    admin: [kazuha@kazuha.org]\n    viewer: [ed@kazuha.org]\n")
	b.meta()
	files, _ := filepath.Glob(filepath.Join(e.audit, "audit-*.jsonl"))
	raw, _ := os.ReadFile(files[0])
	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.Contains(l, `"role_changed"`) {
			line = l
		}
	}
	for _, want := range []string{`"from":"editor"`, `"to":"viewer"`, `"auditor_from":false`, `"auditor_to":false`, `"cause":"config"`, `"identity":"ed@kazuha.org"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %s in %s", want, line)
		}
	}
}

// How long a session lives is decided on every request from what its cookie carries and the
// config as it is now, so no cookie, old or replayed or raced, escapes it. Each test runs without
// Git (the store re-reads the file) and with it (a pushed change, pulled: a new config generation).
func eachStore(t *testing.T, f func(t *testing.T, o options)) {
	t.Run("git", func(t *testing.T) { f(t, options{remote: true}) })
	t.Run("nogit", func(t *testing.T) { f(t, options{nogit: true}) })
}

// keepAlive advances the clock by d in steps shorter than the idle limit, with activity.
func keepAlive(e *env, d time.Duration, bs ...*browser) {
	for left := d; left > 0; left -= 5 * time.Hour {
		e.clk.Advance(min(left, 5*time.Hour))
		for _, b := range bs {
			b.meta()
		}
	}
}

func TestReplayedCookieCannotEscapeTheClaimsLimit(t *testing.T) {
	eachStore(t, func(t *testing.T, o options) {
		o.roles = "  roles:\n    admin: [kazuha@kazuha.org, \"group:ops\"]\n"
		e := newEnv(t, o)
		e.idp.Users["admin"]["groups"] = []string{"ops"}
		b := e.browser()
		b.login("admin", "")
		keepAlive(e, 30*time.Hour, b) // the identity entry also grants admin: the normal limit, so far
		if st, _ := b.meta(); st != 200 {
			t.Fatalf("%d", st)
		}
		latest := b.cookie(SessionCookie).Value // the last cookie the browser holds
		// alice goes: the role now comes only from the group
		e.setRoles("  roles:\n    admin: [\"group:ops\"]\n")
		if st, _ := b.meta(); st != 401 {
			t.Fatalf("a 30h-old session whose role is now only a group's must end: %d", st)
		}
		// the same cookie sent again, by anyone, any number of times
		for i := 0; i < 3; i++ {
			r := e.browser()
			r.setCookie(SessionCookie, latest)
			if st, _ := r.meta(); st != 401 {
				t.Fatalf("replay %d: %d", i, st)
			}
		}
		// the identity entry comes back: the same cookie lives by the normal limit again
		e.setRoles("  roles:\n    admin: [kazuha@kazuha.org, \"group:ops\"]\n")
		r := e.browser()
		r.setCookie(SessionCookie, latest)
		if st, _ := r.meta(); st != 200 {
			t.Fatalf("with the entry back the normal limit applies again: %d", st)
		}
	})
}

func TestConcurrentRequestsWithAnOldCookieAreAllRefused(t *testing.T) {
	eachStore(t, func(t *testing.T, o options) {
		o.roles = "  roles:\n    admin: [kazuha@kazuha.org, \"group:ops\"]\n"
		e := newEnv(t, o)
		e.idp.Users["admin"]["groups"] = []string{"ops"}
		b := e.browser()
		b.login("admin", "")
		keepAlive(e, 30*time.Hour, b)
		old := b.cookie(SessionCookie).Value
		e.setRoles("  roles:\n    admin: [\"group:ops\"]\n")
		var wg sync.WaitGroup
		codes := make([]int, 12)
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := e.browser()
				r.setCookie(SessionCookie, old)
				codes[i], _ = r.meta()
			}()
		}
		wg.Wait()
		for i, c := range codes {
			if c != 401 {
				t.Fatalf("request %d: %d", i, c)
			}
		}
	})
}

// While the config does not load roles are capped at viewer: a session that carries claims is
// limited by claims_absolute (fail safe), one that carries none is not.
func TestDegradedConfigAppliesTheClaimsLimitToSessionsWithClaims(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    admin: [kazuha@kazuha.org, \"group:ops\"]\n    editor: [ed@kazuha.org]\n"})
	e.idp.Users["admin"]["groups"] = []string{"ops"}
	withClaims, without := e.browser(), e.browser()
	withClaims.login("admin", "")
	without.login("editor", "")
	keepAlive(e, 25*time.Hour, withClaims, without)
	if st, _ := withClaims.meta(); st != 200 {
		t.Fatalf("the identity entry grants the role: normal limit: %d", st)
	}
	p := filepath.Join(e.dir, "rackbook.yml")
	good, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte("collections: [not valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st, _ := without.meta(); st != 200 {
		t.Fatalf("a session without claims is unaffected: %d", st)
	}
	if st, _ := withClaims.meta(); st != 401 {
		t.Fatalf("under a degraded config a session with claims gets the claims limit: %d", st)
	}
	_ = os.WriteFile(p, good, 0o644)
}

// The auditor capability follows the same rule as the role: an admin who is an auditor only by group
// has no auditor flag on the token, and one whose whole role comes from the groups cannot make a token.
func TestTokenAndTheAuditorCapabilityFromClaims(t *testing.T) {
	e := newEnv(t, options{roles: "  roles:\n    admin: [kazuha@kazuha.org, \"group:ops\"]\n  auditors: [\"group:audit\"]\n"})
	e.idp.Users["admin"]["groups"] = []string{"audit"} // admin by name, auditor by group only
	b := e.browser()
	b.login("admin", "")
	r := b.postJSON("/api/admin/tokens", `{"name":"t1","scope":"read"}`)
	if r.StatusCode != 201 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	if strings.Contains(r.Body, `"creatorAuditor":true`) {
		t.Fatalf("the capability must not ride on a claim: %s", r.Body)
	}
	e.idp.Users["editor"]["groups"] = []string{"ops", "audit"} // role and capability from groups only
	b2 := e.browser()
	b2.login("editor", "")
	if r := b2.postJSON("/api/admin/tokens", `{"name":"t2","scope":"read"}`); r.StatusCode != 403 || !strings.Contains(r.Body, "creator_role_from_claims") {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
}

// The role editor (POST /api/admin/roles) is an ordinary commit to rackbook.yml: the
// role_changed events that follow are the lazy ones of part 1, written at each affected
// person's next request, and only for the people who come back.
func TestRoleEditorSaveIsFollowedByLazyRoleChanged(t *testing.T) {
	eachStore(t, func(t *testing.T, o options) {
		e := newEnv(t, o)
		admin, ed, guest := e.browser(), e.browser(), e.browser()
		admin.login("admin", "")
		ed.login("editor", "")
		guest.login("viewer", "")
		ed.meta()
		guest.meta()

		r := admin.get("/api/admin/roles")
		if r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, r.Body)
		}
		var cur struct {
			Version string `json:"version"`
			Roles   struct {
				Admin, Editor, Viewer []struct{ Value string } `json:"-"`
			} `json:"-"`
		}
		if err := json.Unmarshal([]byte(r.Body), &cur); err != nil || cur.Version == "" {
			t.Fatalf("%v %s", err, r.Body)
		}
		// ed's domain entry moves from editor to viewer; guest is promoted to editor
		save := fmt.Sprintf(`{"version":%q,"roles":{"admin":["kazuha@kazuha.org"],"editor":["guest@example.com"],"viewer":["*@kazuha.org"]},"auditors":[]}`, cur.Version)
		if r = admin.postJSON("/api/admin/roles", save); r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, r.Body)
		}
		if n := len(e.kinds("role_changed")); n != 0 {
			t.Fatalf("it is lazy: %d events before anybody comes back", n)
		}
		// the administrator is still one, and nothing was written for them
		if got := roleOfMeta(t, admin); got != "admin" {
			t.Fatal(got)
		}
		if got := roleOfMeta(t, ed); got != "viewer" {
			t.Fatal(got)
		}
		evs := e.kinds("role_changed")
		if len(evs) != 1 {
			t.Fatalf("written once, for the person who came back: %+v", evs)
		}
		if ev := evs[0]; ev.Identity != "ed@kazuha.org" || ev.From != "editor" || ev.To != "viewer" || ev.Cause != audit.CauseConfig {
			t.Fatalf("%+v", ev)
		}
		// the person who never came back is compared when they do
		if got := roleOfMeta(t, guest); got != "editor" {
			t.Fatal(got)
		}
		evs = e.kinds("role_changed")
		if len(evs) != 2 || evs[1].Identity != "guest@example.com" || evs[1].From != "viewer" || evs[1].To != "editor" || evs[1].Cause != audit.CauseConfig {
			t.Fatalf("%+v", evs)
		}
		// the session's claims count: signed in with the group, an administrator who would be one only
		// through it is refused (a token of theirs would have no role)
		e.idp.Users["admin"]["groups"] = []string{"ops"}
		grp := e.browser()
		grp.login("admin", "")
		r = grp.get("/api/admin/roles")
		_ = json.Unmarshal([]byte(r.Body), &cur)
		bad := fmt.Sprintf(`{"version":%q,"roles":{"admin":["group:ops"],"editor":[],"viewer":[]},"auditors":[]}`, cur.Version)
		if r = grp.postJSON("/api/admin/roles", bad); r.StatusCode != 422 || !strings.Contains(r.Body, "self_lockout_claims") {
			t.Fatalf("%d %s", r.StatusCode, r.Body)
		}
	})
}
