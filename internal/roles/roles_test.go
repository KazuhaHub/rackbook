package roles

import (
	"strings"
	"testing"
)

func eval(t *testing.T, spec *Spec, s Subject, legacy ...string) Role {
	t.Helper()
	return evalOpt(t, spec, Options{}, s, legacy...)
}

// evalOpt defaults the method to oidc, a plain interactive login.
func evalOpt(t *testing.T, spec *Spec, opt Options, s Subject, legacy ...string) Role {
	t.Helper()
	if s.Method == "" {
		s.Method = "oidc"
	}
	p, err := Compile(spec, opt, legacy...)
	if err != nil {
		t.Fatal(err)
	}
	return p.Evaluate(s)
}

func TestEntryKinds(t *testing.T) {
	spec := &Spec{
		Admin:  []string{"Owner@Example.com"},
		Editor: []string{"*@example.com", "mcphub:Alice", "group:Ops-Team"},
		Viewer: []string{"guest@other.org", "*@viewers.org"},
	}
	for _, c := range []struct {
		name string
		s    Subject
		want Role
	}{
		{"exact, case-insensitive", Subject{ID: "OWNER@example.COM"}, Admin},
		{"exact beats domain: highest wins", Subject{ID: "owner@example.com"}, Admin},
		{"domain", Subject{ID: "x@example.com"}, Editor},
		{"domain does not match a longer suffix host", Subject{ID: "x@evil-example.com"}, None},
		{"domain does not match subdomains", Subject{ID: "x@sub.example.com"}, None},
		{"mcphub user", Subject{ID: "alice", Method: "mcphub"}, Editor},
		{"mcphub entry needs the mcphub method", Subject{ID: "alice", Method: "oidc"}, None},
		{"mcphub username that is an e-mail does not match e-mail entries by default", Subject{ID: "bob@example.com", Method: "mcphub"}, None},
		{"group", Subject{ID: "z@q.io", Groups: []string{"ops-team"}}, Editor},
		{"other group", Subject{ID: "z@q.io", Groups: []string{"sales"}}, None},
		{"viewer exact", Subject{ID: "guest@other.org"}, Viewer},
		{"e-mail field matches too", Subject{ID: "uid-1", Email: "Guest@Other.org"}, Viewer},
		{"nothing", Subject{ID: "nobody@nowhere.org"}, None},
		{"empty identity", Subject{}, None},
	} {
		if got := eval(t, spec, c.s); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestAnyAndHighestWins(t *testing.T) {
	spec := &Spec{Admin: []string{"a@x.org"}, Editor: []string{"a@x.org"}, Viewer: []string{"*"}}
	if got := eval(t, spec, Subject{ID: "a@x.org"}); got != Admin {
		t.Fatal(got)
	}
	if got := eval(t, spec, Subject{ID: "anyone@y.org"}); got != Viewer {
		t.Fatal(got)
	}
	if got := eval(t, spec, Subject{}); got != Viewer {
		t.Fatalf("* matches anonymous too: %v", got)
	}
}

func TestNoRolesBlockIsV01(t *testing.T) {
	if got := eval(t, nil, Subject{ID: "anyone@x.org"}); got != Editor {
		t.Fatal(got)
	}
	// editors without roles: listed are editors, the rest can read (v0.1).
	if got := eval(t, nil, Subject{ID: "ann@x.org"}, "Ann@x.org"); got != Editor {
		t.Fatal(got)
	}
	if got := eval(t, nil, Subject{ID: "bob@x.org"}, "ann@x.org"); got != Viewer {
		t.Fatal(got)
	}
	// editors together with roles: extra editor entries; no match is still no access.
	spec := &Spec{Admin: []string{"boss@x.org"}}
	if got := eval(t, spec, Subject{ID: "ann@x.org"}, "ann@x.org"); got != Editor {
		t.Fatal(got)
	}
	if got := eval(t, spec, Subject{ID: "bob@x.org"}, "ann@x.org"); got != None {
		t.Fatal(got)
	}
	// An empty roles block is a block: nobody matches.
	if got := eval(t, &Spec{}, Subject{ID: "ann@x.org"}); got != None {
		t.Fatal(got)
	}
}

func TestInvalidEntries(t *testing.T) {
	for _, bad := range []string{"", "  ", "*@", "*@a@b", "a*@x.org", "group:", "mcphub:", "*@*.org", "x*"} {
		if _, err := Compile(&Spec{Editor: []string{bad}}, Options{}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := Compile(nil, Options{}, "*@"); err == nil {
		t.Error("bad legacy editor accepted")
	}
}

func TestAllows(t *testing.T) {
	type row struct {
		r    Role
		want [4]bool // read, write, delete, admin
	}
	for _, c := range []row{
		{None, [4]bool{false, false, false, false}},
		{Viewer, [4]bool{true, false, false, false}},
		{Editor, [4]bool{true, true, true, false}},
		{Admin, [4]bool{true, true, true, true}},
	} {
		got := [4]bool{c.r.Allows(Read), c.r.Allows(Write), c.r.Allows(Delete), c.r.Allows(Manage)}
		if got != c.want {
			t.Errorf("%v: %v", c.r, got)
		}
	}
	if Admin.Allows("bogus") || Lower(Admin, Viewer) != Viewer || Lower(Viewer, Admin) != Viewer {
		t.Fatal("bogus action / Lower")
	}
}

func TestASCIIFoldingOnly(t *testing.T) {
	spec := &Spec{Admin: []string{"kazuha@kazuha.org"}, Editor: []string{"*@kazuha.org"}}
	kelvin := "\u212Aazuha@kazuha.org" // KELVIN SIGN folds onto "k" with strings.ToLower
	for _, s := range []Subject{{ID: kelvin}, {ID: FoldASCII(kelvin)}, {ID: "x", Email: kelvin}} {
		if got := eval(t, spec, s); got == Admin {
			t.Errorf("%+v matched the exact admin entry", s)
		}
	}
	if got := eval(t, spec, Subject{ID: "x@\u212Aazuha.org"}); got != None {
		t.Errorf("Kelvin in the domain matched: %v", got)
	}
	if got := eval(t, spec, Subject{ID: "KAZUHA@Kazuha.ORG"}); got != Admin {
		t.Fatal("ASCII case must still fold")
	}
	if FoldASCII("AbC\u212A-Z") != "abc\u212A-z" {
		t.Fatal(FoldASCII("AbC\u212A-Z"))
	}
	// Entries fold the same way: a Kelvin entry never matches the ASCII name.
	if got := eval(t, &Spec{Admin: []string{kelvin}}, Subject{ID: "kazuha@kazuha.org"}); got != None {
		t.Fatal(got)
	}
	// Groups too.
	if got := eval(t, &Spec{Admin: []string{"group:k"}}, Subject{ID: "a@b.c", Groups: []string{"\u212A"}}); got != None {
		t.Fatal(got)
	}
}

func TestMatchingDependsOnTheAuthMethod(t *testing.T) {
	spec := &Spec{
		Admin:  []string{"boss@x.org", "mcphub:carol"},
		Editor: []string{"*@x.org", "group:ops", "mcphub:*"},
		Viewer: []string{"*"},
	}
	for _, m := range []string{"oidc", "passkey", "cloudflare-access", "none", "cli"} {
		if got := eval(t, spec, Subject{ID: "boss@x.org", Method: m}); got != Admin {
			t.Errorf("%s: %v", m, got)
		}
	}
	// MCPHub: only mcphub: entries, never *, domain, group or exact e-mail.
	for _, c := range []struct {
		s    Subject
		want Role
	}{
		{Subject{ID: "boss@x.org", Method: "mcphub"}, Editor}, // mcphub:* only
		{Subject{ID: "carol", Method: "mcphub"}, Admin},
		{Subject{ID: "dave", Method: "mcphub", Groups: []string{"ops"}}, Editor},
	} {
		if got := eval(t, spec, c.s); got != c.want {
			t.Errorf("%+v: %v want %v", c.s, got, c.want)
		}
	}
	noWild := &Spec{Admin: []string{"boss@x.org"}, Editor: []string{"*@x.org", "group:ops"}, Viewer: []string{"*"}}
	if got := eval(t, noWild, Subject{ID: "boss@x.org", Method: "mcphub", Groups: []string{"ops"}}); got != None {
		t.Fatalf("mcphub must not match exact, domain, group or *: %v", got)
	}
	// Opt-in: an e-mail username may match exact and domain entries, nothing else.
	opt := Options{MCPMatchEmail: true}
	if got := evalOpt(t, noWild, opt, Subject{ID: "boss@x.org", Email: "boss@x.org", Method: "mcphub"}); got != Admin {
		t.Fatal(got)
	}
	if got := evalOpt(t, noWild, opt, Subject{ID: "x@x.org", Email: "x@x.org", Method: "mcphub"}); got != Editor {
		t.Fatal(got)
	}
	if got := evalOpt(t, noWild, opt, Subject{ID: "boss@x.org", Method: "mcphub"}); got != None {
		t.Fatalf("a username that looks like an address, without a verified Email, never matches: %v", got)
	}
	if got := evalOpt(t, noWild, opt, Subject{ID: "alice", Method: "mcphub", Groups: []string{"ops"}}); got != None {
		t.Fatalf("a non-email username never matches e-mail entries, groups or *: %v", got)
	}
	// Tokens and unknown methods take their creator's role, never a direct one.
	for _, m := range []string{"token", "", "bogus"} {
		p, _ := Compile(noWild, opt)
		if got := p.Evaluate(Subject{ID: "boss@x.org", Method: m}); got != None {
			t.Errorf("method %q: %v", m, got)
		}
	}
}

func TestOAuthEntries(t *testing.T) {
	spec := &Spec{Admin: []string{"oauth:kc:root"}, Editor: []string{"oauth:entra:Alice@Example.com", "oauth:kc:*"}, Viewer: []string{"bob@example.com", "*@example.org"}}
	p, err := Compile(spec, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := func(m Subject) Role { return p.Evaluate(m) }
	if ev(Subject{ID: "alice@example.com", Method: "oauth", Issuer: "entra"}) != Editor {
		t.Fatal("oauth:entra:<user>")
	}
	if ev(Subject{ID: "alice@example.com", Method: "oauth", Issuer: "kc"}) != Editor { // oauth:kc:*
		t.Fatal("oauth:kc:*")
	}
	if ev(Subject{ID: "root", Method: "oauth", Issuer: "kc"}) != Admin {
		t.Fatal("admin")
	}
	if ev(Subject{ID: "root", Method: "oauth", Issuer: "other"}) != None {
		t.Fatal("the alias must match")
	}
	// Plain e-mail entries need match_email; mcphub entries never match oauth, nor the reverse.
	if ev(Subject{ID: "bob@example.com", Method: "oauth", Issuer: "entra"}) != None {
		t.Fatal("e-mail entries need match_email")
	}
	if ev(Subject{ID: "root", Method: "mcphub"}) != None {
		t.Fatal("oauth entries must not match mcphub users")
	}
	pe, _ := Compile(spec, Options{MCPMatchEmail: true})
	if pe.Evaluate(Subject{ID: "bob", Email: "bob@example.com", Method: "oauth", Issuer: "entra"}) != Viewer || pe.Evaluate(Subject{ID: "x", Email: "x@example.org", Method: "oauth", Issuer: "entra"}) != Viewer || pe.Evaluate(Subject{ID: "bob@example.com", Method: "oauth", Issuer: "entra"}) != None {
		t.Fatal("match_email")
	}
	for _, bad := range []string{"oauth:", "oauth:kc", "oauth:kc:", "oauth::bob"} {
		if _, err := Compile(&Spec{Editor: []string{bad}}, Options{}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestOIDCSubjectEntries(t *testing.T) {
	spec := &Spec{Admin: []string{"oidc:Sub-1"}, Editor: []string{"*@x.org", "group:ops"}, Viewer: []string{"*"}}
	if got := eval(t, spec, Subject{ID: "oidc:sub-1", Method: "oidc"}); got != Admin {
		t.Fatalf("listed subject: %v", got)
	}
	// An unlisted subject matches no *, domain or group entry.
	if got := eval(t, spec, Subject{ID: "oidc:sub-2", Method: "oidc", Groups: []string{"ops"}}); got != None {
		t.Fatalf("unlisted subject: %v", got)
	}
	// An oidc: entry matches nothing but a subject login.
	if got := eval(t, &Spec{Admin: []string{"oidc:sub-1"}}, Subject{ID: "sub-1", Method: "oidc"}); got != None {
		t.Fatalf("%v", got)
	}
	if got := eval(t, &Spec{Admin: []string{"oidc:sub-1"}}, Subject{ID: "oidc:sub-1", Method: "mcphub"}); got != None {
		t.Fatalf("%v", got)
	}
}

func TestAuditorsUseTheEntrySyntaxOfARoleList(t *testing.T) {
	p, err := CompileAuditors(nil, []string{"Aud@Example.com", "*@audit.example.com", "group:Audit-Team", "oauth:acme:aud", "mcphub:aud", "oidc:sub-9"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		s    Subject
		want bool
	}{
		{"exact, folded", Subject{ID: "AUD@example.com", Method: "oidc"}, true},
		{"domain", Subject{ID: "x@audit.example.com", Method: "passkey"}, true},
		{"group", Subject{ID: "x@y.z", Method: "oidc", Groups: []string{"audit-team"}}, true},
		{"oauth", Subject{ID: "aud", Method: "oauth", Issuer: "acme"}, true},
		{"mcphub", Subject{ID: "aud", Method: "mcphub"}, true},
		{"subject identity", Subject{ID: "oidc:sub-9", Method: "oidc"}, true},
		{"nobody else", Subject{ID: "boss@example.com", Method: "oidc"}, false},
		{"another group", Subject{ID: "x@y.z", Method: "oidc", Groups: []string{"ops"}}, false},
		{"a token matches nothing itself", Subject{ID: "aud@example.com", Method: "token"}, false},
		{"mcphub never matches an e-mail entry without match_email", Subject{ID: "aud@example.com", Email: "aud@example.com", Method: "mcphub"}, false},
	} {
		if got := p.IsAuditor(c.s); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAuditorIsNotARole(t *testing.T) {
	spec := &Spec{Admin: []string{"boss@example.com"}, Viewer: []string{"vic@example.com"}}
	p, err := CompileAuditors(spec, []string{"boss@example.com", "aud@example.com"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	boss, aud := Subject{ID: "boss@example.com", Method: "oidc"}, Subject{ID: "aud@example.com", Method: "oidc"}
	// the list does not change the role scale: Evaluate knows nothing of it
	if got := p.Evaluate(boss); got != Admin {
		t.Fatalf("boss: %v", got)
	}
	if got := p.Evaluate(aud); got != None {
		t.Fatalf("an auditor with no role has no role here (the viewer floor is the auth package's): %v", got)
	}
	// an admin is an auditor only when listed
	p2, err := CompileAuditors(spec, []string{"aud@example.com"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p2.IsAuditor(boss) || !p2.IsAuditor(aud) {
		t.Fatal("an admin is not automatically an auditor")
	}
	// no list, no auditors
	p3, _ := Compile(spec, Options{})
	if p3.IsAuditor(aud) || p3.IsAuditor(boss) {
		t.Fatal("no auditors list")
	}
}

func TestInvalidAuditorEntriesNameTheKey(t *testing.T) {
	for _, bad := range []string{"", "a*b", "*@", "group:", "oauth:x", "oidc:", "mcphub:"} {
		if _, err := CompileAuditors(nil, []string{bad}, Options{}); err == nil || !strings.Contains(err.Error(), "auth.auditors") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// the role lists keep their own names
	if _, err := Compile(&Spec{Admin: []string{"a*b"}}, Options{}); err == nil || !strings.Contains(err.Error(), "auth.roles.admin") {
		t.Fatal(err)
	}
}

// app-role:<value> matches the ID token's roles claim, exactly and case-sensitively.
func TestAppRoleEntries(t *testing.T) {
	spec := &Spec{
		Admin:  []string{"app-role:Rackbook.Admin"},
		Editor: []string{"App-Role:Rackbook.Editor", "  app-role: Spaced Role  "},
		Viewer: []string{"app-role:rackbook.viewer"},
	}
	for _, c := range []struct {
		name string
		s    Subject
		want Role
	}{
		{"exact", Subject{ID: "a@x.org", AppRoles: []string{"Rackbook.Admin"}}, Admin},
		{"case matters", Subject{ID: "a@x.org", AppRoles: []string{"rackbook.admin"}}, None},
		{"case matters, the other way", Subject{ID: "a@x.org", AppRoles: []string{"Rackbook.Viewer"}}, None},
		{"lower case entry matches lower case value", Subject{ID: "a@x.org", AppRoles: []string{"rackbook.viewer"}}, Viewer},
		{"the prefix is not case-sensitive, the value is kept as written", Subject{ID: "a@x.org", AppRoles: []string{"Rackbook.Editor"}}, Editor},
		{"inner spaces are part of the value, outer ones are trimmed", Subject{ID: "a@x.org", AppRoles: []string{"Spaced Role"}}, Editor},
		{"highest wins", Subject{ID: "a@x.org", AppRoles: []string{"rackbook.viewer", "Rackbook.Admin"}}, Admin},
		{"a group is not an app role", Subject{ID: "a@x.org", Groups: []string{"Rackbook.Admin"}}, None},
		{"no roles claim", Subject{ID: "a@x.org"}, None},
		{"a prefix of the value is not the value", Subject{ID: "a@x.org", AppRoles: []string{"Rackbook.Admin.Extra"}}, None},
	} {
		if got := eval(t, spec, c.s); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// a group entry still folds case, an app role does not
	g := &Spec{Admin: []string{"group:Ops", "app-role:Ops"}}
	if eval(t, g, Subject{ID: "a@x.org", Groups: []string{"OPS"}}) != Admin || eval(t, g, Subject{ID: "a@x.org", AppRoles: []string{"OPS"}}) != None {
		t.Error("groups fold case; app roles do not")
	}
	// subject logins match only oidc: entries, as with groups
	if got := eval(t, &Spec{Admin: []string{"app-role:X"}}, Subject{ID: "oidc:sub-1", AppRoles: []string{"X"}}); got != None {
		t.Errorf("a login named by its subject matches oidc: entries only: %v", got)
	}
	// only an OIDC-style login carries them: MCPHub and OAuth identities never match
	for _, m := range []string{"mcphub", "oauth", "token"} {
		if got := eval(t, &Spec{Admin: []string{"app-role:X"}}, Subject{ID: "a", Method: m, AppRoles: []string{"X"}}); got != None {
			t.Errorf("%s: %v", m, got)
		}
	}
}

func TestAppRoleEntriesAreValidatedLikeAnyOther(t *testing.T) {
	for _, bad := range []string{"app-role:", "app-role:   ", "APP-ROLE:", "app-role:a*", "app-role:*", "app-role:a\nb"} {
		if _, err := Compile(&Spec{Editor: []string{bad}}, Options{}); err == nil {
			t.Errorf("%q accepted in auth.roles", bad)
		}
		_, err := CompileAuditors(nil, []string{bad}, Options{})
		if err == nil || !strings.Contains(err.Error(), "auth.auditors") {
			t.Errorf("%q in auth.auditors: %v", bad, err)
		}
	}
	for _, ok := range []string{"app-role:Rackbook.Admin", "app-role:Role With Spaces", "app-role:a:b"} {
		if _, err := CompileAuditors(&Spec{Admin: []string{ok}}, []string{ok}, Options{}); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestAppRoleOnAuditors(t *testing.T) {
	p, err := CompileAuditors(&Spec{Admin: []string{"a@x.org"}}, []string{"app-role:Rackbook.Auditor"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAuditor(Subject{ID: "z@x.org", Method: "oidc", AppRoles: []string{"Rackbook.Auditor"}}) {
		t.Error("an app role on auth.auditors")
	}
	if p.IsAuditor(Subject{ID: "z@x.org", Method: "oidc", AppRoles: []string{"rackbook.auditor"}}) {
		t.Error("case matters there too")
	}
}

func TestSubjectWithoutClaimsIsWhatATokenCreatorIs(t *testing.T) {
	p, err := Compile(&Spec{Admin: []string{"app-role:A", "group:g"}, Viewer: []string{"*@x.org"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := Subject{ID: "a@x.org", Method: "oidc", Groups: []string{"g"}, AppRoles: []string{"A"}}
	if p.Evaluate(s) != Admin || p.Evaluate(s.WithoutClaims()) != Viewer {
		t.Fatal("the creator is evaluated by identity alone")
	}
	if s.Groups == nil || s.AppRoles == nil {
		t.Fatal("WithoutClaims must not change the original")
	}
}

func TestSources(t *testing.T) {
	p, err := CompileAuditors(&Spec{
		Admin:  []string{"boss@x.org", "group:ops", "app-role:Admin"},
		Editor: []string{"app-role:Edit", "*@x.org"},
		Viewer: []string{"group:all"},
	}, []string{"group:audit", "aud@x.org"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name          string
		s             Subject
		role, auditor string
	}{
		{"identity only", Subject{ID: "boss@x.org", Method: "oidc"}, "identity", ""},
		{"group and app role agree with the identity", Subject{ID: "boss@x.org", Method: "oidc", Groups: []string{"ops"}, AppRoles: []string{"Admin"}}, "app-role,group,identity", ""},
		{"only the list of the highest role counts", Subject{ID: "e@x.org", Method: "oidc", AppRoles: []string{"Edit"}, Groups: []string{"all"}}, "app-role,identity", ""},
		{"group only", Subject{ID: "g@y.org", Method: "oidc", Groups: []string{"ops"}}, "group", ""},
		{"auditor by group, no role: the floor comes from the same entries", Subject{ID: "g@y.org", Method: "oidc", Groups: []string{"audit"}}, "group", "group"},
		{"auditor by name", Subject{ID: "aud@x.org", Method: "oidc"}, "identity", "identity"},
		{"nothing", Subject{ID: "n@y.org", Method: "oidc"}, "", ""},
	} {
		r, a := p.Sources(c.s)
		if strings.Join(r, ",") != c.role || strings.Join(a, ",") != c.auditor {
			t.Errorf("%s: role %v auditor %v, want %q %q", c.name, r, a, c.role, c.auditor)
		}
	}
	// without a roles block everybody is an editor, by no entry at all
	if r, _ := mustCompile(t, nil).Sources(Subject{ID: "a", Method: "oidc"}); strings.Join(r, ",") != "identity" {
		t.Errorf("%v", r)
	}
}

func mustCompile(t *testing.T, spec *Spec) *Policy {
	t.Helper()
	p, err := Compile(spec, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
