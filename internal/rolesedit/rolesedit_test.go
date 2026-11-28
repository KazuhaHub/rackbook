package rolesedit

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// load makes a config whose auth block is block, in a copy of the test ledger.
func load(t *testing.T, block string) *config.Config {
	t.Helper()
	dir := testutil.CopyExample(t)
	p := filepath.Join(dir, "rackbook.yml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(b, block...), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const block = `
auth:
  roles:
    admin: [boss@example.com]
    viewer: [guest@example.com]   # read only
  auditors: [audie@example.com]
`

func notes(a Annotated, list, value string) []string {
	for _, e := range a.Get(list) {
		if e.Value == value {
			var out []string
			for _, n := range e.Notes {
				out = append(out, n.Level+":"+n.Code)
			}
			return out
		}
	}
	return nil
}

func TestVersionIsOfTheListsOnly(t *testing.T) {
	t.Parallel()
	cfg := load(t, block)
	cur, explicit := Current(cfg)
	if !explicit || !slices.Equal(cur.Admin, []string{"boss@example.com"}) || cur.Editor == nil || len(cur.Editor) != 0 {
		t.Fatalf("%+v", cur)
	}
	v := Version(cur)
	if v != Version(cur.Normalized()) || len(v) != 16 {
		t.Fatal(v)
	}
	other := cur
	other.Viewer = append(slices.Clone(cur.Viewer), "x@example.com")
	if Version(other) == v {
		t.Fatal("a change to a list must change the version")
	}
	// the same text with a comment or another key changed gives the same lists, so the same version
	cfg2 := load(t, strings.Replace(block, "# read only", "# read-only, really", 1)+"\nwrite2: {}\n")
	if c2, _ := Current(cfg2); Version(c2) != v {
		t.Fatal("a comment changed the version")
	}
	if _, explicit := Current(load(t, "\n# nothing\n")); explicit {
		t.Fatal("no roles block")
	}
}

func TestAnnotateNotesWhatTheDeploymentCannotMatch(t *testing.T) {
	t.Parallel()
	cfg := load(t, block)
	l := Lists{
		Admin:    []string{"boss@example.com", "*", "group:ops", "BOSS@example.com"},
		Editor:   []string{"boss@example.com", "mcphub:alice", "oauth:corp:*", "local:alice", "app-role:A"},
		Viewer:   []string{"", "a*b", "x\ny@example.com", strings.Repeat("a", 300)},
		Auditors: []string{"audie@example.com", "oidc:sub"},
	}
	a := Annotate(cfg, l)
	want := map[string][]string{
		"admin/*":                    {"warning:wildcard_admin"},
		"admin/group:ops":            {"warning:no_sso"},
		"admin/BOSS@example.com":     {"warning:duplicate", "warning:also_in"},
		"admin/boss@example.com":     {"warning:also_in"},
		"editor/mcphub:alice":        {"warning:no_mcphub"},
		"editor/oauth:corp:*":        {"warning:unknown_issuer"},
		"editor/local:alice":         {"warning:local_unavailable"},
		"editor/app-role:A":          {"warning:no_sso"},
		"viewer/":                    {"error:empty"},
		"viewer/a*b":                 {"error:invalid"},
		"viewer/x\ny@example.com":    {"error:control_chars"},
		"auditors/oidc:sub":          {"warning:no_sso"},
		"auditors/audie@example.com": {},
	}
	for k, w := range want {
		list, value, _ := strings.Cut(k, "/")
		if got := notes(a, list, value); !slices.Equal(got, w) && !(len(got) == 0 && len(w) == 0) {
			t.Errorf("%s: %v (want %v)", k, got, w)
		}
	}
	if !a.HasError() {
		t.Fatal("errors must show")
	}
	if got := notes(a, "viewer", strings.Repeat("a", 300)); !slices.Equal(got, []string{"error:too_long"}) {
		t.Errorf("%v", got)
	}
	// an entry's kind is what the parser says; a broken one has none
	for _, e := range a.Admin {
		if e.Value == "group:ops" && e.Kind != roles.KindGroup {
			t.Errorf("%+v", e)
		}
	}
	if a.Viewer[1].Kind != "" {
		t.Errorf("%+v", a.Viewer[1])
	}
}

func TestBuildKeepsTheFileAndChecksVersionAndEntries(t *testing.T) {
	t.Parallel()
	cfg := load(t, block)
	cur, _ := Current(cfg)
	ver := Version(cur)
	next := Lists{Admin: []string{"boss@example.com", "new-admin@example.com"}, Editor: []string{"ed@example.com"}, Viewer: []string{}, Auditors: []string{"audie@example.com"}}
	p, err := Build(cfg, Request{Version: ver, Lists: next})
	if err != nil || p.Refusal != nil || !p.Changed {
		t.Fatalf("%v %+v", err, p)
	}
	for _, want := range []string{"-    viewer: [guest@example.com]   # read only", "+    viewer: []   # read only", "+    admin: [boss@example.com, new-admin@example.com]", "+    editor: [ed@example.com]"} {
		if !strings.Contains(p.Diff, want) {
			t.Errorf("the diff lacks %q:\n%s", want, p.Diff)
		}
	}
	if p.Subject != "roles: admin +new-admin@example.com; editor +ed@example.com; viewer -guest@example.com" {
		t.Errorf("%q", p.Subject)
	}
	// without an evaluator nothing about the caller is checked or reported
	if p.Now != nil || p.AfterCap != nil {
		t.Fatalf("%+v %+v", p.Now, p.AfterCap)
	}
	// the new file loads and says the same
	got, err := config.Parse(p.Out, cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := Current(got); !sameLists(c, next.Normalized()) {
		t.Fatalf("%+v", c)
	}
	// the errors that are not refusals
	if _, err := Build(cfg, Request{Version: "", Lists: next}); !errors.Is(err, ErrNoVersion) {
		t.Fatal(err)
	}
	var ve *VersionError
	if _, err := Build(cfg, Request{Version: "stale", Lists: next}); !errors.As(err, &ve) || ve.Version != ver {
		t.Fatal(err)
	}
	if _, err := Build(load(t, "\n# none\n"), Request{Version: "x", Lists: next}); !errors.Is(err, ErrNoRolesBlock) {
		t.Fatal(err)
	}
	// the refusals that need no caller
	for name, l := range map[string]Lists{
		"last admin": {Admin: []string{}, Viewer: []string{"a@b.org"}},
		"invalid":    {Admin: []string{"a@b.org"}, Viewer: []string{"a*b"}},
		"too many":   {Admin: slices.Repeat([]string{"a@b.org"}, 1001)},
	} {
		p, err := Build(cfg, Request{Version: ver, Lists: l})
		if err != nil || p.Refusal == nil {
			t.Errorf("%s: %v %+v", name, err, p)
		}
	}
	// a plan that changes nothing is not a change, and an order of the same entries is not one either
	p, err = Build(cfg, Request{Version: ver, Lists: Lists{Admin: []string{"boss@example.com"}, Viewer: []string{"guest@example.com"}, Auditors: []string{"audie@example.com"}}})
	if err != nil || p.Changed || p.Diff != "" || p.Out != nil {
		t.Fatalf("%v %+v", err, p)
	}
	// a layout the splicer refuses surfaces as ErrUnsupported with the list named
	multi := load(t, "\nauth:\n  roles:\n    admin: [boss@example.com,\n      other@example.com]\n")
	mc, _ := Current(multi)
	_, err = Build(multi, Request{Version: Version(mc), Lists: Lists{Admin: []string{"boss@example.com"}}})
	if !errors.Is(err, yamledit.ErrUnsupported) || !strings.Contains(err.Error(), "auth.roles.admin") {
		t.Fatal(err)
	}
}

func TestCallerRulesRunOnTheEvaluatorsAnswer(t *testing.T) {
	t.Parallel()
	cfg := load(t, block)
	cur, _ := Current(cfg)
	ver := Version(cur)
	caps := map[string]Cap{}
	eval := func(_ *config.Config, spec *roles.Spec, _ []string) (Cap, error) {
		return caps[strings.Join(spec.Admin, ",")], nil
	}
	admin := Cap{Role: "admin", ByIdentity: "admin"}
	next := Lists{Admin: []string{"boss@example.com", "b@example.com"}, Viewer: []string{"guest@example.com"}}
	caps["boss@example.com"] = admin
	caps["boss@example.com,b@example.com"] = admin
	p, err := Build(cfg, Request{Version: ver, Lists: next, Evaluate: eval})
	if err != nil || p.Refusal != nil || p.Now == nil || p.AfterCap == nil || p.AfterCap.Role != "admin" {
		t.Fatalf("%v %+v", err, p)
	}
	caps["boss@example.com,b@example.com"] = Cap{Role: "editor", ByIdentity: "editor"}
	if p, _ = Build(cfg, Request{Version: ver, Lists: next, Evaluate: eval}); p.Refusal == nil || p.Refusal.Code != CodeSelfLockout {
		t.Fatalf("%+v", p.Refusal)
	}
	caps["boss@example.com,b@example.com"] = Cap{Role: "admin", ByIdentity: "none"}
	if p, _ = Build(cfg, Request{Version: ver, Lists: next, Evaluate: eval}); p.Refusal == nil || p.Refusal.Code != CodeSelfLockoutClaims {
		t.Fatalf("%+v", p.Refusal)
	}
	// the last admin is named before the caller
	if p, _ = Build(cfg, Request{Version: ver, Lists: Lists{Viewer: []string{"g@example.com"}}, Evaluate: eval}); p.Refusal == nil || p.Refusal.Code != CodeLastAdmin {
		t.Fatalf("%+v", p.Refusal)
	}
	// nothing is refused when nothing changes, whatever the caller is
	caps["boss@example.com"] = Cap{Role: "admin", ByIdentity: "none"}
	if p, err = Build(cfg, Request{Version: ver, Lists: cur, Evaluate: eval}); err != nil || p.Refusal != nil {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestApplyWritesOnlyWhenAllowedAndChanged(t *testing.T) {
	t.Parallel()
	cfg := load(t, block)
	cur, _ := Current(cfg)
	ver := Version(cur)
	before, _ := os.ReadFile(cfg.Path)
	if _, err := Apply(cfg, Request{Version: ver, Lists: Lists{Admin: []string{}}}); err == nil {
		t.Fatal("last admin")
	} else if rf := new(Refusal); !errors.As(err, &rf) || rf.Code != CodeLastAdmin {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(cfg.Path); string(after) != string(before) {
		t.Fatal("a refused change wrote the file")
	}
	res, err := Apply(cfg, Request{Version: ver, Lists: cur})
	if err != nil || res.Changed() {
		t.Fatalf("%v %+v", err, res)
	}
	res, err = Apply(cfg, Request{Version: ver, Lists: Lists{Admin: []string{"boss@example.com"}, Viewer: []string{"guest@example.com", "v2@example.com"}, Auditors: []string{"audie@example.com"}}, Message: "roles: by hand\n"})
	if err != nil || !res.Changed() || res.Files[0] != "rackbook.yml" || res.Subject() != "roles: by hand" || res.Kind != KindRoles {
		t.Fatalf("%v %+v", err, res)
	}
	after, _ := os.ReadFile(cfg.Path)
	if !strings.Contains(string(after), "viewer: [guest@example.com, v2@example.com]   # read only") {
		t.Fatalf("%s", after)
	}
	// the same version is now stale on the file as it is now
	fresh, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	var ve *VersionError
	if _, err := Apply(fresh, Request{Version: ver, Lists: cur}); !errors.As(err, &ve) {
		t.Fatal("the old version must not apply on the new file:", err)
	}
}
