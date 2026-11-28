package rolesedit

import (
	"slices"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/accounts"
)

const localBlock = `
auth:
  roles:
    admin: ["local:alice"]
    editor: ["local:bob"]
    viewer: ["local:*"]
  auditors: ["local:carol"]
`

func localState() Local {
	return Local{Available: true, States: map[string]string{
		"alice": accounts.StateActive, "bob": accounts.StateRestricted, "carol": accounts.StatePasskeyOnly,
		"dave": accounts.StateInvited, "erin": accounts.StateDisabled, "frank": accounts.StateRemoved,
	}}
}

func TestLocalEntriesAreAddedAndRemovedLikeAnyOther(t *testing.T) {
	t.Parallel()
	cfg := load(t, localBlock)
	cur, _ := Current(cfg)
	ver := Version(cur)
	next := Lists{Admin: []string{"local:alice", "LOCAL:Dave"}, Editor: []string{"local:bob"}, Viewer: []string{}, Auditors: []string{"local:carol", "local:erin"}}
	p, err := Build(cfg, Request{Version: ver, Lists: next, Local: localState()})
	if err != nil || p.Refusal != nil || !p.Changed {
		t.Fatalf("%v %+v", err, p)
	}
	for _, want := range []string{`+    admin: ["local:alice", LOCAL:Dave]`, "+    viewer: []", `+  auditors: ["local:carol", local:erin]`} {
		if !strings.Contains(p.Diff, want) {
			t.Errorf("the diff lacks %q:\n%s", want, p.Diff)
		}
	}
	if p.Subject != "roles: admin +LOCAL:Dave; viewer -local:*; auditors +local:erin" {
		t.Errorf("%q", p.Subject)
	}
	// what the file says is what was asked, and it loads
	if _, err := Apply(cfg, Request{Version: ver, Lists: next, Local: localState()}); err != nil {
		t.Fatal(err)
	}
	// the entry kinds and what the editor says of each
	for list, want := range map[string]map[string][]string{
		ListAdmin:    {"local:alice": nil, "LOCAL:Dave": nil},
		ListAuditors: {"local:carol": nil, "local:erin": {"warning:local_inactive"}},
	} {
		for v, w := range want {
			if got := notes(p.Entries, list, v); !slices.Equal(got, w) && !(len(got) == 0 && len(w) == 0) {
				t.Errorf("%s %s: %v, want %v", list, v, got, w)
			}
		}
	}
	for _, e := range p.Entries.Admin {
		if e.Kind != "local" {
			t.Errorf("%s is %q", e.Value, e.Kind)
		}
	}
	// an invalid local entry is the parser's own error, and the same entry twice is noted
	bad := Lists{Admin: []string{"local:alice", "local:Bad Name"}}
	if p, err := Build(cfg, Request{Version: ver, Lists: bad, Local: localState()}); err != nil || p.Refusal == nil || p.Refusal.Code != CodeInvalidEntries {
		t.Fatalf("%v %+v", err, p)
	}
	if n := notes(Annotate(cfg, Lists{Admin: []string{"local:alice", "LOCAL:alice"}}), ListAdmin, "LOCAL:alice"); !slices.Contains(n, "warning:duplicate") {
		t.Errorf("%v", n)
	}
}

func TestLocalEntriesAreNotedByWhatTheDeploymentHas(t *testing.T) {
	t.Parallel()
	cfg := load(t, localBlock)
	l := Lists{Admin: []string{"local:alice", "local:ghost", "local:erin", "local:frank", "local:*"}, Editor: []string{}, Viewer: []string{}, Auditors: []string{}}
	// local accounts unavailable: every local: entry matches nobody
	a := Annotate(cfg, l)
	for _, v := range l.Admin {
		got := notes(a, ListAdmin, v)
		if !slices.Contains(got, "warning:local_unavailable") {
			t.Errorf("%s: %v", v, got)
		}
	}
	// available: an entry names an account, or it matches nobody yet
	a = AnnotateLocal(cfg, l, localState())
	want := map[string]string{
		"local:alice": "", "local:ghost": "warning:local_no_account", "local:erin": "warning:local_inactive", "local:frank": "warning:local_inactive", "local:*": "warning:wildcard_admin",
	}
	for v, w := range want {
		got := notes(a, ListAdmin, v)
		if w == "" && len(got) != 0 || w != "" && !slices.Contains(got, w) {
			t.Errorf("%s: %v, want %q", v, got, w)
		}
	}
	if slices.Contains(notes(a, ListAdmin, "local:alice"), "warning:local_unavailable") {
		t.Error("local accounts are available here")
	}
}

func TestLastAdminCountsAdminsWhoCanSignIn(t *testing.T) {
	t.Parallel()
	cfg := load(t, localBlock)
	cur, _ := Current(cfg)
	ver := Version(cur)
	try := func(l Lists, local Local) *Refusal {
		t.Helper()
		p, err := Build(cfg, Request{Version: ver, Lists: l, Local: local})
		if err != nil {
			t.Fatal(err)
		}
		return p.Refusal
	}
	base := Lists{Editor: []string{"local:bob"}, Viewer: []string{"local:*"}, Auditors: []string{"local:carol"}}
	with := func(admin ...string) Lists { l := base; l.Admin = admin; return l }

	// an admin list with no entry is refused, as it always was
	if r := try(with(), localState()); r == nil || r.Code != CodeLastAdmin {
		t.Fatalf("%+v", r)
	}
	// replacing the last local admin by a disabled, a removed or an unknown account leaves nobody who can sign in
	for _, v := range []string{"local:erin", "local:frank", "local:ghost"} {
		if r := try(with(v), localState()); r == nil || r.Code != CodeLastAdmin {
			t.Errorf("%s: %+v", v, r)
		}
	}
	// accounts that can sign in now or once their setup is done count
	for _, v := range []string{"local:alice", "local:bob", "local:carol", "local:dave", "local:*", "LOCAL:Alice"} {
		if r := try(with(v), localState()); r != nil {
			t.Errorf("%s: %+v", v, r)
		}
	}
	// beside a name that can sign in, the others do not matter
	if r := try(with("local:erin", "local:alice"), localState()); r != nil {
		t.Errorf("%+v", r)
	}
	// an entry of another kind counts, as before
	if r := try(with("boss@example.com"), localState()); r != nil {
		t.Errorf("%+v", r)
	}
	// local accounts unavailable: a local: entry is no admin who can sign in
	if r := try(with("local:alice"), Local{}); r != nil {
		// the lists are unchanged from the file's admin entry, so nothing is taken away: not refused
		t.Errorf("an unchanged admin list was refused: %+v", r)
	}
	if r := try(with("local:bob"), Local{}); r != nil {
		t.Errorf("an admin list that had no admin who can sign in is not refused for another such entry: %+v", r)
	}
	// but taking the last signable one away is
	cfg2 := load(t, strings.Replace(localBlock, `admin: ["local:alice"]`, `admin: ["local:alice", "boss@example.com"]`, 1))
	cur2, _ := Current(cfg2)
	p, err := Build(cfg2, Request{Version: Version(cur2), Lists: Lists{Admin: []string{"local:alice"}, Editor: cur2.Editor, Viewer: cur2.Viewer, Auditors: cur2.Auditors}, Local: Local{}})
	if err != nil || p.Refusal == nil || p.Refusal.Code != CodeLastAdmin {
		t.Fatalf("%v %+v", err, p)
	}
	// nothing is refused when nothing changes
	p, err = Build(cfg, Request{Version: ver, Lists: cur, Local: Local{}})
	if err != nil || p.Refusal != nil || p.Changed {
		t.Fatalf("%v %+v", err, p)
	}
}

// the editor does not import the account store, so it holds its own copy of the two states it tells apart
func TestStatesAreTheAccountStoresStates(t *testing.T) {
	t.Parallel()
	if stateDisabled != accounts.StateDisabled || stateRemoved != accounts.StateRemoved {
		t.Fatal("the states differ from internal/accounts")
	}
}
