package gitstore

import (
	"errors"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/roles"
)

func TestWriteOptionsForModules(t *testing.T) {
	cfg := &config.Config{Modules: map[string]*config.Module{
		"fast": {Token: "fast-token", Collection: "creds", Fields: []string{"expires"}, DirectPush: true},
		"slow": {Token: "slow-token", Collection: "creds", Fields: []string{"expires"}},
	}}
	tok := func(name string, role roles.Role) *auth.Identity {
		return &auth.Identity{ID: "x@y.z", Method: auth.MethodToken, Token: name, Role: role}
	}
	cases := []struct {
		who     *auth.Identity
		kind    edit.Kind
		coll    string
		forcePR bool
	}{
		{tok("fast-token", roles.Admin), edit.Add, "creds", false},
		{tok("fast-token", roles.Admin), edit.Edit, "creds", false},
		{tok("fast-token", roles.Admin), edit.Delete, "creds", true},
		{tok("fast-token", roles.Admin), edit.Add, "todo", true},
		{tok("fast-token", roles.Editor), edit.Add, "creds", true}, // the creator is no admin (any more)
		{tok("slow-token", roles.Admin), edit.Add, "creds", true},  // no direct_push
		{tok("other", roles.Admin), edit.Add, "creds", true},       // not a module
	}
	for i, c := range cases {
		if o := WriteOptionsFor(c.who, cfg, c.kind, c.coll); o.ForcePR != c.forcePR || o.BranchPrefix != "rackbook/token/"+Slug(c.who.Token) {
			t.Errorf("case %d: %+v", i, o)
		}
	}
}

func TestModuleGuard(t *testing.T) {
	cfg := &config.Config{Modules: map[string]*config.Module{"bot": {Token: "bot-token", Collection: "creds", Fields: []string{"expires"}}}}
	who := &auth.Identity{ID: "x@y.z", Method: auth.MethodToken, Token: "bot-token"}
	op, err := ModuleGuard(who, cfg, edit.Op{Kind: edit.Add, Collection: "creds"})
	if err != nil || op.Module == nil || op.Module.Name != "bot" || op.Module.Fields[0] != "expires" {
		t.Fatalf("%v %+v", err, op)
	}
	var me *edit.ModuleError
	for _, o := range []edit.Op{{Kind: edit.Add, Collection: "todo"}, {Kind: edit.Delete, Collection: "creds"}} {
		if _, err := ModuleGuard(who, cfg, o); !errors.As(err, &me) {
			t.Errorf("%+v: %v", o, err)
		}
	}
	for _, w := range []*auth.Identity{nil, {ID: "a", Method: auth.MethodPasskey, Token: "bot-token"}, {ID: "a", Method: auth.MethodToken, Token: "other"}} {
		if op, err := ModuleGuard(w, cfg, edit.Op{Kind: edit.Delete, Collection: "todo"}); err != nil || op.Module != nil {
			t.Errorf("%+v: %v %+v", w, err, op)
		}
	}
}
