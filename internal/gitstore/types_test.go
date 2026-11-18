package gitstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/types"
)

var admin = &auth.Identity{ID: "boss@example.com", Name: "Boss Admin", Email: "boss@example.com", Method: auth.MethodCloudflareAccess}

func typeWrite(s *Store, req types.Request) (*WriteResult, error) {
	return s.WriteFunc(context.Background(), func(cfg *config.Config) (*edit.Result, error) { return types.Apply(cfg, req) }, admin)
}

func TestTypeChangeIsOneCommitByTheAdmin(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	nt, err := types.Load(s.Ledger(), "services")
	if err != nil {
		t.Fatal(err)
	}
	nt.Fields = append(nt.Fields, types.Field{Name: "owner", Title: "负责人", Type: types.TText, Required: true, Default: "ops"})
	nt.Field("port").Unique = false
	nt.Icon = "server"
	res, err := typeWrite(s, types.Request{Op: types.OpUpdate, Name: "services", Type: nt,
		Migrations: []types.Migration{{Kind: types.MigFillDefault, Field: "owner"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commit) < 7 {
		t.Fatalf("%+v", res)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("expected the seed and exactly one commit")
	}
	got := sh(t, e.bare, "log", "-1", "--format=%an <%ae>|%cn <%ce>|%B")
	want := "Boss Admin <boss@example.com>|Rackbook <rackbook@example.org>|ledger(types): edit services — add field \"owner\"\n\nEdited-by: boss@example.com\nEdited-via: rackbook (cloudflare-access)"
	if got != want {
		t.Fatalf("commit:\n%s\nwant:\n%s", got, want)
	}
	files := strings.Fields(sh(t, e.bare, "show", "--format=", "--name-only", "HEAD"))
	if strings.Join(files, ",") != "docs/ledger/services.yml,rackbook.yml,schemas/service.json" {
		t.Fatalf("files: %v", files)
	}
	// the ledger was reloaded with the new field and the migrated data
	if r := s.Ledger().Collection("services").Records[0]; r.Data["owner"] != "ops" {
		t.Fatalf("%v", r.Data)
	}
	if st := sh(t, e.server, "status", "--porcelain"); st != "" {
		t.Fatalf("clone is dirty: %s", st)
	}
	// planning the same change again is a no-op: no second commit
	res, err = typeWrite(s, types.Request{Op: types.OpUpdate, Name: "services", Type: mustLoad(t, s, "services")})
	if err != nil || res.Commit != "" {
		t.Fatalf("%v %+v", err, res)
	}
}

func mustLoad(t *testing.T, s *Store, name string) *types.Type {
	t.Helper()
	ty, err := types.Load(s.Ledger(), name)
	if err != nil {
		t.Fatal(err)
	}
	return ty
}

func TestCreateTypeCommitsAllThreeFilesAndSurvivesAFailedPush(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ty := &types.Type{Name: "contacts", Title: "联系人", Key: []string{"name"}, Fields: []types.Field{{Name: "name", Type: types.TText, Required: true}}}
	// a push that fails (not because the remote moved) discards the commit and the files it created
	s.pushFn = func(context.Context, string) error { return errors.New("network down") }
	if _, err := typeWrite(s, types.Request{Op: types.OpCreate, Name: "contacts", Type: ty}); err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("expected the push error, got %v", err)
	}
	for _, f := range []string{"docs/ledger/contacts.yml", "schemas/contacts.json"} {
		if _, err := os.Stat(filepath.Join(e.server, f)); err == nil {
			t.Fatalf("%s must be removed after a failed push", f)
		}
	}
	if st := sh(t, e.server, "status", "--porcelain"); st != "" {
		t.Fatalf("clone is dirty: %s", st)
	}
	s.pushFn = nil
	if _, err := typeWrite(s, types.Request{Op: types.OpCreate, Name: "contacts", Type: ty}); err != nil {
		t.Fatal(err)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("expected one commit")
	}
	files := strings.Fields(sh(t, e.bare, "show", "--format=", "--name-only", "HEAD"))
	if strings.Join(files, ",") != "docs/ledger/contacts.yml,rackbook.yml,schemas/contacts.json" {
		t.Fatalf("files: %v", files)
	}
	if s.Ledger().Collection("contacts") == nil {
		t.Fatal("not reloaded")
	}
	// the new collection takes its first record through the normal write path
	res, err := s.Write(context.Background(), edit.Op{Kind: edit.Add, Collection: "contacts", Data: map[string]any{"name": "ann"}}, admin)
	if err != nil || res.Commit == "" {
		t.Fatalf("%v %+v", err, res)
	}
	// deleting a non-empty collection is refused; nothing is committed
	if _, err := typeWrite(s, types.Request{Op: types.OpDelete, Name: "contacts"}); err == nil {
		t.Fatal("expected a refusal")
	} else if _, ok := err.(*types.PlanError); !ok {
		t.Fatalf("%T", err)
	}
}

func TestTypeChangeReplaysOnAMovedRemote(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	// somebody else pushes a data change first
	laptop := open(t, e.laptop, nil)
	if _, err := laptop.Write(context.Background(), sshEdit(t, laptop, "TCP 2222"), editor); err != nil {
		t.Fatal(err)
	}
	nt := mustLoad(t, s, "todo")
	nt.Fields = append(nt.Fields, types.Field{Name: "owner", Type: types.TText})
	if _, err := typeWrite(s, types.Request{Op: types.OpUpdate, Name: "todo", Type: nt}); err != nil {
		t.Fatal(err)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "3" {
		t.Fatal("expected the seed, the other edit and the type change")
	}
	if r := s.Ledger().Collection("services").Get("web-hostco-ashburn-va-us-dc/SSH"); r.Data["port"] != "TCP 2222" {
		t.Fatal("the other edit must be in the clone")
	}
}
