package edit_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// Assembled at run time: this file holds no string a scanner would flag.
var ghToken = "gh" + "p_" + strings.Repeat("a1B2", 9)

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			out[rel] = string(b)
		}
		return nil
	})
	return out
}

func sameTree(t *testing.T, a, b map[string]string) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("files differ: %d vs %d", len(a), len(b))
	}
	for k, v := range a {
		if b[k] != v {
			t.Fatalf("%s changed", k)
		}
	}
}

func asSecretErr(t *testing.T, err error) *secretscan.Error {
	t.Helper()
	var se *secretscan.Error
	if !errors.As(err, &se) {
		t.Fatalf("want a secret error, got %v", err)
	}
	for _, f := range se.Findings {
		if strings.Contains(f.Excerpt, ghToken[:6]) && len(f.Excerpt) > 8 {
			t.Fatalf("leak: %+v", f)
		}
	}
	return se
}

func TestSecretInAddAndEditIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	dir, apply := setup(t)
	before := snapshot(t, dir)

	_, err := apply(edit.Op{Kind: edit.Add, Collection: "todo", Data: map[string]any{"item": "rotate it, new token " + ghToken, "status": "待办"}})
	se := asSecretErr(t, err)
	if f := se.Findings[0]; f.Rule != secretscan.RuleGitHubToken || f.Collection != "todo" || f.Path != "/item" {
		t.Fatalf("%+v", f)
	}
	sameTree(t, before, snapshot(t, dir))

	id := "评估关闭路由器 WAN 上的 Web 后台"
	_, err = apply(edit.Op{Kind: edit.Edit, Collection: "todo", ID: id, Hash: hashOf(t, dir, "todo", id), Data: map[string]any{"item": "x", "scope": "password: hunter2hunter2", "status": "待办"}})
	if se := asSecretErr(t, err); se.Findings[0].Path != "/scope" || se.Findings[0].Rule != secretscan.RuleSecretAssign {
		t.Fatalf("%+v", se.Findings)
	}
	sameTree(t, before, snapshot(t, dir))

	// A clean edit still goes through.
	if _, err := apply(edit.Op{Kind: edit.Edit, Collection: "todo", ID: id, Hash: hashOf(t, dir, "todo", id), Data: map[string]any{"item": "clean", "status": "待办"}}); err != nil {
		t.Fatal(err)
	}
}

func TestSecretScanConfigAllowDisableAndOff(t *testing.T) {
	add := func(extra string) error {
		dir := testutil.CopyExample(t)
		f, _ := os.OpenFile(filepath.Join(dir, "rackbook.yml"), os.O_APPEND|os.O_WRONLY, 0o644)
		f.WriteString("\n" + extra + "\n")
		f.Close()
		cfg := testutil.LoadConfig(t, dir)
		_, err := edit.Apply(cfg, edit.Op{Kind: edit.Add, Collection: "todo", Data: map[string]any{"item": "token " + ghToken, "status": "待办"}})
		return err
	}
	if err := add(""); err == nil {
		t.Fatal("default must refuse")
	}
	if err := add("secret_scan:\n  allow:\n    - {rule: github-token, collection: todo, field: /item, value_sha256: " + secretscan.Hash(ghToken) + "}"); err != nil {
		t.Fatalf("allow by hash: %v", err)
	}
	if err := add("secret_scan:\n  allow:\n    - {rule: github-token, collection: todo, value_sha256: " + secretscan.Hash("something else") + "}"); err == nil {
		t.Fatal("an allow entry for another value must not help")
	}
	if err := add("secret_scan:\n  disable_rules: [github-token]"); err != nil {
		t.Fatalf("disable_rules: %v", err)
	}
	if err := add("secret_scan:\n  enabled: false"); err != nil {
		t.Fatalf("enabled false: %v", err)
	}
	if err := add("secret_scan:\n  extra_patterns:\n    - {id: mine, pattern: 'rotate'}"); err == nil {
		t.Fatal("extra pattern")
	}
}

func TestClearReferencesDoesNotTripOnAnOldSecretButCheckReportsIt(t *testing.T) {
	dir := refLedger(t)
	testutil.Replace(t, dir, "data/tasks.yml", "- {title: t1, owner: ann, reviewer: cy}", "- {title: t1, owner: ann, reviewer: cy, note: \"see token: abcdefgh12345\"}")
	cfg := testutil.LoadConfig(t, dir)
	var found bool
	for _, i := range validate.Run(ledger.Load(cfg, nil)) {
		if i.Rule == ledger.RuleSecret && i.Collection == "tasks" && i.ID == "t1" && i.Path == "/note" {
			found = true
			if strings.Contains(i.Message, "abcdefgh") || !strings.Contains(i.Message, "secret-assignment") {
				t.Fatalf("%+v", i)
			}
		}
	}
	if !found {
		t.Fatal("check must report the hand-committed secret")
	}
	// Clearing the reference rewrites t1; the secret that was already there
	// neither blocks the delete nor counts as introduced by it.
	res, err := edit.Apply(cfg, edit.Op{Kind: edit.Delete, Collection: "people", ID: "ann", ClearReferences: true})
	if err != nil || len(res.Cleared) != 2 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestEditingARecordThatAlreadyHoldsASecretOnlyRefusesNewOnes(t *testing.T) {
	dir, apply := setup(t)
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "scope: gw, status: 待决定", "scope: \"gw token: abcdefgh12345\", status: 待决定")
	id := "评估关闭路由器 WAN 上的 Web 后台"
	data := func(scope, status string) map[string]any {
		return map[string]any{"item": id, "scope": scope, "status": status}
	}
	edit1 := func(d map[string]any) error {
		_, err := apply(edit.Op{Kind: edit.Edit, Collection: "todo", ID: id, Hash: hashOf(t, dir, "todo", id), Data: d})
		return err
	}
	// Keeping the old one is allowed (check reports it), so the record can be fixed up.
	if err := edit1(data("gw token: abcdefgh12345", "待办")); err != nil {
		t.Fatal(err)
	}
	// A different, new secret is refused.
	asSecretErr(t, edit1(data("gw token: abcdefgh12345", "password: hunter2hunter2")))
	if err := edit1(data("gw", "待办")); err != nil {
		t.Fatal(err)
	}
}
