package api_test

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/testutil"
)

// Assembled at run time: this file holds no string a scanner would flag.
var apiToken = "gh" + "p_" + strings.Repeat("a1B2", 9)

func tree(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			c, _ := os.ReadFile(p)
			b.WriteString(p + "\n" + string(c))
		}
		return nil
	})
	return b.String()
}

func wantSecret(t *testing.T, code int, r map[string]any, rule, path string) {
	t.Helper()
	if code != 422 || r["error"] != "secret_detected" {
		t.Fatalf("%d %v", code, r)
	}
	fs := arr(t, r["findings"])
	if len(fs) == 0 {
		t.Fatalf("no findings: %v", r)
	}
	f := fs[0].(map[string]any)
	if f["rule"] != rule || f["path"] != path || !strings.HasSuffix(f["excerpt"].(string), "…") {
		t.Fatalf("%v", f)
	}
	for _, v := range f {
		if s, ok := v.(string); ok && strings.Contains(s, apiToken[:8]) {
			t.Fatalf("finding leaks the secret: %v", f)
		}
	}
	if strings.Contains(r["message"].(string), apiToken[:8]) {
		t.Fatal("message leaks")
	}
}

func TestAPIRefusesSecretsOnCreateAndUpdate(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil, "")
	before := tree(t, f.dir)
	code, r, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "use " + apiToken, "status": "待办"}}, nil)
	wantSecret(t, code, r, "github-token", "/item")

	_, l, _ := f.do(t, "GET", "/api/c/todo", nil, nil)
	rec := arr(t, l["records"])[0].(map[string]any)
	id, hash := rec["id"].(string), rec["hash"].(string)
	code, r, _ = f.do(t, "PUT", "/api/c/todo/"+url.PathEscape(id), map[string]any{"hash": hash, "data": map[string]any{"item": "ok", "scope": "password: hunter2hunter2", "status": "待办"}}, nil)
	if code != 422 || r["error"] != "secret_suspected" || arr(t, r["findings"])[0].(map[string]any)["path"] != "/scope" {
		t.Fatalf("%d %v", code, r)
	}
	if tree(t, f.dir) != before {
		t.Fatal("a refused write changed files")
	}
	code, r, _ = f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "fine", "status": "待办"}}, nil)
	if code != 201 {
		t.Fatalf("%d %v", code, r)
	}
}

func TestCheckEndpointReportsHandCommittedSecrets(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "scope: gw, status: 待决定", "scope: \"gw "+apiToken+"\", status: 待决定")
	f := newFixture(t, nil, dir)
	code, c, _ := f.do(t, "GET", "/api/check", nil, nil)
	errs := arr(t, c["errors"])
	if code != 200 || c["ok"] != false || len(errs) != 1 {
		t.Fatalf("%d %v", code, c)
	}
	e := errs[0].(map[string]any)
	if e["rule"] != "secret" || e["collection"] != "todo" || e["path"] != "/scope" || strings.Contains(e["message"].(string), apiToken[:8]) {
		t.Fatalf("%v", e)
	}
}

func TestAPIRefusesSecretsInDataTypes(t *testing.T) {
	t.Parallel()
	f := adminFixture(t)
	before := tree(t, f.dir)
	ty := typeOf(t, f, "todo")
	ty["fields"] = append(arr(t, ty["fields"]), map[string]any{"name": "owner", "type": "text", "default": apiToken})
	code, r, _ := f.do(t, "PUT", "/api/types/todo", map[string]any{"type": ty}, nil)
	if code != 422 || r["error"] != "secret_detected" || arr(t, r["findings"])[0].(map[string]any)["path"] != "/schema/properties/owner/default" {
		t.Fatalf("%d %v", code, r)
	}
	// an example is data as well, on a new type
	nt := map[string]any{"name": "contacts", "title": "c", "key": []string{"name"}, "fields": []any{
		map[string]any{"name": "name", "type": "text", "required": true, "examples": []string{"sk" + "-" + "Ab12Cd34Ef56Gh78Ij90Kl12"}},
	}}
	code, r, _ = f.do(t, "POST", "/api/types", map[string]any{"type": nt}, nil)
	if code != 422 || r["error"] != "secret_detected" {
		t.Fatalf("%d %v", code, r)
	}
	if tree(t, f.dir) != before {
		t.Fatal("a refused type change wrote")
	}
	// the same type with a harmless example is created
	nt["fields"].([]any)[0].(map[string]any)["examples"] = []string{"alice"}
	if code, r, _ = f.do(t, "POST", "/api/types", map[string]any{"type": nt}, nil); code != 201 {
		t.Fatalf("%d %v", code, r)
	}
}

func TestTypeTitlesDescriptionsAndConfigEntryAreScanned(t *testing.T) {
	t.Parallel()
	f := adminFixture(t)
	before := tree(t, f.dir)
	for name, mut := range map[string]func(ty map[string]any){
		"type description":  func(ty map[string]any) { ty["description"] = "login with " + apiToken },
		"type title":        func(ty map[string]any) { ty["title"] = "pw " + apiToken },
		"field title":       func(ty map[string]any) { ty["fields"].([]any)[0].(map[string]any)["title"] = "token: " + apiToken },
		"field description": func(ty map[string]any) { ty["fields"].([]any)[0].(map[string]any)["description"] = apiToken },
	} {
		nt := map[string]any{"name": "contacts", "title": "c", "key": []string{"name"}, "fields": []any{map[string]any{"name": "name", "type": "text", "required": true}}}
		mut(nt)
		code, r, _ := f.do(t, "POST", "/api/types", map[string]any{"type": nt}, nil)
		if code != 422 || r["error"] != "secret_detected" {
			t.Fatalf("%s: %d %v", name, code, r)
		}
	}
	if tree(t, f.dir) != before {
		t.Fatal("a refused type change wrote")
	}
}
