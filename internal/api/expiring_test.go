package api_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/testutil"
)

func TestExpiringAndMeta(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "schemas/todo.json", `"status":`, `"due": {"type": ["string", "null"], "x-rackbook": {"expires": true}}, "gone": {"type": ["string", "null"], "x-rackbook": {"revoked": true}}, "status":`)
	day := func(n int) string { return time.Now().UTC().AddDate(0, 0, n).Format("2006-01-02") }
	rows := fmt.Sprintf("- {item: late, status: 待办, due: %s}\n- {item: soon, status: 待办, due: %s}\n- {item: far, status: 待办, due: %s}\n- {item: tbd, status: 待办, due: 待补}\n- {item: retired, status: 待办, due: %s, gone: yes}\n", day(-2), day(3), day(100), day(-5))
	p := filepath.Join(dir, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, rows...), 0o644)
	f := newFixture(t, nil, dir)

	code, out, _ := f.do(t, "GET", "/api/expiring", nil, nil)
	items := arr(t, out["items"])
	if code != 200 || out["today"] != time.Now().UTC().Format("2006-01-02") || out["days"] != float64(30) || len(items) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	first := items[0].(map[string]any)
	if first["collection"] != "todo" || first["id"] != "late" || first["label"] != "late" || first["status"] != "expired" || first["daysLeft"] != float64(-2) || first["expires"] != day(-2) || first["source"] != "" {
		t.Fatalf("%v", first)
	}
	if items[1].(map[string]any)["id"] != "soon" {
		t.Fatalf("%v", items)
	}

	_, out, _ = f.do(t, "GET", "/api/expiring?days=365&unknown=true&collection=todo&collection=devices", nil, nil)
	items = arr(t, out["items"])
	if len(items) != 4 || out["days"] != float64(365) {
		t.Fatalf("%v", out)
	}
	last := items[3].(map[string]any)
	if last["id"] != "tbd" || last["status"] != "unknown" || last["daysLeft"] != nil {
		t.Fatalf("%v", last)
	}
	if _, out, _ = f.do(t, "GET", "/api/expiring?days=99999", nil, nil); out["days"] != float64(3650) {
		t.Fatalf("%v", out)
	}
	if _, out, _ = f.do(t, "GET", "/api/expiring?collection=devices", nil, nil); len(arr(t, out["items"])) != 0 {
		t.Fatalf("%v", out)
	}
	for _, q := range []string{"?days=abc", "?days=1.5"} {
		if code, out, _ := f.do(t, "GET", "/api/expiring"+q, nil, nil); code != 400 || out["error"] != "bad_request" {
			t.Fatalf("%s: %d %v", q, code, out)
		}
	}
	if code, out, _ := f.do(t, "GET", "/api/expiring?collection=nope", nil, nil); code != 404 || out["error"] != "not_found" {
		t.Fatalf("%d %v", code, out)
	}

	_, meta, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if mods, ok := meta["modules"].([]any); !ok || len(mods) != 0 {
		t.Fatalf("modules must be an empty array: %#v", meta["modules"])
	}
	for _, c := range arr(t, meta["collections"]) {
		c := c.(map[string]any)
		wantExp, wantRev := "", ""
		if c["name"] == "todo" {
			wantExp, wantRev = "due", "gone"
		}
		if c["expiryField"] != wantExp || c["revokedField"] != wantRev {
			t.Errorf("%v: %v %v", c["name"], c["expiryField"], c["revokedField"])
		}
	}
}
