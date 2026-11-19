package mcpauth_test

import (
	"strings"
	"testing"
	"time"
)

const panelYAML = `modules:
  bot:
    type: entra
    token: bot-token
    collection: todo
    fields: [status]
  notify:
    token: notify-token
    settings:
      thresholds: [30, 7]
`

func runBody(status string) map[string]any {
	return map[string]any{
		"started": "2026-11-18T03:00:00Z", "finished": "2026-11-18T03:00:05Z", "status": status,
		"counts": map[string]any{"created": 2, "updated": 1},
	}
}

type panel struct {
	h                  *harness
	bot, notify, other string
}

func newPanel(t *testing.T) *panel {
	t.Helper()
	h := newHarness(t, hopts{git: true, modules: panelYAML})
	p := &panel{h: h}
	p.bot, _ = h.createToken(map[string]any{"name": "bot-token", "scope": "write"})
	p.notify, _ = h.createToken(map[string]any{"name": "notify-token", "scope": "read"})
	p.other, _ = h.createToken(map[string]any{"name": "plain-token", "scope": "read"})
	return p
}

func (p *panel) version(t *testing.T, name string) string {
	t.Helper()
	_, r, _ := p.h.do("GET", "/api/modules/"+name+"/settings", "", nil)
	return r["version"].(string)
}

func TestModuleTokensReadOnlyTheirOwnSettings(t *testing.T) {
	p := newPanel(t)
	h := p.h
	code, r, _ := h.do("GET", "/api/modules/notify/settings", p.notify, nil)
	if code != 200 || r["type"] != "notify" || r["settings"].(map[string]any)["thresholds"].([]any)[0] != float64(30) || r["runRequest"] != "" {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := h.do("GET", "/api/modules/notify/settings", p.bot, nil); code != 403 || r["error"] != "forbidden" {
		t.Fatalf("another module's token: %d %v", code, r)
	}
	if code, _, _ := h.do("GET", "/api/modules/notify/settings", p.other, nil); code != 403 {
		t.Fatalf("a token that is no module: %d", code)
	}
	if code, _, _ := h.do("GET", "/api/modules/ghost/settings", p.notify, nil); code != 403 {
		t.Fatalf("unknown module for a module token: %d", code)
	}
	if code, _, _ := h.do("GET", "/api/modules/ghost/settings", "", nil); code != 404 {
		t.Fatalf("unknown module for an admin: %d", code)
	}
	// the admin endpoints are for people, whatever the token
	for _, c := range [][2]string{{"GET", "/api/modules"}, {"PUT", "/api/modules/notify/settings"}, {"POST", "/api/modules/notify/preview"}, {"POST", "/api/modules/notify/run-request"}} {
		var body any
		if c[0] != "GET" {
			body = map[string]any{"version": "x", "settings": map[string]any{}}
		}
		for _, tok := range []string{p.notify, p.bot, p.other} {
			if code, _, _ := h.do(c[0], c[1], tok, body); code != 403 {
				t.Fatalf("%s %s with a token: %d", c[0], c[1], code)
			}
		}
	}
}

func TestUnauthorizedCallersCannotProbeModuleNames(t *testing.T) {
	p := newPanel(t)
	h := p.h
	for _, tok := range []string{p.bot, p.other} {
		real, _, _ := h.do("GET", "/api/modules/notify/settings", tok, nil)
		ghost, _, _ := h.do("GET", "/api/modules/ghost/settings", tok, nil)
		if real != 403 || ghost != 403 {
			t.Fatalf("settings: existing %d, unknown %d; both must be 403", real, ghost)
		}
		real, _, _ = h.do("POST", "/api/modules/notify/runs", tok, runBody("ok"))
		ghost, _, _ = h.do("POST", "/api/modules/ghost/runs", tok, runBody("ok"))
		if real != 403 || ghost != 403 {
			t.Fatalf("runs: existing %d, unknown %d; both must be 403", real, ghost)
		}
	}
}

func TestRunFromAFastClockIsAccepted(t *testing.T) {
	p := newPanel(t)
	body := runBody("ok")
	body["started"], body["finished"] = "2099-01-01T00:00:00Z", "2099-01-01T00:00:01Z"
	if code, _, _ := p.h.do("POST", "/api/modules/bot/runs", p.bot, body); code != 400 {
		t.Fatalf("far future: %d", code)
	}
	now := time.Now().UTC()
	body["started"], body["finished"] = now.Add(2*time.Hour).Format(time.RFC3339), now.Add(2*time.Hour+time.Second).Format(time.RFC3339)
	if code, _, _ := p.h.do("POST", "/api/modules/bot/runs", p.bot, body); code != 201 {
		t.Fatalf("a clock two hours fast: %d", code)
	}
	_, list, _ := p.h.do("GET", "/api/modules", "", nil)
	last := list["modules"].([]any)[0].(map[string]any)["lastRun"].(map[string]any)
	if last["started"] != body["started"] {
		t.Fatalf("stored %v, reported %v", last["started"], body["started"])
	}
}

func TestModuleReportsOnlyItsOwnRuns(t *testing.T) {
	p := newPanel(t)
	h := p.h
	if code, r, _ := h.do("POST", "/api/modules/bot/runs", p.bot, runBody("ok")); code != 201 || r["ok"] != true {
		t.Fatalf("%d %v", code, r)
	}
	for name, tok := range map[string]string{"notify's token": p.notify, "a plain token": p.other, "an admin session": ""} {
		if code, r, _ := h.do("POST", "/api/modules/bot/runs", tok, runBody("ok")); code != 403 {
			t.Fatalf("%s: %d %v", name, code, r)
		}
	}
	for name, body := range map[string]map[string]any{
		"status":   runBody("done"),
		"no times": {"status": "ok"},
		"future":   {"started": "2099-01-01T00:00:00Z", "finished": "2099-01-01T00:00:01Z", "status": "ok"},
		"negative": {"started": "2026-11-18T03:00:00Z", "finished": "2026-11-18T03:00:05Z", "status": "ok", "counts": map[string]any{"sent": -3}},
	} {
		if code, _, _ := h.do("POST", "/api/modules/bot/runs", p.bot, body); code != 400 {
			t.Fatalf("%s: %d", name, code)
		}
	}
	failed := runBody("failed")
	failed["error"] = "graph: 403\nforbidden"
	failed["started"], failed["finished"] = "2026-11-18T04:00:00Z", "2026-11-18T04:00:05Z"
	if code, _, _ := h.do("POST", "/api/modules/bot/runs", p.bot, failed); code != 201 {
		t.Fatal(code)
	}
	_, list, _ := h.do("GET", "/api/modules", "", nil)
	mods := list["modules"].([]any)
	bot := mods[0].(map[string]any)
	if bot["name"] != "bot" || bot["type"] != "entra" || bot["status"] != "failed" || bot["tokenStatus"] != "active" || len(bot["runs"].([]any)) != 2 {
		t.Fatalf("%v", bot)
	}
	if last := bot["lastRun"].(map[string]any); last["error"] != "graph: 403 forbidden" {
		t.Fatalf("error text: %v", last)
	}
	if bot["lastOk"] == nil || bot["nextRun"] == nil || bot["schedule"].(map[string]any)["default"] != true {
		t.Fatalf("%v", bot)
	}
	notify := mods[1].(map[string]any)
	if notify["status"] != "never" || notify["readOnly"] != true || notify["lastRun"] != nil || notify["due"] != true {
		t.Fatalf("%v", notify)
	}
	// notify may read the status of every module; nobody else but an admin
	code, st, _ := h.do("GET", "/api/modules/status", p.notify, nil)
	sm := st["modules"].([]any)
	if code != 200 || len(sm) != 2 || sm[0].(map[string]any)["lastRun"].(map[string]any)["status"] != "failed" {
		t.Fatalf("%d %v", code, st)
	}
	for _, tok := range []string{p.bot, p.other} {
		if code, _, _ := h.do("GET", "/api/modules/status", tok, nil); code != 403 {
			t.Fatalf("status for another token: %d", code)
		}
	}
	if code, _, _ := h.do("GET", "/api/modules/status", "", nil); code != 200 {
		t.Fatal("an admin reads the status")
	}
}

func TestSettingsAreSavedAsAGitCommitWithAVersionCheck(t *testing.T) {
	p := newPanel(t)
	h := p.h
	ver := p.version(t, "notify")
	save := map[string]any{"version": ver, "settings": map[string]any{
		"thresholds": []any{30, 7, 1}, "recipients": []any{"ops@example.org", "sec@example.org"}, "send_at": []any{"09:00"}, "timezone": "Asia/Shanghai", "language": "zh",
	}}
	code, r, _ := h.do("PUT", "/api/modules/notify/settings", "", save)
	if code != 200 || r["changed"] != true || r["commit"] == "" || r["version"] == ver {
		t.Fatalf("%d %v", code, r)
	}
	if got := git(t, h.bare, "log", "-1", "--format=%an|%s", "main"); got != "Boss|modules(notify): change language, recipients, send_at, thresholds, timezone" {
		t.Fatalf("commit: %q", got)
	}
	yml := git(t, h.bare, "show", "main:rackbook.yml")
	if !strings.Contains(yml, "    settings:\n      send_at: [\"09:00\"]") || !strings.Contains(yml, "recipients: [ops@example.org, sec@example.org]") {
		t.Fatalf("rackbook.yml:\n%s", yml)
	}
	// the module sees it at once, with the new version
	_, got, _ := h.do("GET", "/api/modules/notify/settings", p.notify, nil)
	if got["version"] != r["version"] || got["settings"].(map[string]any)["timezone"] != "Asia/Shanghai" {
		t.Fatalf("%v", got)
	}
	// a second save from the old version is a conflict that carries the current one
	code, c, _ := h.do("PUT", "/api/modules/notify/settings", "", save)
	if code != 409 || c["error"] != "conflict" || c["current"].(map[string]any)["version"] != r["version"] {
		t.Fatalf("%d %v", code, c)
	}
	before := git(t, h.bare, "rev-parse", "main")
	// invalid values, unknown keys and a stale-free resend with no change write nothing
	cur := r["version"].(string)
	for name, settings := range map[string]map[string]any{
		"unknown key": {"smtp_password": "x"},
		"threshold":   {"thresholds": []any{99999}},
		"email":       {"recipients": []any{"nobody"}},
		"zone":        {"timezone": "Mars/Base"},
		"collection":  {"collections": []any{"nope"}},
		"time":        {"send_at": []any{"25:00"}},
	} {
		if code, r, _ := h.do("PUT", "/api/modules/notify/settings", "", map[string]any{"version": cur, "settings": settings}); code != 422 || r["error"] != "refused" {
			t.Fatalf("%s: %d %v", name, code, r)
		}
	}
	if code, _, _ := h.do("PUT", "/api/modules/notify/settings", "", map[string]any{"settings": map[string]any{}}); code != 422 {
		t.Fatalf("no version: %d", code)
	}
	if code, r, _ := h.do("PUT", "/api/modules/notify/settings", "", map[string]any{"version": cur, "settings": save["settings"]}); code != 200 || r["changed"] != false {
		t.Fatalf("no change: %d %v", code, r)
	}
	if git(t, h.bare, "rev-parse", "main") != before {
		t.Fatal("a refused or empty change reached the repository")
	}
	// tokens cannot save, even the module's own
	if code, _, _ := h.do("PUT", "/api/modules/notify/settings", p.notify, map[string]any{"version": cur, "settings": map[string]any{}}); code != 403 {
		t.Fatalf("module token saved settings: %d", code)
	}
}

func TestRunNowAndPause(t *testing.T) {
	p := newPanel(t)
	h := p.h
	code, r, _ := h.do("POST", "/api/modules/bot/run-request", "", map[string]any{})
	if code != 200 {
		t.Fatalf("%d %v", code, r)
	}
	id := r["runRequest"].(map[string]any)["id"].(string)
	if _, again, _ := h.do("POST", "/api/modules/bot/run-request", "", map[string]any{}); again["runRequest"].(map[string]any)["id"] != id {
		t.Fatal("a second request must return the waiting one")
	}
	_, got, _ := h.do("GET", "/api/modules/bot/settings", p.bot, nil)
	if got["runRequest"] != id {
		t.Fatalf("the module must see the request: %v", got)
	}
	_, list, _ := h.do("GET", "/api/modules", "", nil)
	if rr := list["modules"].([]any)[0].(map[string]any)["runRequest"]; rr == nil || rr.(map[string]any)["id"] != id {
		t.Fatalf("%v", rr)
	}
	body := runBody("ok")
	body["run_request"] = id
	if code, _, _ := h.do("POST", "/api/modules/bot/runs", p.bot, body); code != 201 {
		t.Fatal(code)
	}
	if _, got, _ = h.do("GET", "/api/modules/bot/settings", p.bot, nil); got["runRequest"] != "" {
		t.Fatalf("the request must be cleared by its run: %v", got)
	}
	// pause it: the request is refused and the module sees paused in its settings
	ver := p.version(t, "bot")
	if code, r, _ := h.do("PUT", "/api/modules/bot/settings", "", map[string]any{"version": ver, "settings": map[string]any{"paused": true}}); code != 200 {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := h.do("POST", "/api/modules/bot/run-request", "", map[string]any{}); code != 409 || r["error"] != "paused" {
		t.Fatalf("%d %v", code, r)
	}
	_, got, _ = h.do("GET", "/api/modules/bot/settings", p.bot, nil)
	if got["settings"].(map[string]any)["paused"] != true {
		t.Fatalf("%v", got)
	}
	_, list, _ = h.do("GET", "/api/modules", "", nil)
	if bot := list["modules"].([]any)[0].(map[string]any); bot["paused"] != true || bot["nextRun"] != nil {
		t.Fatalf("%v", bot)
	}
	if code, _, _ := h.do("POST", "/api/modules/ghost/run-request", "", map[string]any{}); code != 404 {
		t.Fatal(code)
	}
}

func TestPreviewAndConfirmationOverTheAPI(t *testing.T) {
	p := newPanel(t)
	h := p.h
	ver := p.version(t, "bot")
	app := "11111111-2222-3333-4444-555555555555"
	settings := map[string]any{"exclude_app_ids": []any{app}}
	code, r, _ := h.do("POST", "/api/modules/bot/preview", "", map[string]any{"settings": settings})
	if code != 200 || r["risky"] != true || len(r["records"].([]any)) != 0 {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := h.do("POST", "/api/modules/bot/preview", "", map[string]any{"settings": map[string]any{"exclude_app_ids": []any{"x"}}}); code != 422 {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := h.do("PUT", "/api/modules/bot/settings", "", map[string]any{"version": ver, "settings": settings}); code != 200 || r["changed"] != true {
		t.Fatalf("%d %v", code, r)
	}
}

func TestTokenPageAndMetaNameTheModule(t *testing.T) {
	p := newPanel(t)
	_, r, _ := p.h.do("GET", "/api/admin/tokens", "", nil)
	byName := map[string]string{}
	for _, tk := range r["tokens"].([]any) {
		m := tk.(map[string]any)
		mod, _ := m["module"].(string)
		byName[m["name"].(string)] = mod
	}
	if byName["bot-token"] != "bot" || byName["notify-token"] != "notify" || byName["plain-token"] != "" {
		t.Fatalf("%v", byName)
	}
	_, meta, _ := p.h.do("GET", "/api/meta", "", nil)
	mods := meta["modules"].([]any)
	if m0 := mods[0].(map[string]any); m0["type"] != "entra" || m0["readOnly"] != false {
		t.Fatalf("%v", m0)
	}
	if m1 := mods[1].(map[string]any); m1["type"] != "notify" || m1["readOnly"] != true || m1["collection"] != "" {
		t.Fatalf("%v", m1)
	}
}
