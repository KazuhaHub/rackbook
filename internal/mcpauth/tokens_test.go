package mcpauth_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/tokens"
)

func (h *harness) createToken(body map[string]any) (string, map[string]any) {
	h.t.Helper()
	code, m, _ := h.do("POST", "/api/admin/tokens", "", body)
	if code != 201 {
		h.t.Fatalf("create token: %d %v", code, m)
	}
	return m["secret"].(string), m
}

func TestTokenLifecycle(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	secret, m := h.createToken(map[string]any{"name": "ci", "scope": "write", "collections": []string{"todo"}, "expiresDays": 30})
	if !strings.HasPrefix(secret, "rbk_") || len(secret) != 47 {
		t.Fatalf("%q", secret)
	}
	snip := m["snippet"].(map[string]any)
	if snip["type"] != "streamable-http" || !strings.HasSuffix(snip["url"].(string), "/mcp") || snip["headers"].(map[string]any)["Authorization"] != "Bearer "+secret {
		t.Fatalf("%v", snip)
	}
	if m["token"].(map[string]any)["prefix"] != secret[:12] {
		t.Fatalf("prefix: %v", m["token"])
	}
	// The commit is on main with the documented subject; only the hash is stored.
	if got := git(t, h.bare, "log", "-1", "--format=%an|%s", "main"); got != "Boss|rackbook(auth): create token ci" {
		t.Fatalf("%q", got)
	}
	file := git(t, h.bare, "show", "main:.rackbook/tokens.yml")
	if strings.Contains(file, secret) || !strings.Contains(file, tokens.HashSecret(secret)) {
		t.Fatalf("the secret must not be stored:\n%s", file)
	}
	// Duplicate names and bad input.
	if code, _, _ := h.do("POST", "/api/admin/tokens", "", map[string]any{"name": "ci", "scope": "read"}); code != 409 {
		t.Fatalf("%d", code)
	}
	for _, b := range []map[string]any{{"name": "Bad Name"}, {"name": "x", "scope": "admin"}, {"name": "x", "scope": "write", "collections": []string{"nope"}}, {"name": "x", "scope": "read", "actions": []string{"delete"}}, {"name": "x", "scope": "write", "writeMode": "push"}} {
		if code, _, _ := h.do("POST", "/api/admin/tokens", "", b); code != 400 {
			t.Fatalf("%v: %d", b, code)
		}
	}
	// tokens.yml is invisible as data.
	_, meta, _ := h.do("GET", "/api/meta", secret, nil)
	for _, c := range meta["collections"].([]any) {
		if strings.Contains(c.(map[string]any)["name"].(string), "token") {
			t.Fatal("tokens must not be a collection")
		}
	}
	// Reads, exports and llms accept the token; the console and admin API do not take it as a login.
	for _, p := range []string{"/api/c/todo", "/export.md", "/llms.txt"} {
		if code, _, _ := h.do("GET", p, secret, nil); code != 200 {
			t.Fatalf("%s: %d", p, code)
		}
	}
	if code, _, _ := h.do("GET", "/api/admin/tokens", secret, nil); code != 403 {
		t.Fatalf("a token must never manage tokens: %d", code)
	}
	// Write through the API: a pull request, as a token.
	code, r, _ := h.do("POST", "/api/c/todo", secret, map[string]any{"data": map[string]any{"item": "by token", "status": "待办"}})
	if code != 201 || r["pullRequest"] != true || h.gh.count() != 1 || !strings.HasPrefix(h.gh.prs[0]["head"], "rackbook/token/ci/") {
		t.Fatalf("%d %v %+v", code, r, h.gh.prs)
	}
	body := git(t, h.bare, "log", "-1", "--format=%an <%ae>%n%B", h.gh.prs[0]["head"])
	for _, want := range []string{"boss <boss@example.com>", "Edited-by: boss@example.com", "Edited-via: rackbook (token:ci)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q:\n%s", want, body)
		}
	}
	// Narrowed to todo: another collection is refused.
	if code, _, _ := h.do("POST", "/api/c/sites", secret, map[string]any{"data": map[string]any{"name": "z"}}); code != 403 {
		t.Fatalf("%d", code)
	}
	// Over MCP the same token writes through a PR with the MCP trailer.
	cs := h.mcpSession(secret)
	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "mcp token", "status": "待办"}})
	if isErr || out["pullRequest"] != true || h.gh.count() != 2 {
		t.Fatalf("%v", out)
	}
	if body := git(t, h.bare, "log", "-1", "--format=%B", h.gh.prs[1]["head"]); !strings.Contains(body, "Edited-via: mcp (token:ci)") {
		t.Fatal(body)
	}
	// Last used is kept in memory; list shows it.
	_, list, _ := h.do("GET", "/api/admin/tokens", "", nil)
	tk := list["tokens"].([]any)[0].(map[string]any)
	if tk["lastUsed"] == nil || tk["status"] != "active" || tk["creatorRole"] != "admin" || len(tk["warnings"].([]any)) != 0 {
		t.Fatalf("%v", tk)
	}
	if _, has := tk["sha256"]; has {
		t.Fatal("hash must not be listed")
	}

	// Expiry.
	h.now = h.now.Add(31 * 24 * time.Hour)
	if code, _, _ := h.do("GET", "/api/meta", secret, nil); code != 401 {
		t.Fatalf("expired: %d", code)
	}
	h.now = h.now.Add(-31 * 24 * time.Hour)
	if code, _, _ := h.do("GET", "/api/meta", secret, nil); code != 200 {
		t.Fatal("valid again")
	}
	// Revocation commits to Git and the entry stays.
	if code, _, _ := h.do("DELETE", "/api/admin/tokens/ci", "", nil); code != 200 {
		t.Fatalf("%d", code)
	}
	if got := git(t, h.bare, "log", "-1", "--format=%s", "main"); got != "rackbook(auth): revoke token ci" {
		t.Fatal(got)
	}
	if code, _, _ := h.do("GET", "/api/meta", secret, nil); code != 401 {
		t.Fatalf("revoked: %d", code)
	}
	if code, _, _ := h.do("DELETE", "/api/admin/tokens/nope", "", nil); code != 404 {
		t.Fatalf("%d", code)
	}
	_, list, _ = h.do("GET", "/api/admin/tokens", "", nil)
	if tk := list["tokens"].([]any)[0].(map[string]any); tk["status"] != "revoked" || tk["revokedBy"] != "boss@example.com" {
		t.Fatalf("%v", tk)
	}
	// The working tree stays clean (new file committed, nothing left over).
	if got := git(t, h.dir, "status", "--porcelain"); got != "" {
		t.Fatalf("dirty clone: %s", got)
	}
}

func TestReadTokenAndDirectPushToken(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	read, _ := h.createToken(map[string]any{"name": "ro", "scope": "read"})
	if code, _, _ := h.do("GET", "/api/c/todo", read, nil); code != 200 {
		t.Fatal(code)
	}
	if code, r, _ := h.do("POST", "/api/c/todo", read, map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}); code != 403 {
		t.Fatalf("a read token must not write: %d %v", code, r)
	}
	push, _ := h.createToken(map[string]any{"name": "pusher", "scope": "write", "writeMode": "push", "collections": []string{"todo"}, "actions": []string{"create", "update", "delete"}})
	code, r, _ := h.do("POST", "/api/c/todo", push, map[string]any{"data": map[string]any{"item": "pushed", "status": "待办"}})
	if code != 201 || r["pullRequest"] != nil || h.gh.count() != 0 {
		t.Fatalf("%d %v", code, r)
	}
	hash := r["hash"].(string)
	// Deletes are a PR even for a push token.
	code, r, _ = h.do("DELETE", "/api/c/todo/pushed?hash="+hash, push, nil)
	if code != 200 || r["pullRequest"] != true || h.gh.count() != 1 {
		t.Fatalf("%d %v", code, r)
	}
	// Actions narrowing.
	narrow, _ := h.createToken(map[string]any{"name": "creator", "scope": "write", "actions": []string{"create"}})
	if code, _, _ := h.do("DELETE", "/api/c/todo/pushed?hash=x", narrow, nil); code != 403 {
		t.Fatalf("%d", code)
	}
	if code, _, _ := h.do("PUT", "/api/c/todo/pushed", narrow, map[string]any{"hash": "x", "data": map[string]any{}}); code != 403 {
		t.Fatalf("%d", code)
	}
}

func TestTokenIsBoundedByItsCreatorsCurrentRole(t *testing.T) {
	// Without Git, so edits to rackbook.yml apply at once; nothing here needs a PR.
	h := newHarness(t, hopts{})
	secret, _ := h.createToken(map[string]any{"name": "w", "scope": "write", "collections": []string{"todo"}})
	cfg := filepath.Join(h.dir, "rackbook.yml")
	setRoles := func(body string) {
		b, _ := os.ReadFile(cfg)
		s := string(b)
		i := strings.Index(s, "  roles:\n")
		j := strings.Index(s, "  mcp:\n")
		os.WriteFile(cfg, []byte(s[:i]+"  roles:\n"+body+s[j:]), 0o644)
	}
	role := func() (int, string) {
		code, m, _ := h.do("GET", "/api/meta", secret, nil)
		if code != 200 {
			return code, ""
		}
		return code, m["user"].(map[string]any)["role"].(string)
	}
	if c, r := role(); c != 200 || r != "editor" {
		t.Fatalf("a write token is an editor at most, even for an admin creator: %d %s", c, r)
	}
	// Creator demoted to viewer: the token shrinks with it (and warns).
	setRoles("    viewer: [boss@example.com]\n")
	if c, r := role(); c != 200 || r != "viewer" {
		t.Fatalf("%d %s", c, r)
	}
	if code, _, _ := h.do("POST", "/api/c/todo", secret, map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}); code != 403 {
		t.Fatalf("%d", code)
	}
	// Creator without any role: the token stops working.
	setRoles("    admin: [someone@example.com]\n")
	if code, m, _ := h.do("GET", "/api/meta", secret, nil); code != 403 || m["error"] != "no_role" {
		t.Fatalf("%d %v", code, m)
	}
	// The list (as the new admin) warns.
	setRoles("    admin: [boss@example.com]\n    viewer: [boss@example.com]\n")
	_, list, _ := h.do("GET", "/api/admin/tokens", "", nil)
	tk := list["tokens"].([]any)[0].(map[string]any)
	if tk["creatorRole"] != "admin" {
		t.Fatalf("%v", tk) // highest role wins
	}
	setRoles("    admin: [boss@example.com]\n")
}

func TestFailedTokenAttemptsAreRateLimitedPerIP(t *testing.T) {
	h := newHarness(t, hopts{})
	bad := "rbk_" + strings.Repeat("a", 43)
	for i := 0; i < 10; i++ {
		if code, _, _ := h.do("GET", "/api/meta", bad, nil); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	code, m, hdr := h.do("GET", "/api/meta", bad, nil)
	if code != http.StatusTooManyRequests || m["error"] != "rate_limited" || hdr.Get("Retry-After") == "" {
		t.Fatalf("%d %v", code, m)
	}
	// A header from an untrusted peer does not move the bucket (no --trusted-proxy here).
	if code, _, _ := h.do("GET", "/api/meta", bad, nil, "CF-Connecting-IP", "203.0.113.9"); code != 429 {
		t.Fatalf("spoofed header must not help: %d", code)
	}
	// The limit also blocks a good token from that address until the window passes.
	secret, _ := h.createToken(map[string]any{"name": "ok", "scope": "read"})
	if code, _, _ := h.do("GET", "/api/meta", secret, nil); code != 429 {
		t.Fatalf("%d", code)
	}
	// Non-token requests are unaffected.
	if code, _, _ := h.do("GET", "/api/meta", "", nil); code != 200 {
		t.Fatal(code)
	}
}

func TestClearReferencesNeedsUpdateRightsOnTheReferencingCollections(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	secret, _ := h.createToken(map[string]any{"name": "dev-only", "scope": "write", "collections": []string{"devices"}, "actions": []string{"delete"}})
	id := "web-hostco-ashburn-va-us-dc" // referenced by services
	_, rec, _ := h.do("GET", "/api/c/devices/"+id, secret, nil)
	hash, _ := rec["hash"].(string)
	if hash == "" {
		t.Fatalf("no hash: %v", rec)
	}
	// Without clearing, the delete guard answers 409 (the token may delete devices).
	if code, _, _ := h.do("DELETE", "/api/c/devices/"+id+"?hash="+hash, secret, nil); code != 409 {
		t.Fatalf("referenced delete: %d", code)
	}
	// Clearing would edit services records, which this token may not update.
	if code, body, _ := h.do("DELETE", "/api/c/devices/"+id+"?hash="+hash+"&clearReferences=true", secret, nil); code != 403 {
		t.Fatalf("clearReferences must check the token on every edited collection: %d %v", code, body)
	}
}

// A token carries the auditor capability of its creator for as long as the
// creator is on auth.auditors, re-evaluated per request like the role.
func TestTokenCarriesTheAuditorCapabilityOfItsCreator(t *testing.T) {
	h := newHarness(t, hopts{})
	cfg := filepath.Join(h.dir, "rackbook.yml")
	setAuditors := func(list string) {
		t.Helper()
		b, _ := os.ReadFile(cfg)
		s := string(b)
		if i := strings.Index(s, "  auditors:"); i >= 0 {
			j := strings.Index(s[i:], "\n")
			s = s[:i] + s[i+j+1:]
		}
		if list != "" {
			s = strings.Replace(s, "  mcp:\n", "  auditors: ["+list+"]\n  mcp:\n", 1)
		}
		if err := os.WriteFile(cfg, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	user := func(secret string) map[string]any {
		t.Helper()
		code, m, _ := h.do("GET", "/api/meta", secret, nil)
		if code != 200 {
			t.Fatalf("%d %v", code, m)
		}
		return m["user"].(map[string]any)
	}

	// created while the creator (an admin) is not an auditor: an admin is not one automatically
	secret, _ := h.createToken(map[string]any{"name": "r", "scope": "read"})
	if u := user(secret); u["auditor"] != nil || u["role"] != "viewer" {
		t.Fatalf("%v", u)
	}
	// the creator is added to the list: the same token has the capability now
	setAuditors("boss@example.com")
	if u := user(secret); u["auditor"] != true || u["role"] != "viewer" {
		t.Fatalf("after adding the creator: %v", u)
	}
	_, list, _ := h.do("GET", "/api/admin/tokens", "", nil)
	if tk := list["tokens"].([]any)[0].(map[string]any); tk["creatorAuditor"] != true || tk["creatorRole"] != "admin" {
		t.Fatalf("%v", tk)
	}
	// still no writes, and the audit routes stay out of a token's reach
	if code, _, _ := h.do("POST", "/api/c/todo", secret, map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}); code != 403 {
		t.Fatalf("a read token wrote: %d", code)
	}
	if code, _, _ := h.do("GET", "/api/activity", secret, nil); code != 403 {
		t.Fatalf("a token reached the activity view: %d", code)
	}
	// a token made while the creator is an auditor has it too, and loses it with the creator's entry
	secret2, _ := h.createToken(map[string]any{"name": "w", "scope": "write", "collections": []string{"todo"}})
	if u := user(secret2); u["auditor"] != true || u["role"] != "editor" {
		t.Fatalf("%v", u)
	}
	setAuditors("")
	for _, s := range []string{secret, secret2} {
		if u := user(s); u["auditor"] != nil {
			t.Fatalf("after removal: %v", u)
		}
	}
	// the list matches by the creator's identity: another person's entry grants nothing
	setAuditors("someone@example.com")
	if u := user(secret); u["auditor"] != nil {
		t.Fatalf("%v", u)
	}
}
