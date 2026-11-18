package mcpauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/auth/oauth/oauthtest"
)

func TestProtectedResourceMetadataAndChallenges(t *testing.T) {
	h := newHarness(t, hopts{})
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		code, m, _ := h.do("GET", p, "", nil)
		if code != 200 || m["resource"] != resourceURL || m["authorization_servers"].([]any)[0] != h.iss.URL ||
			m["bearer_methods_supported"].([]any)[0] != "header" || m["scopes_supported"].([]any)[0] != "rackbook:write" {
			t.Fatalf("%s: %d %v", p, code, m)
		}
	}
	// A bad token on /mcp: 401 with the resource metadata in the challenge.
	code, m, hdr := h.do("POST", "/mcp", "garbage", map[string]any{})
	if code != 401 || m["error"] != "invalid_token" || !strings.Contains(hdr.Get("WWW-Authenticate"), `resource_metadata="http://localhost:9999/.well-known/oauth-protected-resource"`) ||
		!strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("%d %v %v", code, m, hdr)
	}
	// A real JWT is accepted only on /mcp: on the API it is ignored (auth none: the console user).
	tok := h.jwt(oauthtest.Options{Subject: "alice"})
	if code, m, _ := h.do("GET", "/api/meta", tok, nil); code != 200 || m["user"].(map[string]any)["authMethod"] != "none" {
		t.Fatalf("a JWT must not authenticate /api: %d %v", code, m)
	}
	// A user with no role: 403 insufficient_scope.
	code, m, hdr = h.do("POST", "/mcp", h.jwt(oauthtest.Options{Subject: "mallory"}), map[string]any{})
	if code != 403 || m["error"] != "no_role" || !strings.Contains(hdr.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("%d %v %v", code, m, hdr)
	}
	// Expired and wrong audience.
	for _, o := range []oauthtest.Options{{Exp: h.now.Add(-time.Hour)}, {Audience: "http://localhost:9999/other"}} {
		if code, _, _ := h.do("POST", "/mcp", h.jwt(o), map[string]any{}); code != 401 {
			t.Fatalf("%+v: %d", o, code)
		}
	}
}

func TestMCPHubUserReadsAndWritesViaPullRequest(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "Alice", Scope: "rackbook:write", ClientID: "cursor"}))

	if out, isErr := call(t, cs, "list_problems", nil); isErr || out["ok"] != true {
		t.Fatalf("%v", out)
	}
	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "via mcp", "status": "待办"}})
	if isErr || out["pullRequest"] != true || out["url"] != "https://github.com/acme/ledger/pull/1" || out["commit"] != nil {
		t.Fatalf("%v", out)
	}
	if h.gh.count() != 1 || !strings.HasPrefix(h.gh.prs[0]["head"], "rackbook/mcp/alice/") || h.gh.prs[0]["base"] != "main" {
		t.Fatalf("%+v", h.gh.prs)
	}
	if git(t, h.bare, "rev-list", "--count", "main") != "1" {
		t.Fatal("main must not move")
	}
	body := git(t, h.bare, "log", "-1", "--format=%an <%ae>%n%B", h.gh.prs[0]["head"])
	for _, want := range []string{"Alice <alice>", "Edited-by: alice", "Edited-via: mcp (MCPHub, client cursor)", "Record: todo/via mcp"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if !strings.Contains(h.gh.prs[0]["body"], "Edited-via: mcp (MCPHub, client cursor)") {
		t.Fatalf("PR body: %q", h.gh.prs[0]["body"])
	}
	// Invalid data is refused exactly like the API.
	out, isErr = call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"status": "待办"}})
	if !isErr || out["error"] != "invalid" || out["errors"] == nil {
		t.Fatalf("%v", out)
	}
	if h.gh.count() != 1 {
		t.Fatal("an invalid write must not open a PR")
	}
	// Update needs a hash, and goes through a PR too.
	hash := todoRecord(t, cs, "所有服务器 SSH 改到 10511")
	out, isErr = call(t, cs, "update_record", map[string]any{"collection": "todo", "id": "所有服务器 SSH 改到 10511", "hash": hash,
		"data": map[string]any{"item": "所有服务器 SSH 改到 10511", "scope": "所有服务器", "status": "完成（2026-11-02）"}})
	if isErr || out["pullRequest"] != true || h.gh.count() != 2 {
		t.Fatalf("%v", out)
	}
	// The hash is required by the tool's schema.
	if res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "update_record", Arguments: map[string]any{"collection": "todo", "id": "x", "data": map[string]any{}}}); err == nil && !res.IsError {
		t.Fatal("hash is required")
	}
	// A stale hash conflicts (main did not change, so use a wrong one).
	if out, isErr = call(t, cs, "update_record", map[string]any{"collection": "todo", "id": "所有服务器 SSH 改到 10511", "hash": "deadbeef",
		"data": map[string]any{"item": "所有服务器 SSH 改到 10511", "status": "完成"}}); !isErr || out["error"] != "conflict" {
		t.Fatalf("%v", out)
	}
	// History of a record is readable.
	if out, isErr = call(t, cs, "record_history", map[string]any{"collection": "todo", "id": "所有服务器 SSH 改到 10511"}); isErr || out["commits"] == nil {
		t.Fatalf("%v", out)
	}
}

func TestScopeNarrowsAndRolesDecide(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	// No write scope: reads work, writes are refused with insufficient_scope.
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "other"}))
	if _, isErr := call(t, cs, "list_collections", nil); isErr {
		t.Fatal("read must work")
	}
	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "x", "status": "待办"}})
	if !isErr || out["error"] != "insufficient_scope" {
		t.Fatalf("%v", out)
	}
	// A viewer never writes, even with the write scope: the scope cannot widen the role.
	cs = h.mcpSession(h.jwt(oauthtest.Options{Subject: "vic", Scope: "rackbook:write"}))
	out, isErr = call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "x", "status": "待办"}})
	if !isErr || out["error"] != "forbidden" {
		t.Fatalf("%v", out)
	}
	out, isErr = call(t, cs, "delete_record", map[string]any{"collection": "todo", "id": "x", "hash": "h"})
	if !isErr || out["error"] != "forbidden" {
		t.Fatalf("%v", out)
	}
	if h.gh.count() != 0 {
		t.Fatal("nothing may be opened")
	}
}

func TestDirectPushAndDeletesAlwaysPR(t *testing.T) {
	h := newHarness(t, hopts{git: true, mcpYAML: "    direct_push:\n      - {users: [\"mcphub:alice\"], collections: [todo]}\n"})
	alice := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	// Listed user + collection: a create goes straight to main.
	out, isErr := call(t, alice, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "direct", "status": "待办"}})
	if isErr || out["pullRequest"] != false || out["commit"] == nil || h.gh.count() != 0 {
		t.Fatalf("%v", out)
	}
	if git(t, h.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("main must have moved")
	}
	if got := git(t, h.bare, "log", "-1", "--format=%B", "main"); !strings.Contains(got, "Edited-via: mcp (MCPHub, client client-1)") {
		t.Fatal(got)
	}
	// ... but a delete is a PR anyway.
	hash := todoRecord(t, alice, "direct")
	out, isErr = call(t, alice, "delete_record", map[string]any{"collection": "todo", "id": "direct", "hash": hash})
	if isErr || out["pullRequest"] != true || h.gh.count() != 1 {
		t.Fatalf("%v", out)
	}
	if git(t, h.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("a delete must not reach main")
	}
	// Another user, same collection: PR. Same user, another collection: PR.
	ed := h.mcpSession(h.jwt(oauthtest.Options{Subject: "ed", Scope: "rackbook:write"}))
	if out, _ = call(t, ed, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "ed", "status": "待办"}}); out["pullRequest"] != true {
		t.Fatalf("%v", out)
	}
	out, _ = call(t, alice, "create_record", map[string]any{"collection": "sites", "data": map[string]any{"name": "zzz"}})
	if out["pullRequest"] == false {
		t.Fatalf("direct_push must be limited to the listed collection: %v", out)
	}
}

func TestWritesFailLikeTheAPIWhenTheStoreIsNotHealthy(t *testing.T) {
	// No Git: a pull request cannot be opened, the error says so.
	h := newHarness(t, hopts{})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "x", "status": "待办"}})
	if !isErr || out["error"] != "pull_request_unavailable" {
		t.Fatalf("%v", out)
	}
	// A rewritten remote history pauses writes with the API's error code.
	g := newHarness(t, hopts{git: true})
	git(t, g.dir, "fetch", "-q", "origin")
	other := t.TempDir()
	git(t, other, "clone", "-q", g.bare, "w")
	w := other + "/w"
	git(t, w, "commit", "-q", "--allow-empty", "-m", "extra")
	git(t, w, "push", "-q", "origin", "main")
	g.store.Pull(t.Context())
	// Rewrite: a new root commit replaces main on the remote (done on the bare repo directly).
	git(t, g.bare, "update-ref", "refs/heads/main", git(t, g.bare, "commit-tree", "-m", "rewritten", "main^{tree}"))
	g.store.Pull(t.Context())
	cs = g.mcpSession(g.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	out, isErr = call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "x", "status": "待办"}})
	if !isErr || out["error"] != "history_rewritten" || out["lastGood"] == nil {
		t.Fatalf("%v", out)
	}
	if p, _ := call(t, cs, "list_problems", nil); p["ok"] != false || len(p["store"].([]any)) != 1 {
		t.Fatalf("%v", p)
	}
}

func TestAnyOAuthIssuerEntraStyle(t *testing.T) {
	// An Entra-like issuer: RS256, typ JWT, scp scopes, a /v2.0 path, OIDC metadata only.
	entra := oauthtest.NewWith(t, oauthtest.Config{Alg: "RS256", Path: "/v2.0", Discovery: "oidc"})
	h := newHarness(t, hopts{git: true,
		rolesYAML:   "    admin: [boss@example.com]\n    editor: [\"oauth:entra:alice@example.com\", \"carol@example.com\"]\n",
		extraIssuer: "issuer: " + entra.URL + ", alias: entra, audience: \"api://rackbook\", require_typ_at_jwt: false, username_claim: preferred_username, algorithms: [RS256]",
		mcpYAML:     "    scopes: {write: rackbook.write}\n"})
	mint := func(user string) string {
		return entra.Mint(oauthtest.Options{Audience: "api://rackbook", Typ: "JWT", ClientID: "-", Now: h.now, Scp: "rackbook.write profile",
			Extra: map[string]any{"preferred_username": user, "azp": "app-1"}})
	}
	// Not in any role.
	if code, _, _ := h.do("POST", "/mcp", mint("mallory@example.com"), map[string]any{}); code != 403 {
		t.Fatalf("%d", code)
	}
	cs := h.mcpSession(mint("Alice@Example.com"))
	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "entra", "status": "待办"}})
	if isErr || out["pullRequest"] != true {
		t.Fatalf("%v", out)
	}
	if !strings.HasPrefix(h.gh.prs[0]["head"], "rackbook/mcp/alice-example-com/") {
		t.Fatalf("%v", h.gh.prs[0])
	}
	if body := git(t, h.bare, "log", "-1", "--format=%B", h.gh.prs[0]["head"]); !strings.Contains(body, "Edited-by: alice@example.com") || !strings.Contains(body, "Edited-via: mcp (entra, client app-1)") {
		t.Fatal(body)
	}
	// carol is listed by plain e-mail: without match_email an OAuth identity does not match it.
	if code, _, _ := h.do("POST", "/mcp", mint("carol@example.com"), map[string]any{}); code != 403 {
		t.Fatalf("e-mail entries need match_email: %d", code)
	}
	// An ID token (aud = the client, nonce, no scope) is refused as an access token.
	idTok := entra.Mint(oauthtest.Options{Audience: "app-1", Typ: "JWT", ClientID: "-", Now: h.now, Extra: map[string]any{"nonce": "n", "preferred_username": "alice@example.com"}})
	if code, _, _ := h.do("POST", "/mcp", idTok, map[string]any{}); code != 401 {
		t.Fatalf("%d", code)
	}
}

func TestMatchEmailUsesOnlyVerifiedEmails(t *testing.T) {
	entra := oauthtest.NewWith(t, oauthtest.Config{Alg: "RS256", Path: "/v2.0", Discovery: "oidc"})
	h := newHarness(t, hopts{git: true,
		rolesYAML:   "    admin: [boss@example.com]\n    editor: [\"carol@example.com\"]\n",
		extraIssuer: "issuer: " + entra.URL + ", alias: entra, audience: \"api://rackbook\", require_typ_at_jwt: false, username_claim: preferred_username, algorithms: [RS256]",
		mcpYAML:     "    match_email: true\n    scopes: {write: rackbook.write}\n"})
	mint := func(extra map[string]any) string {
		extra["preferred_username"] = "carol@example.com"
		return entra.Mint(oauthtest.Options{Audience: "api://rackbook", Typ: "JWT", ClientID: "-", Now: h.now, Scp: "rackbook.write", Extra: extra})
	}
	// A username that looks like an address, or an unverified email, grants nothing.
	for name, extra := range map[string]map[string]any{
		"username only":    {},
		"unverified email": {"email": "carol@example.com"},
		"email_verified 0": {"email": "carol@example.com", "email_verified": false},
	} {
		if code, _, _ := h.do("POST", "/mcp", mint(extra), map[string]any{}); code != 403 {
			t.Errorf("%s: %d, want 403", name, code)
		}
	}
	if code, _, _ := h.do("POST", "/mcp", mint(map[string]any{"email": "carol@example.com", "email_verified": true}), map[string]any{}); code == 403 || code == 401 {
		t.Errorf("a verified email must match: %d", code)
	}
}
