package oauthserver_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Two requests with the same token at the same moment get the same answer, and
// so does every repeat inside the grace window: both sessions hold the same
// refresh token and keep working through several rotations.
func TestConcurrentRefreshesGetTheSameAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	cur := tok.refresh
	for round := 0; round < 4; round++ {
		var wg sync.WaitGroup
		out := make([]resp, 3)
		for i := range out {
			wg.Add(1)
			go func() { defer wg.Done(); out[i] = e.refresh(cid, cur) }()
		}
		wg.Wait()
		for i, r := range out {
			if r.StatusCode != 200 || string(r.body) != string(out[0].body) {
				t.Fatalf("round %d, request %d: %d %s (first: %s)", round, i, r.StatusCode, r.body, out[0].body)
			}
		}
		if e.mcpStatus(out[0].str("access_token")).StatusCode != 200 {
			t.Fatal("the answer's access token does not work")
		}
		cur = out[0].str("refresh_token")
		e.clock.advance(5 * time.Minute)
	}
}

// A response that never arrived: the retry inside the grace window gets exactly
// the same answer, and the state does not change.
func TestRetryAfterLostResponse(t *testing.T) {
	t.Parallel()
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	first := e.refresh(cid, tok.refresh)
	before, _ := os.ReadFile(filepath.Join(e.dir, "oauth-grants.json"))
	e.clock.advance(30 * time.Second)
	retry := e.refresh(cid, tok.refresh)
	if retry.StatusCode != 200 || string(retry.body) != string(first.body) {
		t.Fatalf("retry: %d %s (first: %s)", retry.StatusCode, retry.body, first.body)
	}
	if after, _ := os.ReadFile(filepath.Join(e.dir, "oauth-grants.json")); string(after) != string(before) {
		t.Fatal("a replayed answer changed the state file")
	}
	if r := e.refresh(cid, first.str("refresh_token")); r.StatusCode != 200 {
		t.Fatalf("the refresh token from the answer: %s", r.body)
	}
}

// Inside the grace window a thief with the old token gets the very same answer
// (the grace cannot tell them apart; that is the price of tolerating a lost
// response), so nothing is gained from a single replay. After the window the
// replay ends the grant.
func TestThiefReplayInsideAndAfterGrace(t *testing.T) {
	t.Parallel()
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	legit := e.refresh(cid, tok.refresh)
	e.clock.advance(10 * time.Second)
	thief := e.refresh(cid, tok.refresh)
	if thief.StatusCode != 200 || string(thief.body) != string(legit.body) {
		t.Fatalf("replay inside the grace: %d %s", thief.StatusCode, thief.body)
	}
	e.clock.advance(61 * time.Second)
	if r := e.refresh(cid, tok.refresh); r.StatusCode != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("replay after the grace: %d %s", r.StatusCode, r.body)
	}
	if r := e.refresh(cid, legit.str("refresh_token")); r.str("error") != "invalid_grant" {
		t.Fatalf("the grant survived a replay after the grace: %s", r.body)
	}
	if e.mcpStatus(legit.str("access_token")).StatusCode != 401 {
		t.Fatal("access token of a revoked grant works")
	}
}

// A token from an older rotation ends the grant.
func TestOldGenerationReuseRevokes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	t1 := e.refresh(cid, tok.refresh)
	e.clock.advance(2 * time.Minute)
	t2 := e.refresh(cid, t1.str("refresh_token"))
	if t2.StatusCode != 200 {
		t.Fatalf("second rotation: %s", t2.body)
	}
	if r := e.refresh(cid, tok.refresh); r.StatusCode != 400 {
		t.Fatalf("old generation: %d %s", r.StatusCode, r.body)
	}
	if r := e.refresh(cid, t2.str("refresh_token")); r.str("error") != "invalid_grant" {
		t.Fatalf("grant survived old-generation reuse: %s", r.body)
	}
}

// The remembered answers are only in memory: after a restart inside the grace
// window the old token is refused, the grant is not revoked, and the token the
// client did receive still works.
func TestRestartInsideGraceRefusesWithoutRevoking(t *testing.T) {
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	first := e.refresh(cid, tok.refresh)
	e.restart()
	e.clock.advance(5 * time.Second)
	if r := e.refresh(cid, tok.refresh); r.StatusCode != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("old token after a restart: %d %s", r.StatusCode, r.body)
	}
	if r := e.refresh(cid, first.str("refresh_token")); r.StatusCode != 200 {
		t.Fatalf("the grant must survive: %d %s", r.StatusCode, r.body)
	}
}

// A refused refresh does not use the token up.
func TestRefusedRefreshKeepsTheToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	bad := []url.Values{
		{"resource": {e.base + "/other"}},
		{"scope": {"rackbook:admin"}},
	}
	for _, extra := range bad {
		v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.refresh}, "client_id": {cid}}
		for k, x := range extra {
			v[k] = x
		}
		if r := e.form("/oauth/token", v); r.StatusCode != 400 {
			t.Fatalf("%v: %d %s", extra, r.StatusCode, r.body)
		}
	}
	if r := e.refresh(cid, tok.refresh); r.StatusCode != 200 {
		t.Fatalf("the token was used up by refused requests: %d %s", r.StatusCode, r.body)
	}
}

// A grant whose client is no longer in allowed_clients ends at the next refresh.
func TestRefreshChecksAllowedClients(t *testing.T) {
	t.Parallel()
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	e.setAllowed([]string{"https://other.example/client.json"})
	if r := e.refresh(cid, tok.refresh); r.StatusCode != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("refresh of a client that is not allowed: %d %s", r.StatusCode, r.body)
	}
	e.setAllowed(nil)
	if g := e.get(boss, "/api/account/grants").json()["grants"].([]any); len(g) != 0 {
		t.Fatalf("the grant should have been revoked: %v", g)
	}
}

// A revoke that cannot be saved must not claim success.
func TestRevokeReportsWriteFailure(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a read-only directory")
	}
	e := newEnv(t, opts{})
	_, tok := e.login("ed@example.com", "c")
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(e.dir, 0o700)
	r := e.do("ed@example.com", http.MethodDelete, "/api/account/grants/"+tok.grant, nil, "Sec-Fetch-Site", "same-origin")
	if r.StatusCode != 500 {
		t.Fatalf("revoke with an unwritable state directory: %d %s", r.StatusCode, r.body)
	}
	if e.mcpStatus(tok.access).StatusCode != 200 {
		t.Fatal("the grant is still in force, so the token must still work")
	}
	if a := e.do(boss, http.MethodDelete, "/api/admin/grants/"+tok.grant, nil, "Sec-Fetch-Site", "same-origin"); a.StatusCode != 500 {
		t.Fatalf("admin revoke with an unwritable state directory: %d", a.StatusCode)
	}
	os.Chmod(e.dir, 0o700)
	if r := e.do("ed@example.com", http.MethodDelete, "/api/account/grants/"+tok.grant, nil, "Sec-Fetch-Site", "same-origin"); r.StatusCode != 200 {
		t.Fatalf("revoke after the directory is writable again: %d", r.StatusCode)
	}
}

// Replaying an authorization code revokes the grant it made; if that cannot be
// saved the request fails instead of pretending.
func TestCodeReplayRevokeFailureSurfaces(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a read-only directory")
	}
	e := newEnv(t, opts{})
	cid := e.register("c")
	v, ch := pkce()
	code := e.approve(boss, e.params(cid, testRedirect, ch))
	if r := e.exchange(cid, code, v); r.StatusCode != 200 {
		t.Fatal(string(r.body))
	}
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(e.dir, 0o700)
	if r := e.exchange(cid, code, v); r.StatusCode != 500 || r.str("error") != "server_error" {
		t.Fatalf("replay with an unwritable directory: %d %s", r.StatusCode, r.body)
	}
}
