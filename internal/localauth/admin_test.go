//go:build !windows

package localauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

func (e *env) serveAdmin() *AdminServer {
	e.t.Helper()
	a, err := e.svc.ServeAdmin()
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(a.Close)
	return a
}

func (e *env) adminDo(req AdminRequest) AdminResponse {
	e.t.Helper()
	c, err := DialAdmin(context.Background(), e.dir, e.key)
	if err != nil {
		e.t.Fatal(err)
	}
	defer c.Close()
	if req.Operator == "" {
		req.Operator = "tester"
	}
	r, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func TestAdminChannelRunsCommandsAndLinksWork(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.serveAdmin()
	r := e.adminDo(AdminRequest{Cmd: "invite", Username: "dana", Name: "Dana"})
	if !r.OK || len(r.Links) != 1 || !strings.HasPrefix(r.Links[0].URL, testBase+"/auth/local/setup#") || r.Links[0].Kind != "invite" {
		t.Fatalf("%+v", r)
	}
	tok := strings.TrimPrefix(r.Links[0].URL, testBase+"/auth/local/setup#")
	b := e.browser(addrA)
	if o := e.open(b, tok); o.Status != 200 {
		t.Fatalf("the link made over the channel does not open: %d %s", o.Status, o.Body)
	}
	// the event is the CLI's: method cli, the operator, the account as target, and never the link
	ev := e.events("account_invited")
	if len(ev) != 1 || ev[0].Method != "cli" || ev[0].Target != "local:dana" || ev[0].Detail[0] != "operator:tester" {
		t.Fatalf("%+v", ev)
	}
	for _, x := range e.events("") {
		if strings.Contains(strings.Join(x.Detail, " ")+x.Reason+x.Code, tok) {
			t.Fatal("the link token is in the audit log")
		}
	}
	// errors come back as answers
	if r := e.adminDo(AdminRequest{Cmd: "invite", Username: "dana"}); r.OK || r.Code != "username_used" {
		t.Fatalf("%+v", r)
	}
	if r := e.adminDo(AdminRequest{Cmd: "frobnicate", Username: "dana"}); r.OK {
		t.Fatal("an unknown command ran")
	}
	if r := e.adminDo(AdminRequest{Cmd: "disable", Username: "Not Valid!"}); r.OK {
		t.Fatal("a bad username ran")
	}
}

func TestAdminChannelRefusesAPeerWithoutTheKey(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.serveAdmin()
	other, _ := statekey.GenerateKey()
	// the client with the wrong key stops at the server's proof and sends nothing
	if _, err := DialAdmin(context.Background(), e.dir, other); !errors.Is(err, errAdminAuth) {
		t.Fatalf("%v", err)
	}
	// a peer that connects with the wrong key and sends a command anyway: the server never opens it
	c, err := net.Dial("unix", socketPath(e.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	nc := bytes.Repeat([]byte{1}, adminNonceLen)
	c.Write(nc)
	resp := make([]byte, adminNonceLen+32)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	sc := &secureConn{c: c, sendDir: dirClient, recvDir: dirServer, maxFrame: maxAdminFrame}
	sc.aead, _ = sessionAEAD(channelKey(other), nc, resp[:adminNonceLen])
	if err := sc.writeMsg(AdminRequest{Cmd: "invite", Username: "mallory", Operator: "mallory"}); err != nil {
		t.Fatal(err)
	}
	var out AdminResponse
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := sc.readMsg(&out); err == nil {
		t.Fatal("the server answered a peer without the key")
	}
	if e.account("mallory") != nil {
		t.Fatal("a command from a peer without the key ran")
	}
	// raw garbage, a huge length, and silence
	for _, junk := range [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n"), {0xff, 0xff, 0xff, 0xff, 1, 2, 3}} {
		c2, _ := net.Dial("unix", socketPath(e.dir))
		c2.Write(bytes.Repeat([]byte{7}, adminNonceLen))
		io.ReadFull(c2, make([]byte, adminNonceLen+32))
		c2.Write(junk)
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, _ := c2.Read(make([]byte, 16)); n != 0 {
			t.Errorf("the server answered junk with %d bytes", n)
		}
		c2.Close()
	}
}

// a relay under the same account (the OS permission lets it connect) sees only sealed frames, and cannot change,
// replay or reorder them
func TestAdminChannelIsEncryptedAndAuthenticatedAgainstARelay(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.serveAdmin()
	var mu sync.Mutex
	var up, down bytes.Buffer
	ln, err := net.Listen("unix", e.dir+"/relay.sock")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	var flip, drop atomicBool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("unix", socketPath(e.dir))
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				defer s.Close()
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					buf := make([]byte, 4096)
					for {
						n, err := c.Read(buf)
						if n > 0 {
							b := append([]byte(nil), buf[:n]...)
							mu.Lock()
							up.Write(b)
							mu.Unlock()
							if flip.get() && n > 40 {
								b[n-1] ^= 1 // a changed bit in a sealed frame
							}
							if !drop.get() {
								s.Write(b)
							}
						}
						if err != nil {
							return
						}
					}
				}()
				go func() {
					defer wg.Done()
					buf := make([]byte, 4096)
					for {
						n, err := s.Read(buf)
						if n > 0 {
							mu.Lock()
							down.Write(buf[:n])
							mu.Unlock()
							c.Write(buf[:n])
						}
						if err != nil {
							return
						}
					}
				}()
				wg.Wait()
			}()
		}
	}()
	// the same code as DialAdmin, through the relay
	run := func(req AdminRequest) (AdminResponse, error) {
		c, err := net.Dial("unix", e.dir+"/relay.sock")
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		sc, err := clientHandshake(c, channelKey(e.key))
		if err != nil {
			return AdminResponse{}, err
		}
		defer c.Close()
		cl := &AdminClient{sc: sc}
		return cl.Do(req)
	}
	resp, err := run(AdminRequest{Cmd: "invite", Username: "dana", Operator: "op"})
	if err != nil || !resp.OK {
		t.Fatalf("%v %+v", err, resp)
	}
	tok := strings.TrimPrefix(resp.Links[0].URL, testBase+"/auth/local/setup#")
	mu.Lock()
	wire := up.String() + down.String()
	mu.Unlock()
	if strings.Contains(wire, tok) || strings.Contains(wire, "dana") || strings.Contains(wire, "invite") || strings.Contains(wire, "auth/local") {
		t.Fatal("something readable crossed the channel: links and commands must be sealed")
	}
	// a changed bit: the server does not run the command
	flip.set(true)
	if _, err := run(AdminRequest{Cmd: "invite", Username: "erin", Operator: "op"}); err == nil {
		t.Fatal("a tampered request was answered")
	}
	flip.set(false)
	if e.account("erin") != nil {
		t.Fatal("a tampered request ran")
	}
	// replaying a captured request frame on a new connection does not open (a new session key)
	mu.Lock()
	captured := append([]byte(nil), up.Bytes()...)
	mu.Unlock()
	if len(captured) < adminNonceLen+5 {
		t.Fatal("nothing captured")
	}
	frame := captured[adminNonceLen:]
	c, _ := net.Dial("unix", socketPath(e.dir))
	c.Write(bytes.Repeat([]byte{9}, adminNonceLen))
	io.ReadFull(c, make([]byte, adminNonceLen+32))
	c.Write(frame[:min(len(frame), 4+int(binary.BigEndian.Uint32(frame[:4])))])
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 8)); n != 0 {
		t.Fatal("a replayed request was answered")
	}
	c.Close()
	if r := e.account("dana"); r == nil || len(e.events("account_invited")) != 1 {
		t.Fatalf("the replay must not invite again: %d events", len(e.events("account_invited")))
	}
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) get() bool  { a.mu.Lock(); defer a.mu.Unlock(); return a.v }
func (a *atomicBool) set(v bool) { a.mu.Lock(); a.v = v; a.mu.Unlock() }

func TestAdminSocketIsPrivateAndExclusive(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.serveAdmin()
	st, err := os.Stat(socketPath(e.dir))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	// the socket was made in a private directory (no process-wide umask) and moved to its name: nothing is left behind
	ents, _ := os.ReadDir(e.dir)
	for _, d := range ents {
		if strings.HasPrefix(d.Name(), ".admin-") {
			t.Fatalf("a temporary directory of the socket is left: %s", d.Name())
		}
	}
	if _, err := e.svc.ServeAdmin(); err == nil || !strings.Contains(err.Error(), "another process holds") {
		t.Fatalf("a second server on the same state directory: %v", err)
	}
	// no server: a clear error, and a stale socket does not block a start
	e2 := newEnv(t, envOpts{})
	if _, err := DialAdmin(context.Background(), e2.dir, e2.key); !errors.Is(err, ErrNoServer) {
		t.Fatalf("%v", err)
	}
	os.WriteFile(socketPath(e2.dir), nil, 0o600)
	a, err := e2.svc.ServeAdmin()
	if err != nil {
		t.Fatalf("a stale socket file must not block a start: %v", err)
	}
	a.Close()
	if _, err := os.Stat(socketPath(e2.dir)); err == nil {
		t.Error("the socket is removed at close")
	}
}

func TestOnlineDisableEndsSessionsAndRenewsTheSecret(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.serveAdmin()
	bob := e.addAccount("bob")
	b := e.browser(addrA)
	e.login1(b, bob, goodPassword, e.code(bob))
	if _, ok := e.login.LocalSession(httptestRequest(b)); !ok {
		t.Fatal("no session")
	}
	cookie := b.cookies["__Host-rackbook_session"]
	before := e.account("bob")
	if r := e.adminDo(AdminRequest{Cmd: "disable", Username: "bob"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	after := e.account("bob")
	if after.State != accounts.StateDisabled || after.SID == before.SID || bytes.Equal(after.SessionSecret, before.SessionSecret) {
		t.Fatalf("an online disable must renew sid and secret: %+v", after)
	}
	if _, ok := e.login.LocalSession(httptestRequest(b)); ok {
		t.Fatal("the session survived the disable")
	}
	// enable brings the account back, not the old cookie
	if r := e.adminDo(AdminRequest{Cmd: "enable", Username: "bob"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	b.cookies["__Host-rackbook_session"] = cookie
	if _, ok := e.login.LocalSession(httptestRequest(b)); ok {
		t.Fatal("an old cookie came back to life when the account was enabled")
	}
	if r := e.login1(e.browser(addrB), bob, goodPassword, e.code(bob)); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// end-sessions ends them, and remove leaves a tombstone
	b2 := e.browser(addrA)
	e.login1(b2, bob, goodPassword, e.code(bob))
	if r := e.adminDo(AdminRequest{Cmd: "end-sessions", Username: "bob"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if _, ok := e.login.LocalSession(httptestRequest(b2)); ok {
		t.Fatal("end-sessions left a session")
	}
	if r := e.adminDo(AdminRequest{Cmd: "remove", Username: "bob"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if got := e.account("bob"); got.State != accounts.StateRemoved {
		t.Fatalf("%+v", got)
	}
}

func TestRecoverBringsBackALockedOutAdmin(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  nist_cap: 10\n  throttle: {max: 1000}\n"})
	e.serveAdmin()
	alice := e.addAccount("alice")
	// the admin is locked out: the NIST cap puts the account in passkey_only
	good := e.browser(addrA)
	e.login1(good, alice, goodPassword, e.code(alice))
	for i := 1; i <= 8; i++ {
		e.login1(e.browser("192.0.2."+itoa(i)), alice, "wrong wrong wrong", "")
	}
	e.login1(e.browser("192.0.2.9"), alice, "wrong wrong wrong", "")
	e.login1(good, alice, "wrong wrong wrong", "")
	if got := e.account("alice"); got.State != accounts.StatePasskeyOnly {
		t.Fatalf("%+v", got)
	}
	if r := e.login1(good, alice, goodPassword, e.code(alice)); r.Status != 401 {
		t.Fatalf("locked out: %d", r.Status)
	}
	// recover: a full reset and a link
	r := e.adminDo(AdminRequest{Cmd: "recover", Username: "alice", Operator: "root"})
	if !r.OK || len(r.Links) != 1 || r.Links[0].Kind != "reset" || r.Links[0].Scope != "all" {
		t.Fatalf("%+v", r)
	}
	if got := e.account("alice"); got.State != accounts.StateResetPending || got.Password != "" || got.ConsecutiveFailures != 0 {
		t.Fatalf("%+v", got)
	}
	tok := strings.TrimPrefix(r.Links[0].URL, testBase+"/auth/local/setup#")
	b := e.browser(addrB)
	if o := e.open(b, tok); o.Status != 200 || o.json()["scope"] != "all" {
		t.Fatalf("%d %s", o.Status, o.Body)
	}
	totp, sec := e.enrolTOTP(b, tok)
	if f := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": totp}); f.Status != 200 || f.json()["signedIn"] != true {
		t.Fatalf("%d %s", f.Status, f.Body)
	}
	got := e.account("alice")
	if got.State != accounts.StateActive || got.ConsecutiveFailures != 0 {
		t.Fatalf("%+v", got)
	}
	if r := e.login1(e.browser(addrA), &person{name: "alice"}, newPassword, e.code(&person{name: "alice", secret: sec})); r.Status != 200 {
		t.Fatalf("after recovery: %d %s", r.Status, r.Body)
	}
	// an unknown username is invited, and --grant-admin is reported when the server cannot commit it
	r = e.adminDo(AdminRequest{Cmd: "recover", Username: "newadmin", Name: "New Admin", GrantAdmin: true})
	if !r.OK || r.Links[0].Kind != "invite" || !strings.Contains(strings.Join(r.Lines, " "), "local:newadmin") {
		t.Fatalf("%+v", r)
	}
}

func TestRecoverCommitsTheAdminRoleWhenTheServerCan(t *testing.T) {
	var granted []string
	e := newEnv(t, envOpts{mutate: func(o *Options) {
		o.GrantAdmin = func(_ context.Context, u, op string) error { granted = append(granted, u+"/"+op); return nil }
	}})
	e.serveAdmin()
	r := e.adminDo(AdminRequest{Cmd: "recover", Username: "newadmin", GrantAdmin: true, Operator: "root"})
	if !r.OK || len(granted) != 1 || granted[0] != "newadmin/root" {
		t.Fatalf("%+v %v", r, granted)
	}
}

func TestLastLocalAdminCannotBeDisabledOrRemovedUnderSSOOnly(t *testing.T) {
	e := newEnv(t, envOpts{sso: true, auth: "  login: {sso_only: true}\n"})
	e.serveAdmin()
	e.addAccount("alice") // the only local admin
	e.addAccount("bob")
	for _, cmd := range []string{"disable", "remove"} {
		if r := e.adminDo(AdminRequest{Cmd: cmd, Username: "alice"}); r.OK || r.Code != "last_local_admin" {
			t.Fatalf("%s: %+v", cmd, r)
		}
	}
	if got := e.account("alice"); got.State != accounts.StateActive {
		t.Fatal("the refused change changed the account")
	}
	// a non-admin is not protected, and with a second admin the first can go
	if r := e.adminDo(AdminRequest{Cmd: "disable", Username: "bob"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	// without sso_only the guard does not apply
	e2 := newEnv(t, envOpts{sso: true})
	e2.serveAdmin()
	e2.addAccount("alice")
	if r := e2.adminDo(AdminRequest{Cmd: "disable", Username: "alice"}); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestUnlockOverTheChannelClearsTheMemoryTablesToo(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 3, window: 1m}\n  lock: {enabled: true, duration: 30m, scope: ip_account}\n"})
	e.serveAdmin()
	alice := e.addAccount("alice")
	for i := 0; i < 3; i++ {
		e.login1(e.browser(addrA), alice, "wrong wrong wrong", "")
	}
	e.clk.Advance(2 * time.Minute)
	if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 429 {
		t.Fatalf("not locked: %d", r.Status)
	}
	if r := e.adminDo(AdminRequest{Cmd: "unlock", Username: "alice"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("after the unlock: %d %s", r.Status, r.Body)
	}
}

func TestResetAllIssuesALinkPerLiveAccount(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.serveAdmin()
	e.addAccount("alice")
	e.addAccount("bob")
	e.addAccount("carol")
	e.adminDo(AdminRequest{Cmd: "remove", Username: "carol"})
	r := e.adminDo(AdminRequest{Cmd: "reset", All: true, Scope: "all"})
	if !r.OK || len(r.Links) != 2 {
		t.Fatalf("%+v", r)
	}
	for _, n := range []string{"alice", "bob"} {
		if e.account(n).State != accounts.StateResetPending {
			t.Errorf("%s is %s", n, e.account(n).State)
		}
	}
}
