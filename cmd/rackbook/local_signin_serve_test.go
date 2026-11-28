//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// A server that runs: the sign-in pages and endpoints are mounted with their own policy, the admin channel answers the
// command line over the state directory's socket, and a link made through it opens.
func TestServeMountsLocalSignInAndTheAdminChannel(t *testing.T) {
	if os.Getenv("RACKBOOK_NO_SIGNALS") != "" {
		t.Skip("signals are off")
	}
	fx := newAccountsFixture(t)
	other, _ := statekey.GenerateKey()
	sessionFile := writeKey(t, other)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	t.Setenv("RACKBOOK_STATE_KEY", "")
	t.Setenv("RACKBOOK_SESSION_KEY", "")
	args := append(serveArgs(t, fx.state, "--state-key-file", fx.keyFile, "--session-key-file", sessionFile), "--listen", addr)
	done := make(chan error, 1)
	var serveOut bytes.Buffer
	go func() {
		root := newRoot()
		root.SetOut(&serveOut)
		root.SetErr(&serveOut)
		root.SetArgs(args)
		done <- root.Execute()
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("serve did not stop")
		}
	}
	defer stop()
	sock := filepath.Join(fx.state, "admin.sock")
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("serve ended: %v\n%s", err, serveOut.String())
		default:
		}
		if _, err := os.Lstat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no admin socket:\n%s", serveOut.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	// the socket is made before the HTTP listener: wait for both
	for {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server does not listen:\n%s", serveOut.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	// the command line talks to the running server
	out, err := run(t, fx.args("accounts", "invite", "zed", "--operator", "ops")...)
	if err != nil || strings.Contains(out, "working on the files") {
		t.Fatalf("%v\n%s", err, out)
	}
	tok := strings.SplitN(linkOf(t, out), "#", 2)[1]
	if !strings.HasPrefix(linkOf(t, out), "https://ledger.example.com/auth/local/setup#") {
		t.Fatalf("the link must carry the server's base URL: %s", out)
	}
	post := func(path, body string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", "http://"+addr+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	resp, body := post("/auth/local/setup/open", fmt.Sprintf(`{"token":%q}`, tok))
	var j map[string]any
	_ = json.Unmarshal([]byte(body), &j)
	if resp.StatusCode != 200 || j["kind"] != "invite" || j["username"] != "zed" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != api.AuthPageCSP(nil) {
		t.Fatalf("the setup endpoint's policy: %s", got)
	}
	// the same answer for a wrong password of a name that does not exist and of one that does
	a, ab := post("/auth/local/login", `{"username":"nobody","password":"x","code":"123456"}`)
	b, bb := post("/auth/local/login", `{"username":"alice","password":"x","code":"123456"}`)
	if a.StatusCode != 401 || b.StatusCode != 401 || ab != bb {
		t.Fatalf("%d %q / %d %q", a.StatusCode, ab, b.StatusCode, bb)
	}
	// the page is a document with the sign-in policy
	pr, err := http.Get("http://" + addr + "/auth/local/setup")
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	if pr.StatusCode != 200 || pr.Header.Get("Content-Security-Policy") != api.AuthPageCSP(nil) || !strings.HasPrefix(pr.Header.Get("Cache-Control"), "no-") {
		t.Fatalf("%d %v", pr.StatusCode, pr.Header)
	}
	stop()
	if _, err := os.Lstat(sock); err == nil {
		t.Error("the admin socket is left behind")
	}
	_ = context.Background()
}
