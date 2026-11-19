package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/modsettings"
	"github.com/kazuhahub/rackbook/modules/rbclient"
)

func intp(i int) *int { return &i }

func item(col, id, exp string, d int) rbclient.Item {
	st := "expiring"
	if d < 0 {
		st = "expired"
	}
	return rbclient.Item{Collection: col, ID: id, Label: id, Expires: exp, DaysLeft: intp(d), Status: st}
}

var std = []int{30, 14, 7, 0}

func TestPlanFirstSeen(t *testing.T) {
	cases := []struct {
		days  int
		fired []int
	}{
		{40, nil},
		{30, []int{30}},
		{20, []int{30}},
		{10, []int{30, 14}},
		{5, []int{30, 14, 7}},
		{0, []int{30, 14, 7, 0}},
		{-3, []int{30, 14, 7, 0}},
	}
	for _, c := range cases {
		t.Run(strconv.Itoa(c.days), func(t *testing.T) {
			var items []rbclient.Item
			if c.days <= 30 {
				items = append(items, item("c", "a", "2026-12-01", c.days))
			}
			due, next := plan(newState(), items, std)
			if c.days > 30 {
				if len(due) != 0 || len(next.Items) != 0 {
					t.Fatalf("due=%v state=%v", due, next.Items)
				}
				return
			}
			if len(due) != 1 {
				t.Fatalf("due = %d, want 1", len(due))
			}
			if got := next.Items[stateKey("c", "a")].Fired; !reflect.DeepEqual(got, c.fired) {
				t.Fatalf("fired = %v, want %v", got, c.fired)
			}
		})
	}
}

func TestPlanFiresOncePerThreshold(t *testing.T) {
	st := newState()
	steps := []struct {
		days int
		due  bool
	}{{29, true}, {28, false}, {14, true}, {13, false}, {7, true}, {6, false}, {0, true}, {-1, false}, {-9, false}}
	for _, s := range steps {
		due, next := plan(st, []rbclient.Item{item("c", "a", "2026-12-01", s.days)}, std)
		if (len(due) == 1) != s.due {
			t.Fatalf("days %d: due=%v want %v", s.days, len(due) == 1, s.due)
		}
		st = next
	}
	due, _ := plan(st, []rbclient.Item{item("c", "a", "2026-12-01", -10)}, std)
	if len(due) != 0 {
		t.Fatal("expired item fired twice")
	}
}

func TestPlanExpiresChangeResets(t *testing.T) {
	st := newState()
	_, st = plan(st, []rbclient.Item{item("c", "a", "2026-12-01", 5)}, std)
	due, st := plan(st, []rbclient.Item{item("c", "a", "2026-12-20", 25)}, std)
	if len(due) != 1 {
		t.Fatal("renewed item should fire again at its new window")
	}
	if got := st.Items[stateKey("c", "a")]; got.Expires != "2026-12-20" || !reflect.DeepEqual(got.Fired, []int{30}) {
		t.Fatalf("entry = %+v", got)
	}
}

func TestPlanPrunes(t *testing.T) {
	st := newState()
	_, st = plan(st, []rbclient.Item{item("c", "a", "x", 5), item("c", "b", "y", 5)}, std)
	_, st = plan(st, []rbclient.Item{item("c", "b", "y", 4)}, std)
	if _, ok := st.Items[stateKey("c", "a")]; ok || len(st.Items) != 1 {
		t.Fatalf("state = %v", st.Items)
	}
}

func TestPlanSkipsUnknownAndSorts(t *testing.T) {
	items := []rbclient.Item{item("c", "late", "x", 6), {Collection: "c", ID: "u", Status: "unknown"}, item("c", "early", "y", -2)}
	due, _ := plan(newState(), items, std)
	if len(due) != 2 || due[0].ID != "early" {
		t.Fatalf("due = %+v", due)
	}
}

func TestStateRoundTripAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	s, err := loadState(p)
	if err != nil || len(s.Items) != 0 {
		t.Fatalf("missing file: %v %v", s, err)
	}
	s.Items[stateKey("c", "id\x00x")] = Entry{Expires: "2026-01-01", Fired: []int{30, 14}}
	if err := saveState(p, s); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // Windows has no permission bits
		t.Fatalf("mode %v", fi.Mode())
	}
	got, err := loadState(p)
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatalf("round trip: %v %v", got, err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
	os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := loadState(p); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt: %v", err)
	}
}

func TestResolveStatePath(t *testing.T) {
	first, other := t.TempDir(), t.TempDir()
	t.Setenv("STATE_DIRECTORY", first+string(os.PathListSeparator)+other)
	if got := resolveStatePath("s.json"); got != filepath.Join(first, "s.json") {
		t.Fatal(got)
	}
	abs := filepath.Join(other, "s.json")
	if got := resolveStatePath(abs); got != abs {
		t.Fatal(got)
	}
	t.Setenv("STATE_DIRECTORY", "")
	if got := resolveStatePath("s.json"); got != "s.json" {
		t.Fatal(got)
	}
}

func TestConfig(t *testing.T) {
	c, err := parseConfig([]byte("rackbook: {url: https://r.example, token_file: t}\nthresholds: [7, 30, 7, 0, 14]\nwebhook: {url: https://h.example/x}\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Thresholds, std) || c.Language != "en" || c.Interval != 6*time.Hour || c.StateFile != "notify-state.json" {
		t.Fatalf("%+v", c)
	}
	bad := map[string]string{
		"unknown field": "rackbook: {url: u, token_file: t}\nbogus: 1\nwebhook: {url: https://h}\n",
		"negative":      "rackbook: {url: u, token_file: t}\nthresholds: [-1]\nwebhook: {url: https://h}\n",
		"language":      "rackbook: {url: u, token_file: t}\nlanguage: fr\nwebhook: {url: https://h}\n",
		"no channel":    "rackbook: {url: u, token_file: t}\n",
		"no url":        "rackbook: {token_file: t}\nwebhook: {url: https://h}\n",
		"both webhook":  "rackbook: {url: u, token_file: t}\nwebhook: {url: https://h, url_file: f}\n",
		"inject":        "rackbook: {url: u, token_file: t}\nsmtp: {host: h, from: \"a@b.c\\nBcc: x@y.z\", to: [a@b.c]}\n",
	}
	for name, y := range bad {
		if _, err := parseConfig([]byte(y), false); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := parseConfig([]byte("rackbook: {url: u, token_file: t}\n"), true); err != nil {
		t.Errorf("dry run without channels: %v", err)
	}
}

func TestDigestText(t *testing.T) {
	due := []rbclient.Item{item("credentials", "a b/c", "2026-11-10", -8), item("hosts", "h1", "2026-12-01", 13)}
	due[1].Source = "entra"
	d := buildDigest("en", "https://rb.example/", due)
	if d.Subject != "Rackbook: 1 expired, 1 expiring" {
		t.Fatal(d.Subject)
	}
	for _, s := range []string{"[EXPIRED] credentials / a b/c", "Days left: -8", "Source: manual", "Source: entra", "https://rb.example/c/credentials/a%20b%2Fc"} {
		if !strings.Contains(d.Body, s) {
			t.Errorf("missing %q in\n%s", s, d.Body)
		}
	}
	z := buildDigest("zh", "https://rb.example", due[:1])
	if z.Subject != "Rackbook：1 项已过期" || !strings.Contains(z.Body, "来源: 手动") {
		t.Fatalf("%q\n%s", z.Subject, z.Body)
	}
}

type fakeRackbook struct {
	mu    sync.Mutex
	items []rbclient.Item
	query string
	auth  string
	fail  bool
	// the modules panel: nil remote = a server without it (404)
	remote *modsettings.Remote
	status []modsettings.ModuleStatus
	runs   []modsettings.Run
}

func (f *fakeRackbook) set(items ...rbclient.Item) {
	f.mu.Lock()
	f.items = items
	f.mu.Unlock()
}

func (f *fakeRackbook) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/api/modules/notify/settings" && f.remote != nil:
			json.NewEncoder(w).Encode(f.remote)
			return
		case r.URL.Path == "/api/modules/notify/runs" && r.Method == "POST" && f.remote != nil:
			var run modsettings.Run
			json.NewDecoder(r.Body).Decode(&run)
			f.runs = append(f.runs, run)
			w.WriteHeader(201)
			return
		case r.URL.Path == "/api/modules/status" && f.status != nil:
			json.NewEncoder(w).Encode(map[string]any{"modules": f.status})
			return
		case r.URL.Path != "/api/expiring":
			http.NotFound(w, r)
			return
		}
		f.query = r.URL.RawQuery
		f.auth = r.Header.Get("Authorization")
		if f.fail {
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(rbclient.Expiring{Today: "2026-11-18", Days: 30, Items: f.items})
	}))
	t.Cleanup(s.Close)
	return s
}

type env struct {
	cfg  *Config
	rb   *fakeRackbook
	dir  string
	out  bytes.Buffer
	stat string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{rb: &fakeRackbook{}, dir: t.TempDir()}
	srv := e.rb.server(t)
	tok := filepath.Join(e.dir, "token")
	os.WriteFile(tok, []byte("rbk_test\n"), 0o600)
	e.stat = filepath.Join(e.dir, "state.json")
	e.cfg = &Config{
		Rackbook:   RackbookConfig{URL: srv.URL, TokenFile: tok, Module: "notify"},
		Thresholds: std, StateFile: e.stat, Language: "en", Interval: time.Hour,
	}
	return e
}

func (e *env) run(t *testing.T, dry bool) error {
	t.Helper()
	n, err := newNotifier(e.cfg, dry, &e.out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return n.run(context.Background())
}

func (e *env) stateItems(t *testing.T) map[string]Entry {
	s, err := loadState(e.stat)
	if err != nil {
		t.Fatal(err)
	}
	return s.Items
}

type hook struct {
	mu    sync.Mutex
	calls []map[string]any
	code  int
}

func (h *hook) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		h.mu.Lock()
		h.calls = append(h.calls, m)
		code := h.code
		h.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestRunWebhookFlow(t *testing.T) {
	e := newEnv(t)
	h := &hook{code: 200}
	e.cfg.Webhook = &WebhookConfig{URL: h.server(t).URL}
	e.cfg.Collections = []string{"credentials"}
	e.rb.set(item("credentials", "a", "2026-11-20", 2))

	if err := e.run(t, false); err != nil {
		t.Fatal(err)
	}
	if e.rb.auth != "Bearer rbk_test" || !strings.Contains(e.rb.query, "days=30") || !strings.Contains(e.rb.query, "collection=credentials") || strings.Contains(e.rb.query, "unknown") {
		t.Fatalf("query %q auth %q", e.rb.query, e.rb.auth)
	}
	if len(h.calls) != 1 {
		t.Fatalf("calls %d", len(h.calls))
	}
	if txt, _ := h.calls[0]["text"].(string); !strings.Contains(txt, "credentials / a") {
		t.Fatalf("text %q", txt)
	}
	if items, _ := h.calls[0]["items"].([]any); len(items) != 1 {
		t.Fatalf("items %v", h.calls[0]["items"])
	}
	if got := e.stateItems(t)[stateKey("credentials", "a")].Fired; !reflect.DeepEqual(got, []int{30, 14, 7}) {
		t.Fatalf("fired %v", got)
	}
	if err := e.run(t, false); err != nil || len(h.calls) != 1 {
		t.Fatalf("second run sent again: %v %d", err, len(h.calls))
	}

	e.rb.set()
	if err := e.run(t, false); err != nil || len(e.stateItems(t)) != 0 {
		t.Fatalf("prune: %v %v", err, e.stateItems(t))
	}
}

func TestRunWebhookFailureKeepsState(t *testing.T) {
	e := newEnv(t)
	h := &hook{code: 500}
	e.cfg.Webhook = &WebhookConfig{URL: h.server(t).URL}
	e.rb.set(item("c", "a", "2026-11-20", 2))
	if err := e.run(t, false); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(e.stat); !os.IsNotExist(err) {
		t.Fatal("state saved after failed delivery")
	}
	h.mu.Lock()
	h.code = 204
	h.mu.Unlock()
	if err := e.run(t, false); err != nil || len(h.calls) != 2 {
		t.Fatalf("retry: %v %d", err, len(h.calls))
	}
	if len(e.stateItems(t)) != 1 {
		t.Fatal("state not saved after success")
	}
}

func TestRunDryRun(t *testing.T) {
	e := newEnv(t)
	e.rb.set(item("c", "a", "2026-11-20", 2))
	if err := e.run(t, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.out.String(), "Subject: Rackbook: 1 expiring") || !strings.Contains(e.out.String(), "c / a") {
		t.Fatal(e.out.String())
	}
	if _, err := os.Stat(e.stat); !os.IsNotExist(err) {
		t.Fatal("dry run saved state")
	}
}

func TestRunAPIFailure(t *testing.T) {
	e := newEnv(t)
	e.rb.fail = true
	if err := e.run(t, false); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunCorruptState(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(e.stat, []byte("garbage"), 0o600)
	if err := e.run(t, false); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(e.stat); string(b) != "garbage" {
		t.Fatal("corrupt state overwritten")
	}
}

func TestWebhookURLRules(t *testing.T) {
	for _, u := range []string{"http://example.org/x", "ftp://x", "/x", ""} {
		if _, err := validateWebhookURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	for _, u := range []string{"https://example.org/x", "http://localhost:1/x", "http://127.0.0.1:2/x"} {
		if _, err := validateWebhookURL(u); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
}

func TestWebhookURLFile(t *testing.T) {
	e := newEnv(t)
	h := &hook{code: 200}
	f := filepath.Join(e.dir, "hook-url")
	os.WriteFile(f, []byte(h.server(t).URL+"\n"), 0o600)
	e.cfg.Webhook = &WebhookConfig{URLFile: f}
	e.rb.set(item("c", "a", "2026-11-20", 2))
	if err := e.run(t, false); err != nil || len(h.calls) != 1 {
		t.Fatalf("%v %d", err, len(h.calls))
	}
}

type fakeSMTP struct {
	ln        net.Listener
	startTLS  bool
	cert      tls.Certificate
	mu        sync.Mutex
	plainCmds []string
	auth      string
	from      string
	rcpts     []string
	data      string
}

func newFakeSMTP(t *testing.T, startTLS bool) (*fakeSMTP, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, startTLS: startTLS, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f, pool
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var conn net.Conn = c
	r := bufio.NewReader(conn)
	say := func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }
	say("220 fake ESMTP")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		f.mu.Lock()
		if !secure {
			f.plainCmds = append(f.plainCmds, line)
		}
		f.mu.Unlock()
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			say("250-fake")
			if f.startTLS && !secure {
				say("250-STARTTLS")
			}
			say("250-AUTH PLAIN")
			say("250 8BITMIME")
		case cmd == "STARTTLS":
			say("220 go ahead")
			conn = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
			r = bufio.NewReader(conn)
			secure = true
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = line
			f.mu.Unlock()
			say("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from = line[len("MAIL FROM:"):]
			f.rcpts = nil
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line[len("RCPT TO:"):])
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func TestSMTPSend(t *testing.T) {
	f, pool := newFakeSMTP(t, true)
	smtpRootCAs = pool
	t.Cleanup(func() { smtpRootCAs = nil })
	e := newEnv(t)
	pw := filepath.Join(e.dir, "pw")
	os.WriteFile(pw, []byte("s3cret\n"), 0o600)
	e.cfg.Language = "zh"
	e.cfg.SMTP = &SMTPConfig{Host: "127.0.0.1", Port: f.port(), Username: "u", PasswordFile: pw,
		From: "Rackbook <rb@example.org>", To: []string{"ops@example.org", "b@example.org"}, Helo: "notify.example.org"}
	e.rb.set(item("credentials", "tls-www", "2026-11-10", -8), item("credentials", "x", "2026-11-25", 7))
	if err := e.run(t, false); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.plainCmds) == 0 || f.plainCmds[0] != "EHLO notify.example.org" {
		t.Fatalf("first command %v, want EHLO notify.example.org", f.plainCmds)
	}
	for _, c := range f.plainCmds {
		u := strings.ToUpper(c)
		if strings.HasPrefix(u, "MAIL") || strings.HasPrefix(u, "AUTH") || u == "DATA" {
			t.Fatalf("command %q before STARTTLS", c)
		}
	}
	if !strings.HasPrefix(f.auth, "AUTH PLAIN ") || !strings.HasPrefix(f.from, "<rb@example.org>") || len(f.rcpts) != 2 || f.rcpts[0] != "<ops@example.org>" {
		t.Fatalf("auth=%q from=%q rcpts=%v", f.auth, f.from, f.rcpts)
	}
	head, body, _ := strings.Cut(f.data, "\r\n\r\n")
	hdr := map[string]string{}
	for _, l := range strings.Split(head, "\r\n") {
		k, v, _ := strings.Cut(l, ": ")
		hdr[k] = v
	}
	subj, err := new(mime.WordDecoder).DecodeHeader(hdr["Subject"])
	if err != nil || subj != "Rackbook：1 项已过期，1 项即将到期" {
		t.Fatalf("subject %q %v", subj, err)
	}
	if strings.ContainsAny(hdr["Subject"], "\u4e00") {
		t.Fatal("subject not encoded")
	}
	for _, k := range []string{"From", "To", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"} {
		if hdr[k] == "" {
			t.Errorf("missing header %s", k)
		}
	}
	if hdr["To"] != "<ops@example.org>, <b@example.org>" || hdr["Content-Type"] != "text/plain; charset=UTF-8" {
		t.Fatalf("headers %v", hdr)
	}
	dec, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec), "来源: 手动") || !strings.Contains(string(dec), "/c/credentials/tls-www") {
		t.Fatalf("body %q", dec)
	}
	for _, l := range strings.Split(body, "\r\n") {
		if len(l) > 76 {
			t.Fatalf("long line %q", l)
		}
	}
}

func TestSMTPRequiresSTARTTLS(t *testing.T) {
	f, pool := newFakeSMTP(t, false)
	smtpRootCAs = pool
	t.Cleanup(func() { smtpRootCAs = nil })
	e := newEnv(t)
	e.cfg.SMTP = &SMTPConfig{Host: "127.0.0.1", Port: f.port(), From: "rb@example.org", To: []string{"ops@example.org"}}
	e.rb.set(item("c", "a", "2026-11-20", 2))
	err := e.run(t, false)
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.plainCmds {
		u := strings.ToUpper(c)
		if strings.HasPrefix(u, "MAIL") || strings.HasPrefix(u, "RCPT") || u == "DATA" {
			t.Fatalf("sent %q without TLS", c)
		}
	}
	if f.data != "" {
		t.Fatal("message delivered without TLS")
	}
	if _, err := os.Stat(e.stat); !os.IsNotExist(err) {
		t.Fatal("state saved")
	}
}

func TestSMTPUntrustedCert(t *testing.T) {
	f, _ := newFakeSMTP(t, true)
	e := newEnv(t)
	e.cfg.SMTP = &SMTPConfig{Host: "127.0.0.1", Port: f.port(), From: "rb@example.org", To: []string{"ops@example.org"}}
	e.rb.set(item("c", "a", "2026-11-20", 2))
	if err := e.run(t, false); err == nil {
		t.Fatal("expected certificate error")
	}
}

func TestHeaderInjection(t *testing.T) {
	a, _ := parseAddress("rb@example.org")
	if _, err := buildMessage(a, []*mail.Address{a}, "x\r\nBcc: evil@example.org", "b", time.Now()); err == nil {
		t.Fatal("subject injection accepted")
	}
	if _, err := parseAddress("a@b.c\r\nBcc: x@y.z"); err == nil {
		t.Fatal("address injection accepted")
	}
}

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := realMain([]string{"--version"}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != version {
		t.Fatalf("%d %q", code, out.String())
	}
}

func TestOnceExitCodes(t *testing.T) {
	e := newEnv(t)
	h := &hook{code: 200}
	hs := h.server(t)
	cfg := filepath.Join(e.dir, "notify.yml")
	y := fmt.Sprintf("rackbook: {url: %s, token_file: %s}\nstate_file: %s\nwebhook: {url: %s}\n", e.cfg.Rackbook.URL, e.cfg.Rackbook.TokenFile, e.stat, hs.URL)
	os.WriteFile(cfg, []byte(y), 0o600)
	e.rb.set(item("c", "a", "2026-11-20", 2))
	var out, errb bytes.Buffer
	if code := realMain([]string{"--config", cfg, "--once"}, &out, &errb); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	e.rb.fail = true
	if code := realMain([]string{"--config", cfg, "--once"}, &out, &errb); code != 1 {
		t.Fatalf("code %d", code)
	}
}

func TestHeloName(t *testing.T) {
	t.Cleanup(func() { hostname = os.Hostname })
	for _, tc := range []struct {
		helo, host string
		err        error
		want       string
	}{
		{"mail.example.org", "box.example.org", nil, "mail.example.org"},
		{"", "box.example.org", nil, "box.example.org"},
		{"", "box", nil, "localhost"},
		{"", "", nil, "localhost"},
		{"", "bad host.example.org", nil, "localhost"},
		{"", "box.example.org", errors.New("no hostname"), "localhost"},
	} {
		hostname = func() (string, error) { return tc.host, tc.err }
		if got := heloName(&SMTPConfig{Helo: tc.helo}); got != tc.want {
			t.Errorf("helo %q host %q: got %q, want %q", tc.helo, tc.host, got, tc.want)
		}
	}
	for _, bad := range []string{"a b", "x\r\nMAIL FROM:<e>", "-x", ".x"} {
		s := &SMTPConfig{Host: "h", From: "a@b.c", To: []string{"a@b.c"}, Helo: bad}
		if err := s.normalize(); err == nil {
			t.Errorf("helo %q accepted", bad)
		}
	}
}
