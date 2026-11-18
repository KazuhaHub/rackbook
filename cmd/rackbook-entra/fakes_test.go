package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/modules/rbclient"
)

const (
	testTenant = "11111111-2222-3333-4444-555555555555"
	testClient = "99999999-8888-7777-6666-000000000000"
	testToken  = "graph-access-token"
	rbToken    = "rbk_testtoken"
)

var testNow = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func genKey(t *testing.T, bits int) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "rackbook-entra-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func writePEM(t *testing.T, key *rsa.PrivateKey, pkcs8 bool, certs ...*x509.Certificate) string {
	t.Helper()
	var buf bytes.Buffer
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	} else {
		pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	}
	for _, c := range certs {
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	p := filepath.Join(t.TempDir(), "entra.pem")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeToken is the Entra token endpoint; it verifies every assertion.
type fakeToken struct {
	t    *testing.T
	srv  *httptest.Server
	cert *x509.Certificate
	mu   sync.Mutex
	hits int
}

func newFakeToken(t *testing.T, cert *x509.Certificate) *fakeToken {
	f := &fakeToken{t: t, cert: cert}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeToken) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits++
	f.mu.Unlock()
	t := f.t
	if r.Method != http.MethodPost || r.URL.Path != "/"+testTenant+"/oauth2/v2.0/token" {
		t.Errorf("token request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		t.Error(err)
	}
	want := map[string]string{
		"grant_type":            "client_credentials",
		"scope":                 "https://graph.microsoft.com/.default",
		"client_id":             testClient,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}
	for k, v := range want {
		if r.PostForm.Get(k) != v {
			t.Errorf("form %s = %q, want %q", k, r.PostForm.Get(k), v)
		}
	}
	parts := strings.Split(r.PostForm.Get("client_assertion"), ".")
	if len(parts) != 3 {
		t.Errorf("assertion has %d parts", len(parts))
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Error(err)
		}
		return b
	}
	var hdr map[string]string
	json.Unmarshal(dec(parts[0]), &hdr)
	s1 := sha1.Sum(f.cert.Raw)
	s2 := sha256.Sum256(f.cert.Raw)
	wantHdr := map[string]string{
		"alg": "RS256", "typ": "JWT",
		"x5t":      base64.RawURLEncoding.EncodeToString(s1[:]),
		"x5t#S256": base64.RawURLEncoding.EncodeToString(s2[:]),
	}
	if !reflect.DeepEqual(hdr, wantHdr) {
		t.Errorf("header = %v, want %v", hdr, wantHdr)
	}
	var cl struct {
		Aud, Iss, Sub, Jti string
		Nbf, Iat, Exp      int64
	}
	json.Unmarshal(dec(parts[1]), &cl)
	if cl.Aud != "http://"+r.Host+"/"+testTenant+"/oauth2/v2.0/token" || cl.Iss != testClient || cl.Sub != testClient || len(cl.Jti) < 16 {
		t.Errorf("claims = %+v", cl)
	}
	if cl.Exp-cl.Nbf != 300 || cl.Nbf != cl.Iat || time.Since(time.Unix(cl.Nbf, 0)) > time.Minute {
		t.Errorf("times = %+v", cl)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(f.cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], dec(parts[2])); err != nil {
		t.Errorf("signature: %v", err)
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"access_token": testToken, "expires_in": 3599, "token_type": "Bearer"})
}

// fakeGraph is Microsoft Graph with two pages of applications.
type fakeGraph struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	pages    [][]graphObject
	sps      []graphObject
	throttle int    // answer this many requests to /applications with 429
	always   int    // answer every request with this status when non-zero
	nextHost string // when set, nextLink points at this base instead
	hits     int
}

func newFakeGraph(t *testing.T) *fakeGraph {
	f := &fakeGraph{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGraph) base() string { return f.srv.URL + "/v1.0" }

func (f *fakeGraph) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		f.t.Errorf("graph auth header = %q", r.Header.Get("Authorization"))
	}
	if f.always != 0 {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(f.always)
		return
	}
	q := r.URL.Query()
	if q.Get("$top") != "999" || q.Get("$select") != "id,appId,displayName,passwordCredentials,keyCredentials" {
		f.t.Errorf("graph query = %v", q)
	}
	switch r.URL.Path {
	case "/v1.0/applications":
		if f.throttle > 0 {
			f.throttle--
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		n := 0
		fmt.Sscan(q.Get("page"), &n)
		out := map[string]any{"value": f.pages[n]}
		if n+1 < len(f.pages) {
			base := f.base()
			if f.nextHost != "" {
				base = f.nextHost
			}
			out["@odata.nextLink"] = fmt.Sprintf("%s/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999&page=%d", base, n+1)
		}
		json.NewEncoder(w).Encode(out)
	case "/v1.0/servicePrincipals":
		json.NewEncoder(w).Encode(map[string]any{"value": f.sps})
	default:
		http.NotFound(w, r)
	}
}

// fakeRB implements /api/c/credentials with hashes and the module rules.
type fakeRB struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	records  map[string]map[string]any
	writes   int
	denyAll  bool
	conflict bool
}

var allowedFields = map[string]bool{"kind": true, "self_signed": true, "purpose": true, "expires": true, "not_before": true, "kid": true, "ids": true, "revoked": true, "source": true}

func newFakeRB(t *testing.T) *fakeRB {
	f := &fakeRB{t: t, records: map[string]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func hashOf(d map[string]any) string {
	b, _ := json.Marshal(d)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:8])
}

func (f *fakeRB) seed(name string, data map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data["name"] = name
	f.records[name] = data
}

func (f *fakeRB) get(name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[name]
}

func (f *fakeRB) setField(name, k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[name][k] = v
}

func jerr(w http.ResponseWriter, status int, code, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func (f *fakeRB) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+rbToken {
		jerr(w, http.StatusUnauthorized, "unauthorized", "bad token")
		return
	}
	const prefix = "/api/c/credentials"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == prefix:
		names := make([]string, 0, len(f.records))
		for n := range f.records {
			names = append(names, n)
		}
		sort.Strings(names)
		recs := []map[string]any{}
		for _, n := range names {
			recs = append(recs, map[string]any{"id": n, "hash": hashOf(f.records[n]), "data": f.records[n]})
		}
		json.NewEncoder(w).Encode(map[string]any{"records": recs})
	case r.Method == http.MethodPost && r.URL.Path == prefix:
		var in struct{ Data map[string]any }
		json.NewDecoder(r.Body).Decode(&in)
		if f.denyAll {
			jerr(w, 403, "forbidden", "module entra may only write: allow list says no")
			return
		}
		if in.Data["source"] != "entra" {
			jerr(w, 403, "forbidden", "source must be entra")
			return
		}
		name, _ := in.Data["name"].(string)
		if _, ok := f.records[name]; ok || f.conflict {
			jerr(w, 409, "conflict", "exists")
			return
		}
		f.records[name] = in.Data
		f.writes++
		json.NewEncoder(w).Encode(map[string]any{"id": name, "hash": hashOf(in.Data), "data": in.Data})
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, prefix+"/"):
		id := strings.TrimPrefix(r.URL.Path, prefix+"/")
		var in struct {
			Data map[string]any
			Hash string
		}
		json.NewDecoder(r.Body).Decode(&in)
		old, ok := f.records[id]
		if !ok {
			jerr(w, 404, "not_found", "no such record")
			return
		}
		if f.denyAll {
			jerr(w, 403, "forbidden", "module entra may only write: allow list says no")
			return
		}
		if f.conflict || in.Hash != hashOf(old) {
			jerr(w, 409, "conflict", "changed")
			return
		}
		if old["source"] != "entra" || in.Data["source"] != "entra" {
			jerr(w, 403, "forbidden", "not a record of this module")
			return
		}
		for k := range in.Data {
			if !allowedFields[k] && !reflect.DeepEqual(in.Data[k], old[k]) {
				jerr(w, 403, "forbidden", "field "+k+" is not in the module's fields")
				return
			}
		}
		for k := range old {
			if _, ok := in.Data[k]; !ok && !allowedFields[k] {
				jerr(w, 403, "forbidden", "field "+k+" removed")
				return
			}
		}
		f.records[id] = in.Data
		f.writes++
		json.NewEncoder(w).Encode(map[string]any{"id": id, "hash": hashOf(in.Data), "data": in.Data})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeRB) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

type env struct {
	t      *testing.T
	a      *app
	graph  *fakeGraph
	rb     *fakeRB
	tok    *fakeToken
	out    *bytes.Buffer
	sleeps []time.Duration
}

func tm(s string) *time.Time {
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &v
}

const (
	appA = "aaaaaaaa-0000-0000-0000-00000000000a"
	appB = "bbbbbbbb-0000-0000-0000-00000000000b"
	appC = "cccccccc-0000-0000-0000-00000000000c"
	appD = "dddddddd-0000-0000-0000-00000000000d"
	k1   = "11111111-aaaa-0000-0000-000000000001"
	k2   = "22222222-aaaa-0000-0000-000000000002"
	k3   = "33333333-aaaa-0000-0000-000000000003"
	k4   = "44444444-aaaa-0000-0000-000000000004"
	k5   = "55555555-aaaa-0000-0000-000000000005"
	k6   = "66666666-aaaa-0000-0000-000000000006"
	kx   = "77777777-aaaa-0000-0000-000000000007"
)

func newEnv(t *testing.T) *env {
	key, cert := genKey(t, 2048)
	pemPath := writePEM(t, key, true, cert)
	e := &env{t: t, out: &bytes.Buffer{}}
	e.tok = newFakeToken(t, cert)
	e.graph = newFakeGraph(t)
	e.rb = newFakeRB(t)

	e.graph.pages = [][]graphObject{
		{
			{ID: "oa", AppID: appA, DisplayName: "Billing Service!", PasswordCredentials: []graphKeyCred{
				{KeyID: k1, DisplayName: "prod", Start: tm("2026-03-01T10:00:00Z"), End: tm("2027-03-01T10:00:00Z")},
				{KeyID: k2, DisplayName: "cert", Start: tm("2026-04-01T00:00:00Z"), End: tm("2027-06-01T00:00:00Z")},
			}, KeyCredentials: []graphKeyCred{
				{KeyID: k2, DisplayName: "cert", Start: tm("2026-04-01T00:00:00Z"), End: tm("2027-06-01T00:00:00Z")},
			}},
		},
		{
			{ID: "ob", AppID: appB, DisplayName: "Platform Managed", PasswordCredentials: []graphKeyCred{
				{KeyID: kx, End: tm("2027-01-01T00:00:00Z")},
			}},
			{ID: "oc", AppID: appC, DisplayName: "Legacy", PasswordCredentials: []graphKeyCred{
				{KeyID: k3, DisplayName: "secret [2025]", End: tm("2026-01-01T00:00:00Z")},
				{KeyID: k4, DisplayName: "secret [2026]", End: tm("2027-09-01T00:00:00Z")},
				{KeyID: k5, DisplayName: "no end"},
			}},
		},
	}
	e.graph.sps = []graphObject{
		{ID: "spa", AppID: appA, DisplayName: "Billing Service!", PasswordCredentials: []graphKeyCred{
			{KeyID: k1, DisplayName: "prod", Start: tm("2026-03-01T10:00:00Z"), End: tm("2027-03-01T10:00:00Z")},
		}},
		{ID: "spd", AppID: appD, DisplayName: "Daemon", PasswordCredentials: []graphKeyCred{
			{KeyID: k6, DisplayName: "d", End: tm("2027-02-02T00:00:00Z")},
		}},
	}

	cfg := &Config{
		Rackbook: RackbookConfig{URL: e.rb.srv.URL, TokenFile: "tok", Collection: "credentials", Source: "entra"},
		Entra: EntraConfig{
			TenantID: testTenant, ClientID: testClient, CertificateFile: pemPath,
			ExcludeAppIDs: []string{strings.ToUpper(appB)},
			AuthorityHost: e.tok.srv.URL, GraphURL: e.graph.base(),
		},
		Record: RecordConfig{Defaults: map[string]any{"owner": "ops", "used_by": []any{"all"}}},
	}
	if err := cfg.finish(); err != nil {
		t.Fatal(err)
	}
	rb, err := rbclient.New(e.rb.srv.URL, rbToken)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	ts := newTokenSource(cfg.Entra, key, cert, hc)
	g := newGraphClient(cfg.Entra.GraphURL, ts, hc)
	g.sleep = func(_ context.Context, d time.Duration) error { e.sleeps = append(e.sleeps, d); return nil }
	e.a = &app{cfg: cfg, graph: g, rb: rb, out: e.out, now: func() time.Time { return testNow },
		log: slog.New(slog.NewTextHandler(testWriter{t}, nil))}
	return e
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func (e *env) run(dry bool) result {
	e.t.Helper()
	res, err := e.a.syncOnce(context.Background(), dry)
	if err != nil {
		e.t.Fatalf("sync: %v", err)
	}
	return res
}

func name(prefixApp, keyID string) string { return "entra-" + prefixApp + "-" + keyID[:8] }
