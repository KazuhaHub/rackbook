package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/sops"
	"github.com/kazuhahub/rackbook/internal/sops/sopstest"
)

const (
	sAlphaToken = "ALPHA-TOKEN-0123456789"
	sNewValue   = "NEW-VALUE-9876543210"
)

// spy counts decryptions: listing a file must never decrypt it.
type spy struct {
	ansiblerepo.Sopser
	decrypts atomic.Int32
}

func (s *spy) Decrypt(ctx context.Context, enc []byte, key string) ([]byte, error) {
	s.decrypts.Add(1)
	return s.Sopser.Decrypt(ctx, enc, key)
}

type sEnv struct {
	*wEnv
	sx   *sopstest.Env
	conf string
	spy  *spy
	tmp  string
	log  string
}

// newSEnv seeds a repository with real SOPS files: alpha (readable by the
// server's key, holding two keys), beta (no file yet) and a .sops.yaml whose
// rules name the admin, the server and the host key.
func newSEnv(t *testing.T, mut func(o *api.Options, io *api.InfraOptions), tweak func(s *sEnv, seed map[string]string)) *sEnv {
	t.Helper()
	sx := sopstest.New(t)
	s := &sEnv{sx: sx, tmp: t.TempDir(), log: filepath.Join(t.TempDir(), "calls.log")}
	s.conf = sx.Config(map[string][]string{
		"secrets/alpha.sops.yaml": {"admin", "server", "host"},
		"secrets/beta.sops.yaml":  {"admin", "server", "host"},
	})
	seed := map[string]string{
		".sops.yaml":              s.conf,
		"secrets/alpha.sops.yaml": sx.Encrypt(t, s.conf, "secrets/alpha.sops.yaml", `{"cloudflare_dns_token":"`+sAlphaToken+`","feature_demo_token":"old-demo-token"}`),
		"secrets/beta.sops.yaml":  "",
	}
	if tweak != nil {
		tweak(s, seed)
	}
	r, err := sops.New(context.Background(), sops.Options{KeyFile: sx.KeyFile("server"), Sops: sx.Wrapper(t, s.log), AgeKeygen: sx.AgeKeygen, Tmp: s.tmp})
	if err != nil {
		t.Fatal(err)
	}
	s.spy = &spy{Sopser: r}
	s.wEnv = newWEnvX(t, wExtra{seed: seed, sops: s.spy}, mut)
	return s
}

func (s *sEnv) secretsPath(host, tail string) string {
	return "/api/infra/hosts/" + host + "/secrets" + tail
}

func (s *sEnv) file(t *testing.T, host string) map[string]any {
	t.Helper()
	code, body, _ := s.do(t, "GET", s.secretsPath(host, ""), nil, me)
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	return body
}

func (s *sEnv) base(t *testing.T, host string) string {
	return s.file(t, host)["file"].(map[string]any)["base"].(string)
}

func (s *sEnv) reveal(t *testing.T, host, key string, hdr map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	return s.do(t, "POST", s.secretsPath(host, "/reveal"), map[string]any{"key": key}, hdr)
}

func keyNames(t *testing.T, body map[string]any) []string {
	t.Helper()
	var out []string
	for _, k := range arr(t, body["file"].(map[string]any)["keys"]) {
		out = append(out, k.(map[string]any)["name"].(string))
	}
	return out
}

func TestSecretsListShowsNamesWithoutDecrypting(t *testing.T) {
	s := newSEnv(t, nil, nil)
	body := s.file(t, "alpha")
	if got := strings.Join(keyNames(t, body), ","); got != "cloudflare_dns_token,feature_demo_token" {
		t.Fatalf("keys %s", got)
	}
	f := body["file"].(map[string]any)
	if f["canDecrypt"] != true || f["exists"] != true || len(arr(t, f["recipients"])) != 3 || len(arr(t, f["rule"])) != 3 {
		t.Fatalf("%v", f)
	}
	if body["publicKey"] != s.sx.Pub("server") || body["enabled"] != true || body["canWrite"] != true {
		t.Fatalf("%v", body)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), sAlphaToken) || strings.Contains(string(raw), "old-demo-token") {
		t.Fatal("a value in the listing")
	}
	// a host without a file yet
	if f := s.file(t, "beta")["file"].(map[string]any); f["exists"] != false || len(arr(t, f["keys"])) != 0 {
		t.Fatalf("%v", f)
	}
	if code, _, _ := s.do(t, "GET", s.secretsPath("nope", ""), nil, me); code != 404 {
		t.Fatalf("%d", code)
	}
	if n := s.spy.decrypts.Load(); n != 0 {
		t.Fatalf("listing decrypted %d times", n)
	}
	// the key names of a file the server's key cannot read are listed too
	s2 := newSEnv(t, nil, func(s *sEnv, seed map[string]string) {
		seed[".sops.yaml"] = s.sx.Config(map[string][]string{"secrets/alpha.sops.yaml": {"admin", "host"}})
		seed["secrets/alpha.sops.yaml"] = s.sx.Encrypt(t, seed[".sops.yaml"], "secrets/alpha.sops.yaml", `{"only_name":"v"}`)
	})
	f = s2.file(t, "alpha")["file"].(map[string]any)
	if f["canDecrypt"] != false || len(arr(t, f["keys"])) != 1 {
		t.Fatalf("%v", f)
	}
}

func TestSecretsRevealIsAuditedNoStoreAndRateLimited(t *testing.T) {
	var logBuf bytes.Buffer
	sink := &jsonSink{}
	s := newSEnv(t, func(o *api.Options, io *api.InfraOptions) {
		lg := slog.New(slog.NewTextHandler(&logBuf, nil))
		o.Logger = lg
		io.Audit = multiAuditor{&ansiblerepo.AuditLog{Log: lg}, sink}
	}, nil)
	code, body, hdr := s.reveal(t, "alpha", "cloudflare_dns_token", me)
	if code != 200 || body["value"] != sAlphaToken {
		t.Fatalf("%d %v", code, body)
	}
	if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control %q", cc)
	}
	// who, what and when are audited; the value is not, anywhere
	raw := sink.bytes()
	var e ansiblerepo.AuditEntry
	if err := json.Unmarshal(bytes.TrimSpace(raw), &e); err != nil {
		t.Fatalf("%v %q", err, raw)
	}
	if e.Who != "me@kazuha.org" || e.Outcome != "revealed" || e.Action != "infra(secrets/alpha): reveal cloudflare_dns_token" || e.Time.IsZero() || len(e.Files) != 1 || e.Files[0] != "secrets/alpha.sops.yaml" {
		t.Fatalf("%+v", e)
	}
	if strings.Contains(string(raw), sAlphaToken) || strings.Contains(logBuf.String(), sAlphaToken) {
		t.Fatal("the value reached the audit or the log")
	}
	// refused, missing and invalid key names
	if code, _, _ := s.reveal(t, "alpha", "nope", me); code != 404 {
		t.Fatalf("missing key: %d", code)
	}
	if code, _, _ := s.reveal(t, "alpha", "../Etc", me); code != 404 {
		t.Fatalf("bad key name: %d", code)
	}
	if code, _, _ := s.reveal(t, "alpha", "sops", me); code != 404 {
		t.Fatalf("the metadata is not a key: %d", code)
	}
	if code, _, _ := s.reveal(t, "nope", "x", me); code != 404 {
		t.Fatalf("host: %d", code)
	}
	// ten reveals a minute
	got429 := false
	for i := 0; i < 12; i++ {
		if code, _, h := s.reveal(t, "alpha", "feature_demo_token", me); code == 429 {
			got429 = h.Get("Retry-After") != ""
			break
		}
	}
	if !got429 {
		t.Fatal("reveals are not rate limited")
	}
	raw = sink.bytes()
	if !strings.Contains(string(raw), `"outcome":"rate_limited"`) || strings.Contains(string(raw), "old-demo-token") {
		t.Fatalf("%s", raw)
	}
	if !strings.Contains(logBuf.String(), "reveal limit reached") || !strings.Contains(logBuf.String(), "me@kazuha.org") {
		t.Fatalf("no warning with the identity: %s", logBuf.String())
	}
	if s.remote(t, "%s") != "seed" {
		t.Fatal("a reveal committed something")
	}
}

func TestSecretsSetAndUnsetAreCommits(t *testing.T) {
	s := newSEnv(t, nil, nil)
	base := s.base(t, "alpha")
	// replace one, add one
	code, res, _ := s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"base": base, "key": "cloudflare_dns_token", "value": sNewValue}, me)
	if code != 200 || res["commit"] == "" {
		t.Fatalf("%d %v", code, res)
	}
	if subj := s.remote(t, "%s"); subj != "infra(secrets/alpha): set cloudflare_dns_token" {
		t.Fatalf("subject %q", subj)
	}
	if body := s.remote(t, "%b"); !strings.Contains(body, "Files: secrets/alpha.sops.yaml") || strings.Contains(body, "Co-Authored") {
		t.Fatalf("trailers %q", body)
	}
	if a := s.remote(t, "%ae"); a != "me@kazuha.org" {
		t.Fatalf("author %q", a)
	}
	if c := s.remote(t, "%ce"); c != "rackbook@kazuha.org" {
		t.Fatalf("committer %q", c)
	}
	committed := sh(t, s.bare, "show", "HEAD:secrets/alpha.sops.yaml")
	if strings.Contains(committed, sNewValue) || strings.Contains(committed, sAlphaToken) || !strings.Contains(committed, "ENC[AES256_GCM") {
		t.Fatalf("the committed file is not encrypted:\n%s", committed)
	}
	for _, d := range arr(t, res["diffs"]) {
		if strings.Contains(d.(map[string]any)["diff"].(string), "ENC[") {
			t.Fatal("ciphertext in the diff")
		}
	}
	if _, b, _ := s.reveal(t, "alpha", "cloudflare_dns_token", me); b["value"] != sNewValue {
		t.Fatalf("%v", b)
	}
	// the other key is untouched
	if _, b, _ := s.reveal(t, "alpha", "feature_demo_token", me); b["value"] != "old-demo-token" {
		t.Fatalf("%v", b)
	}
	// a stale base is a conflict, nothing is committed
	head := s.remote(t, "%H")
	code, res, _ = s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"base": base, "key": "k2", "value": sNewValue}, me)
	if code != http.StatusConflict || res["error"] != "conflict" || s.remote(t, "%H") != head {
		t.Fatalf("%d %v", code, res)
	}
	// delete
	code, res, _ = s.do(t, "POST", s.secretsPath("alpha", "/unset"), map[string]any{"base": s.base(t, "alpha"), "key": "feature_demo_token"}, me)
	if code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if subj := s.remote(t, "%s"); subj != "infra(secrets/alpha): delete feature_demo_token" {
		t.Fatalf("subject %q", subj)
	}
	if got := strings.Join(keyNames(t, s.file(t, "alpha")), ","); got != "cloudflare_dns_token" {
		t.Fatalf("keys %s", got)
	}
	if code, _, _ := s.reveal(t, "alpha", "feature_demo_token", me); code != 404 {
		t.Fatalf("deleted key: %d", code)
	}
	// deleting a key that is not there, and bad names and values
	for name, body := range map[string]map[string]any{
		"unset missing": {"key": "nope"},
		"set bad name":  {"key": "Bad Name", "value": "v"},
		"set reserved":  {"key": "sops", "value": "v"},
		"set plaintext": {"key": "a_unencrypted", "value": "v"},
		"set empty":     {"key": "k", "value": ""},
		"set too large": {"key": "k", "value": strings.Repeat("x", ansiblerepo.MaxSecretValue+1)},
		"set not text":  {"key": "k", "value": "a\x00b"},
	} {
		body["base"] = s.base(t, "alpha")
		path := "/set"
		if strings.HasPrefix(name, "unset") {
			path = "/unset"
		}
		head := s.remote(t, "%H")
		if code, res, _ := s.do(t, "POST", s.secretsPath("alpha", path), body, me); code != http.StatusUnprocessableEntity && code != http.StatusRequestEntityTooLarge && code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, code, res)
		}
		if s.remote(t, "%H") != head {
			t.Errorf("%s committed", name)
		}
	}
}

func TestSecretsCreateTheFileOfAHostWithoutOne(t *testing.T) {
	s := newSEnv(t, nil, nil)
	code, res, _ := s.do(t, "POST", s.secretsPath("beta", "/set"), map[string]any{"base": "", "key": "first_key", "value": sNewValue}, me)
	if code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	f := sh(t, s.bare, "show", "HEAD:secrets/beta.sops.yaml")
	if strings.Contains(f, sNewValue) || !strings.Contains(f, s.sx.Pub("server")) || !strings.Contains(f, s.sx.Pub("host")) {
		t.Fatalf("%s", f)
	}
	if _, b, _ := s.reveal(t, "beta", "first_key", me); b["value"] != sNewValue {
		t.Fatalf("%v", b)
	}
	// deleting from a file that does not exist
	if code, _, _ := s.do(t, "POST", s.secretsPath("alpha", "/unset"), map[string]any{"base": s.base(t, "alpha"), "key": "nope"}, me); code != http.StatusUnprocessableEntity {
		t.Fatalf("%d", code)
	}
}

func TestSecretsNoValueInArgvLogsAuditOrScratchFiles(t *testing.T) {
	var logBuf bytes.Buffer
	s := newSEnv(t, func(o *api.Options, io *api.InfraOptions) {
		io.Audit = &ansiblerepo.AuditLog{Log: slog.New(slog.NewTextHandler(&logBuf, nil))}
	}, nil)
	if code, res, _ := s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"base": s.base(t, "alpha"), "key": "k_new", "value": sNewValue}, me); code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if code, _, _ := s.reveal(t, "alpha", "k_new", me); code != 200 {
		t.Fatalf("%d", code)
	}
	calls, _ := os.ReadFile(s.log)
	if !strings.Contains(string(calls), "ARGV: set --value-stdin") {
		t.Fatalf("no recorded call:\n%s", calls)
	}
	for _, v := range []string{sNewValue, sAlphaToken, "old-demo-token"} {
		if strings.Contains(string(calls), v) {
			t.Fatalf("%q reached argv, an environment or a file handed to sops", v)
		}
	}
	if strings.Contains(logBuf.String(), sNewValue) {
		t.Fatal("the value was logged")
	}
	if left, _ := os.ReadDir(s.tmp); len(left) != 0 {
		t.Fatalf("scratch files left: %v", left)
	}
	// nor in the work tree of the clone or in git
	err := filepath.Walk(s.work, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(sNewValue)) {
				t.Errorf("the value is in %s", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecretsRecipientsMustMatchTheCreationRule(t *testing.T) {
	// alpha is encrypted for the host and the server, but its rule also wants the admin: it was never updated
	s := newSEnv(t, nil, func(s *sEnv, seed map[string]string) {
		old := s.sx.Config(map[string][]string{"secrets/alpha.sops.yaml": {"server", "host"}})
		seed["secrets/alpha.sops.yaml"] = s.sx.Encrypt(t, old, "secrets/alpha.sops.yaml", `{"k":"v"}`)
	})
	code, res, _ := s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"base": s.base(t, "alpha"), "key": "k2", "value": sNewValue}, me)
	if code != http.StatusUnprocessableEntity || res["error"] != "invalid" {
		t.Fatalf("%d %v", code, res)
	}
	found := false
	for _, i := range arr(t, res["issues"]) {
		found = found || i.(map[string]any)["code"] == "secrets.recipients"
	}
	if !found {
		t.Fatalf("%v", res["issues"])
	}
	if s.remote(t, "%s") != "seed" {
		t.Fatal("committed")
	}
}

func TestSecretsFileWithoutTheServersKey(t *testing.T) {
	s := newSEnv(t, nil, func(s *sEnv, seed map[string]string) {
		seed[".sops.yaml"] = s.sx.Config(map[string][]string{"secrets/alpha.sops.yaml": {"admin", "host"}})
		seed["secrets/alpha.sops.yaml"] = s.sx.Encrypt(t, seed[".sops.yaml"], "secrets/alpha.sops.yaml", `{"k":"v"}`)
	})
	code, res, _ := s.reveal(t, "alpha", "k", me)
	if code != http.StatusUnprocessableEntity || !strings.Contains(res["message"].(string), "updatekeys") {
		t.Fatalf("%d %v", code, res)
	}
	code, res, _ = s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"base": s.base(t, "alpha"), "key": "k2", "value": sNewValue}, me)
	if code != http.StatusUnprocessableEntity || res["error"] != "edit_failed" {
		t.Fatalf("%d %v", code, res)
	}
	if s.remote(t, "%s") != "seed" {
		t.Fatal("committed")
	}
}

func TestSecretFeatureSettingsGoToSOPS(t *testing.T) {
	s := newSEnv(t, nil, nil)
	path := "/api/infra/hosts/alpha/features/demo"
	base := s.wEnv.base(t, "/api/infra/hosts/alpha/vars")
	// the preview shows key names, never a value
	code, res, _ := s.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "preview": true, "settings": map[string]any{"name": "two", "token": sNewValue}}, me)
	if code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if raw, _ := json.Marshal(res); strings.Contains(string(raw), sNewValue) || len(arr(t, res["diffs"])) != 2 {
		t.Fatalf("%s", raw)
	}
	if s.remote(t, "%s") != "seed" {
		t.Fatal("a preview committed")
	}
	code, res, _ = s.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "two", "token": sNewValue}}, me)
	if code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if files := sh(t, s.bare, "show", "--name-only", "--format=", "HEAD"); !strings.Contains(files, "inventory/host_vars/alpha.yml") || !strings.Contains(files, "secrets/alpha.sops.yaml") {
		t.Fatalf("one commit, both files: %s", files)
	}
	vars := sh(t, s.bare, "show", "HEAD:inventory/host_vars/alpha.yml")
	if strings.Contains(vars, sNewValue) || strings.Contains(vars, "token") || !strings.Contains(vars, "name: two") {
		t.Fatalf("%s", vars)
	}
	if _, b, _ := s.reveal(t, "alpha", "feature_demo_token", me); b["value"] != sNewValue {
		t.Fatalf("%v", b)
	}
	// an empty secret box leaves the stored value alone, and the SOPS file untouched
	head := s.remote(t, "%H")
	base = s.wEnv.base(t, "/api/infra/hosts/alpha/vars")
	code, res, _ = s.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "three", "token": ""}}, me)
	if code != 200 || s.remote(t, "%H") == head {
		t.Fatalf("%d %v", code, res)
	}
	if files := sh(t, s.bare, "show", "--name-only", "--format=", "HEAD"); strings.Contains(files, "secrets/") {
		t.Fatalf("the SOPS file was touched: %s", files)
	}
	if _, b, _ := s.reveal(t, "alpha", "feature_demo_token", me); b["value"] != sNewValue {
		t.Fatalf("%v", b)
	}
	// a secret value is checked against its definition
	base = s.wEnv.base(t, "/api/infra/hosts/alpha/vars")
	code, res, _ = s.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "three", "token": "{{ evil }}"}}, me)
	if code != http.StatusUnprocessableEntity || arr(t, res["issues"])[0].(map[string]any)["code"] != "feature.bad_value" {
		t.Fatalf("%d %v", code, res)
	}
}

func TestSecretsAuthorizationMatrix(t *testing.T) {
	s := newSEnv(t, nil, nil)
	base := s.base(t, "alpha")
	type req struct {
		method, path string
		body         map[string]any
	}
	reqs := map[string]req{
		"list":      {"GET", s.secretsPath("alpha", ""), nil},
		"reveal":    {"POST", s.secretsPath("alpha", "/reveal"), map[string]any{"key": "cloudflare_dns_token"}},
		"set":       {"POST", s.secretsPath("alpha", "/set"), map[string]any{"base": base, "key": "k", "value": sNewValue}},
		"unset":     {"POST", s.secretsPath("alpha", "/unset"), map[string]any{"base": base, "key": "cloudflare_dns_token"}},
		"reencrypt": {"POST", s.secretsPath("alpha", "/reencrypt"), map[string]any{"base": base}},
	}
	denied := map[string]map[string]string{
		"not an infra admin": {"X-User": "editor@kazuha.org"},
		"API token":          {"Authorization": "Bearer token"},
		"OAuth token":        {"Authorization": "Bearer oauth"},
		"MCP token":          {"Authorization": "Bearer mcphub"},
		"passkey":            {"X-User": "me@kazuha.org", "X-Method": "passkey"},
		"another issuer":     {"X-User": "me@kazuha.org", "X-Issuer": "https://evil.test"},
		"another client":     {"X-User": "me@kazuha.org", "X-Client": "other-app"},
	}
	for rn, r := range reqs {
		for name, hdr := range denied {
			code, body, _ := s.do(t, r.method, r.path, r.body, hdr)
			if code != http.StatusForbidden || body["error"] != "forbidden" {
				t.Errorf("%s as %s: %d %v", rn, name, code, body)
			}
			if raw, _ := json.Marshal(body); strings.Contains(string(raw), sAlphaToken) {
				t.Errorf("%s as %s: a value leaked", rn, name)
			}
		}
		if code, _, _ := s.do(t, r.method, r.path, r.body, nil); code != http.StatusUnauthorized {
			t.Errorf("%s without a session: %d", rn, code)
		}
	}
	// a session older than the window may list but not reveal or change anything
	stale := map[string]string{"X-User": "me@kazuha.org", "X-Signed-In-Age": "46800"}
	for _, rn := range []string{"reveal", "set", "unset", "reencrypt"} {
		r := reqs[rn]
		if code, body, _ := s.do(t, r.method, r.path, r.body, stale); code != http.StatusForbidden || body["error"] != "reauth_required" {
			t.Errorf("%s with a stale session: %d %v", rn, code, body)
		}
	}
	if code, _, _ := s.do(t, "GET", reqs["list"].path, nil, stale); code != 200 {
		t.Errorf("list with a stale session: %d", code)
	}
	if s.remote(t, "%s") != "seed" {
		t.Fatal("a refused request committed something")
	}
	if outs := s.audit.outcomes(); len(outs) == 0 {
		t.Fatal("refusals are not audited")
	} else {
		for _, o := range outs {
			if o == "revealed" {
				t.Fatalf("a refused request revealed: %v", outs)
			}
		}
	}
}

func TestSecretsOffWithoutAKeyFile(t *testing.T) {
	e := newWEnv(t, nil)
	code, body, _ := e.do(t, "GET", "/api/infra/hosts/alpha/secrets", nil, me)
	if code != 200 || body["enabled"] != false || body["publicKey"] != "" {
		t.Fatalf("%d %v", code, body)
	}
	for _, p := range []string{"/reveal", "/set", "/unset", "/reencrypt"} {
		if code, body, _ := e.do(t, "POST", "/api/infra/hosts/alpha/secrets"+p, map[string]any{"key": "k", "value": "v", "base": ""}, me); code != http.StatusForbidden || body["error"] != "secrets_off" {
			t.Errorf("%s: %d %v", p, code, body)
		}
	}
	// on a server with the editors off the commits are off
	s := newSEnv(t, func(o *api.Options, io *api.InfraOptions) { io.Write = false }, nil)
	if code, body, _ := s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"key": "k", "value": "v", "base": ""}, me); code != http.StatusForbidden || body["error"] != "read_only" {
		t.Fatalf("%d %v", code, body)
	}
}

func TestSecretsRevealRefusedOnAReadOnlyServer(t *testing.T) {
	s := newSEnv(t, func(o *api.Options, io *api.InfraOptions) { o.ReadOnly = true }, nil)
	code, body, _ := s.reveal(t, "alpha", "cloudflare_dns_token", me)
	if code != http.StatusForbidden || body["error"] != "read_only" {
		t.Fatalf("%d %v", code, body)
	}
	if raw, _ := json.Marshal(body); strings.Contains(string(raw), sAlphaToken) {
		t.Fatal("value leaked")
	}
}

func TestSecretsOnlyManagedHostsWithTheirOwnRule(t *testing.T) {
	inv := wInventory + "    extra:\n      hosts:\n        admin:\n        gamma:\n"
	inv = strings.Replace(inv, "        beta:\n", "        beta:\n        admin:\n        gamma:\n", 1)
	inv = strings.Replace(inv, "    extra:\n      hosts:\n        admin:\n        gamma:\n", "    solo:\n      hosts:\n        solo:\n", 1)
	s := newSEnv(t, nil, func(s *sEnv, seed map[string]string) {
		seed["inventory/hosts.yml"] = inv
		// admin has a rule and a file; gamma is managed with a file but no rule of its own; a broad rule covers it
		conf := s.sx.Config(map[string][]string{"secrets/alpha.sops.yaml": {"admin", "server", "host"}, "secrets/beta.sops.yaml": {"admin", "server", "host"}, "secrets/admin.sops.yaml": {"admin", "server"}})
		conf += "  - path_regex: ^secrets/.*$\n    age: \"" + s.sx.Pub("admin") + "," + s.sx.Pub("server") + "\"\n"
		seed[".sops.yaml"] = conf
		seed["secrets/alpha.sops.yaml"] = s.sx.Encrypt(t, conf, "secrets/alpha.sops.yaml", `{"cloudflare_dns_token":"`+sAlphaToken+`"}`)
		seed["secrets/admin.sops.yaml"] = s.sx.Encrypt(t, conf, "secrets/admin.sops.yaml", `{"ci_signing_key":"ADMIN-ONLY"}`)
		seed["secrets/gamma.sops.yaml"] = s.sx.Encrypt(t, conf, "secrets/gamma.sops.yaml", `{"k":"v"}`)
		seed["secrets/solo.sops.yaml"] = s.sx.Encrypt(t, conf, "secrets/solo.sops.yaml", `{"k":"v"}`)
	})
	head := s.remote(t, "%H")
	for _, host := range []string{"admin", "gamma", "solo"} {
		for name, req := range map[string]struct {
			path string
			body map[string]any
		}{
			"list":   {s.secretsPath(host, ""), nil},
			"reveal": {s.secretsPath(host, "/reveal"), map[string]any{"key": "k"}},
			"set":    {s.secretsPath(host, "/set"), map[string]any{"base": "", "key": "k", "value": sNewValue}},
			"unset":  {s.secretsPath(host, "/unset"), map[string]any{"base": "", "key": "k"}},
		} {
			method := "POST"
			if req.body == nil {
				method = "GET"
			}
			code, body, _ := s.do(t, method, req.path, req.body, me)
			if code != http.StatusUnprocessableEntity {
				t.Errorf("%s %s: %d %v", name, host, code, body)
			}
			if raw, _ := json.Marshal(body); strings.Contains(string(raw), "ADMIN-ONLY") {
				t.Errorf("%s %s: leaked", name, host)
			}
		}
	}
	if s.remote(t, "%H") != head {
		t.Fatal("something was committed")
	}
}

func TestSecretsMultilineValuesAreKeptExactly(t *testing.T) {
	s := newSEnv(t, nil, nil)
	pem := "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"
	for _, v := range []string{pem, "no trailing newline\nsecond", "  leading and trailing space \n\n"} {
		code, res, _ := s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"base": s.base(t, "alpha"), "key": "pem_key", "value": v}, me)
		if code != 200 {
			t.Fatalf("%d %v", code, res)
		}
		if _, b, _ := s.reveal(t, "alpha", "pem_key", me); b["value"] != v {
			t.Fatalf("got %q, want %q", b["value"], v)
		}
	}
	// a PEM block whose line breaks were lost is refused
	head := s.remote(t, "%H")
	flat := "-----BEGIN PRIVATE KEY----- AAAA BBBB -----END PRIVATE KEY-----"
	code, res, _ := s.do(t, "POST", s.secretsPath("alpha", "/set"), map[string]any{"base": s.base(t, "alpha"), "key": "pem_key", "value": flat}, me)
	if code != http.StatusUnprocessableEntity || s.remote(t, "%H") != head {
		t.Fatalf("%d %v", code, res)
	}
	// the same through a feature's secret setting (multi-line allowed there too)
	path := "/api/infra/hosts/alpha/features/demo"
	base := s.wEnv.base(t, "/api/infra/hosts/alpha/vars")
	code, res, _ = s.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "two", "token": flat}}, me)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %v", code, res)
	}
	code, res, _ = s.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "two", "token": pem}}, me)
	if code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if _, b, _ := s.reveal(t, "alpha", "feature_demo_token", me); b["value"] != pem {
		t.Fatalf("%q", b["value"])
	}
}

func TestSecretsReencryptChangesRecipientsAndDataKey(t *testing.T) {
	// the file is encrypted for admin, server and host; the rule now wants admin, server and other
	s := newSEnv(t, nil, func(s *sEnv, seed map[string]string) {
		seed[".sops.yaml"] = s.sx.Config(map[string][]string{"secrets/alpha.sops.yaml": {"admin", "server", "other"}, "secrets/beta.sops.yaml": {"admin", "server", "other"}})
	})
	f := s.file(t, "alpha")["file"].(map[string]any)
	if len(arr(t, f["recipients"])) != 3 || len(arr(t, f["rule"])) != 3 || strings.Join(strs(arr(t, f["recipients"])), ",") == strings.Join(strs(arr(t, f["rule"])), ",") {
		t.Fatalf("the listing does not show the difference: %v", f)
	}
	before := sh(t, s.bare, "show", "HEAD:secrets/alpha.sops.yaml")
	base := s.base(t, "alpha")
	code, res, _ := s.do(t, "POST", s.secretsPath("alpha", "/reencrypt"), map[string]any{"base": base}, me)
	if code != 200 || res["commit"] == "" {
		t.Fatalf("%d %v", code, res)
	}
	if subj := s.remote(t, "%s"); subj != "infra(secrets/alpha): re-encrypt for the .sops.yaml recipients (new data key)" {
		t.Fatalf("subject %q", subj)
	}
	after := sh(t, s.bare, "show", "HEAD:secrets/alpha.sops.yaml")
	if after == before || strings.Contains(after, s.sx.Pub("host")) || !strings.Contains(after, s.sx.Pub("other")) || strings.Contains(after, sAlphaToken) {
		t.Fatalf("recipients or data key not changed:\n%s", after)
	}
	f = s.file(t, "alpha")["file"].(map[string]any)
	if strings.Join(strs(arr(t, f["recipients"])), ",") != strings.Join(strs(arr(t, f["rule"])), ",") || f["canDecrypt"] != true {
		t.Fatalf("%v", f)
	}
	if _, b, _ := s.reveal(t, "alpha", "cloudflare_dns_token", me); b["value"] != sAlphaToken {
		t.Fatalf("%v", b)
	}
	// the removed recipient cannot read it any more, the new one can
	for who, ok := range map[string]bool{"host": false, "other": true} {
		r, err := sops.New(context.Background(), sops.Options{KeyFile: s.sx.KeyFile(who), Sops: s.sx.Sops, AgeKeygen: s.sx.AgeKeygen, Tmp: s.tmp})
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.Decrypt(context.Background(), []byte(after), "cloudflare_dns_token")
		if ok && err != nil || !ok && !errors.Is(err, sops.ErrCannotDecrypt) {
			t.Errorf("%s: %v", who, err)
		}
	}
	// it is audited (who, what, files), without a value
	var found bool
	for _, e := range s.audit.e {
		if e.Action == "infra(secrets/alpha): reencrypt" && e.Outcome == "reencrypted" && e.Who == "me@kazuha.org" && len(e.Files) == 1 && e.Files[0] == "secrets/alpha.sops.yaml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("not audited: %+v", s.audit.e)
	}
	// a stale base is a conflict
	head := s.remote(t, "%H")
	if code, res, _ := s.do(t, "POST", s.secretsPath("alpha", "/reencrypt"), map[string]any{"base": base}, me); code != http.StatusConflict || s.remote(t, "%H") != head {
		t.Fatalf("%d %v", code, res)
	}
	// with the recipients already right it still makes a new data key
	code, _, _ = s.do(t, "POST", s.secretsPath("alpha", "/reencrypt"), map[string]any{"base": s.base(t, "alpha")}, me)
	if code != 200 || sh(t, s.bare, "show", "HEAD:secrets/alpha.sops.yaml") == after {
		t.Fatalf("%d: no new data key", code)
	}
}

func TestSecretsReencryptRefusals(t *testing.T) {
	refuse := func(name string, host string, tweak func(s *sEnv, seed map[string]string), want string) {
		t.Run(name, func(t *testing.T) {
			s := newSEnv(t, nil, tweak)
			head := s.remote(t, "%H")
			code, res, _ := s.do(t, "POST", s.secretsPath(host, "/reencrypt"), map[string]any{"base": s.base(t, host)}, me)
			raw, _ := json.Marshal(res)
			if code != http.StatusUnprocessableEntity || !strings.Contains(string(raw), want) || s.remote(t, "%H") != head {
				t.Fatalf("%d %s", code, raw)
			}
		})
	}
	// the rule does not list the server's own key
	refuse("own key missing", "alpha", func(s *sEnv, seed map[string]string) {
		seed[".sops.yaml"] = s.sx.Config(map[string][]string{"secrets/alpha.sops.yaml": {"admin", "host"}, "secrets/beta.sops.yaml": {"admin", "server"}})
	}, "lock it out")
	// no file yet
	refuse("no file", "beta", nil, "does not exist")
	// a file with a pgp recipient besides age
	refuse("pgp", "alpha", func(s *sEnv, seed map[string]string) {
		seed["secrets/alpha.sops.yaml"] = strings.Replace(seed["secrets/alpha.sops.yaml"], "    age:\n", "    pgp:\n        - fp: ABCDEF0123456789\n          enc: x\n    age:\n", 1)
	}, "not age keys")
	// a rule with more than one key group
	refuse("key groups", "alpha", func(s *sEnv, seed map[string]string) {
		seed[".sops.yaml"] = "creation_rules:\n  - path_regex: ^secrets/alpha\\.sops\\.yaml$\n    key_groups:\n      - age: [" + s.sx.Pub("admin") + ", " + s.sx.Pub("server") + "]\n      - age: [" + s.sx.Pub("host") + "]\n"
	}, "key_groups are not supported")
}

func strs(in []any) []string {
	var out []string
	for _, v := range in {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

// jsonSink keeps the audit entries as JSON lines.
type jsonSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *jsonSink) Record(e ansiblerepo.AuditEntry) {
	b, _ := json.Marshal(e)
	j.mu.Lock()
	defer j.mu.Unlock()
	j.buf.Write(append(b, '\n'))
}

func (j *jsonSink) bytes() []byte {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]byte(nil), j.buf.Bytes()...)
}

type multiAuditor []ansiblerepo.Auditor

func (m multiAuditor) Record(e ansiblerepo.AuditEntry) {
	for _, a := range m {
		a.Record(e)
	}
}
