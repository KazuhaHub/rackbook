package secretscan

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// Secrets are assembled at run time so that this file holds no string a
// scanner (or GitHub push protection) would take for a real credential.
var (
	pemHead = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
	age     = "AGE-SECRET-KEY-1" + strings.Repeat("Q", 58)
	ghp     = "gh" + "p_" + strings.Repeat("a1B2", 9)
	ghPAT   = "github" + "_pat_" + strings.Repeat("A1b2c3", 5)
	openai  = "sk" + "-proj-" + "Ab12Cd34Ef56Gh78Ij90"
	slack   = "xox" + "b-" + "1234567890-abcdefghij"
	aws     = "AKIA" + "IOSFODNN7EXAMPLE"
	google  = "AIza" + strings.Repeat("Sy-9_xYz0", 4)[:35]
	stripe  = "sk" + "_live_" + strings.Repeat("a1B2c3", 4)
	jwt     = "eyJ" + "hbGciOiJIUzI1" + ".eyJ" + "zdWIiOiIxMjM0" + ".SflKxwRJSMeKKF2QT4"
	hex32   = strings.Repeat("0123456789abcdef", 2)
	urlPw   = "postgres://admin:hunter2pass@db.internal:5432/app"
)

func rules(t *testing.T, s *Scanner, text string) []string {
	t.Helper()
	var out []string
	for _, f := range s.ScanRecord("c", "id", map[string]any{"f": text}) {
		out = append(out, f.Rule)
	}
	return out
}

func has(rs []string, id string) bool {
	for _, r := range rs {
		if r == id {
			return true
		}
	}
	return false
}

func TestEveryRuleFiresAndKeepsQuietOnNearMisses(t *testing.T) {
	cases := []struct {
		rule string
		pos  []string
		neg  []string
	}{
		{RulePrivateKey,
			[]string{pemHead + "\nb3BlbnNz", "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----", "x -----BEGIN " + "RSA PRIVATE KEY----- y", "-----BEGIN " + "EC PRIVATE KEY-----", "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----", "-----BEGIN " + "PRIVATE KEY-----"},
			[]string{"-----BEGIN PUBLIC KEY-----", "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----BEGIN CERTIFICATE-----", "BEGIN PRIVATE KEY without dashes", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@host"}},
		{RuleAgeKey,
			[]string{age, "key " + age + " end"},
			[]string{"AGE-SECRET-KEY-1" + strings.Repeat("Q", 20), "age1" + strings.Repeat("q", 58)}},
		{RuleGitHubToken,
			[]string{ghp, "token=" + ghp, "gh" + "s_" + strings.Repeat("Z9", 20)},
			[]string{"ghp_short", "ghx_" + strings.Repeat("a", 40)}},
		{RuleGitHubPAT,
			[]string{ghPAT},
			[]string{"github_pat_short"}},
		{RuleAIKey,
			[]string{openai, "sk" + "-ant-" + "api03-Ab12Cd34Ef56Gh78Ij90", "use sk" + "-" + "Ab12Cd34Ef56Gh78Ij90Kl12 here"},
			[]string{"task-management-system-service-account", "disk-usage-monitoring-dashboard-v", "sk-short", "risk-assessment-for-all-the-hosts"}},
		{RuleSlackToken,
			[]string{slack, "xox" + "p-" + "1234567890-abcdefghij", "xa" + "pp-1-A0123456789-1234567890123-abcdef0123456789abcdef"},
			[]string{"xoxb-short", "xoxz-1234567890-abcdefghij", "xapp-x-A0123456789", "xapp-1-short", "boxb-1234567890-abcdefghij"}},
		{RuleAWSKeyID,
			[]string{aws, "ASIA" + "IOSFODNN7EXAMPLE", "id=" + aws + " ok", aws + "_x", aws + "9"},
			[]string{"AKIA" + "IOSFODNN7EXAMPL", "akia" + "iosfodnn7example"}},
		{RuleGoogleKey,
			[]string{google, "k=" + google},
			[]string{"AIza" + "short", "AIzaSyShort"}},
		{RuleStripeKey,
			[]string{stripe, "rk" + "_live_" + strings.Repeat("a1B2c3", 4)},
			[]string{"sk" + "_test_" + strings.Repeat("a1B2c3", 4), "sk" + "_live_short"}},
		{RuleJWT,
			[]string{jwt, "Authorization: " + jwt},
			[]string{"eyJhbGciOi.notjwt", "eyJhbGciOiJIUzI1.eyJ", "a.b.c"}},
		{RuleSecretAssign,
			[]string{"password: hunter2hunter2", "{\"password\": \"Hunter2Hunter2x\"}", "password: $uperS3cretPass", "db password = correcthorse", "API_KEY=abcdefgh12345", "api-key: abcdefgh12345", "client_secret: abcdefgh", "my token: abcdefgh", "privkey=abcdefgh", "passwd:abcdefgh", "notes: root password: changeme123!", "token: $GITHUB_TOKEN", "password: %DB_PASSWORD%", "api_key: https://vault.example.com/ui/kv", `password: "*K9q!vR2#mZx7"`, "notes: password: *K9q!vR2#mZx7", "password: /Tr0ub4dor&3xyz", "password: ssh-Tr0ub4dor&3xyz", "token: ssh-Tr0ub4dor3xyzQ", "password: ~/Tr0ub4dor&3xyz", "pw is password: '[K9q!vR2#mZx7]'", "password: (K9q!vR2#mZx7)", "password: <K9q!vR2#mZx7>"},
			[]string{"password: short", "token: 1234567", "the password is stored in the vault", "passwords: rotated-quarterly", "token_count: 12345678", "password: ***", "password: TBD", "password: ********", "password: ${DB_PASSWORD}", "password: op://Infra/db/password", "token: env:GITHUB_TOKEN", "password: vault:kv/db#pw", "secret: /run/secrets/db_password", "password: <redacted>", "password: xxxxxxxxxx", "password: secrets/db#password", "password policy", "密码策略", "Token Service", "password reset link sent", "the password policy is documented", "token is required for api access", "password: 待补", "token_ttl: 3600 seconds"}},
		{RuleHexKey,
			[]string{"key: " + hex32, "preshared key: " + hex32, "host nas01 luks key: " + hex32, "node n1 wg key=" + hex32, "public key: " + hex32, "hostkey: " + hex32, "gpg key: " + hex32, "nodekey:" + hex32, "'" + "key: " + hex32 + "'", "privkey=" + hex32, "KEY:" + strings.ToUpper(hex32)},
			[]string{"key: " + hex32[:31], "fingerprint: " + hex32 + hex32, "sha256: " + hex32 + hex32, "key: " + hex32 + "zz", "key_fingerprint: " + hex32}},
		{RuleURLPassword,
			[]string{urlPw, "see https://bob:pw@example.com/x", "ssh://git:token@host", "https://user:${PASSWORD}@host/"},
			[]string{"https://example.com/path", "https://host:8080/path", "ssh://git@github.com/org/repo.git", "git@github.com:org/repo.git", "https://example.com:8080", "mailto:admin@example.com"}},
	}
	s := Default()
	for _, c := range cases {
		for _, p := range c.pos {
			if got := rules(t, s, p); !has(got, c.rule) {
				t.Errorf("%s should fire on %q, got %v", c.rule, p, got)
			}
		}
		for _, n := range c.neg {
			if got := rules(t, s, n); has(got, c.rule) {
				t.Errorf("%s must not fire on %q", c.rule, n)
			}
		}
	}
}

func TestBenignOperationsText(t *testing.T) {
	for _, s := range []string{
		"fingerprint: SHA256:" + strings.Repeat("abcDEF012", 5),
		"nginx reverse proxy for the internal wiki; renew the TLS certificate every 60 days",
		"Tailscale 100.64.0.0/10, MagicDNS enabled, ACL tag:server",
		"仅允许密钥登录，禁用密码认证 (password authentication disabled)",
		"key: value", "api key rotation: quarterly",
		"https://grafana.example.com/d/abcdef/overview?orgId=1",
	} {
		if got := rules(t, Default(), s); len(got) > 0 {
			t.Errorf("%q fired %v", s, got)
		}
	}
}

func TestFindingsNeverLeakTheSecret(t *testing.T) {
	secrets := []string{pemHead, age, ghp, ghPAT, openai, slack, aws, google, stripe, jwt, hex32, "hunter2pass", "abcdefgh12345"}
	for _, sec := range secrets {
		data := map[string]any{"notes": "x password: " + sec + " y", "k": []any{sec, map[string]any{sec: "v"}}}
		for _, f := range Default().ScanRecord("c", "id", data) {
			b, _ := json.Marshal(f)
			r := []rune(strings.TrimSuffix(f.Excerpt, "…"))
			if len(r) > 4 || !strings.HasSuffix(f.Excerpt, "…") {
				t.Errorf("excerpt %q of %q", f.Excerpt, sec)
			}
			if len(sec) > 8 && strings.Contains(string(b), sec[:9]) {
				t.Errorf("finding leaks %q: %s", sec, b)
			}
			if f.Rule == "" || f.Collection != "c" {
				t.Errorf("%+v", f)
			}
		}
	}
	if got := Excerpt("abcdefghij"); got != "abc…" || Excerpt("ab") != "…" || Excerpt(strings.Repeat("z", 40)) != "zzzz…" {
		t.Fatalf("%q %q", got, Excerpt("ab"))
	}
}

func TestRecordWalkPathsKeysAndSecretIDs(t *testing.T) {
	data := map[string]any{
		"name":   "ok",
		"notes":  []any{"fine", map[string]any{"text": "pw: " + ghp}},
		"labels": map[string]any{"a/b": "token=" + openai, ghp: "v"},
		"deep":   map[string]any{"x": map[string]any{"y": aws}},
		"port":   22, "on": true, "none": nil,
	}
	fs := Default().ScanRecord("devices", "web-1", data)
	got := map[string]string{}
	for _, f := range fs {
		got[f.Path+"|"+f.In] = f.Rule
		if strings.Contains(f.Path, ghp[:10]) {
			t.Errorf("secret key in path: %q", f.Path)
		}
	}
	for _, want := range []string{"/notes/1/text|", "/labels/a~1b|", "/labels|key", "/deep/x/y|"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	// A secret used as the record id is cut to an excerpt in the report.
	for _, f := range Default().ScanRecord("c", ghp, map[string]any{"name": ghp}) {
		if strings.Contains(f.ID, "a1B2a1B2") || f.ID != RedactID(ghp) {
			t.Fatalf("id %q", f.ID)
		}
	}
}

func TestFieldNamedPasswordIsCaught(t *testing.T) {
	fs := Default().ScanRecord("c", "x", map[string]any{"password": "hunter2hunter2", "ssh_key": hex32, "public_key": hex32, "token": "short", "note": "n"})
	var paths []string
	for _, f := range fs {
		paths = append(paths, f.Path)
	}
	if strings.Join(paths, ",") != "/password,/public_key,/ssh_key" {
		t.Fatalf("%v", paths)
	}
}

func TestAllowListByHashFieldAndCollection(t *testing.T) {
	val := "hunter2hunter2"
	rec := map[string]any{"notes": "password: " + val, "other": "token: abcdefgh1234"}
	mk := func(a ...Allow) *Scanner {
		s, err := New(Config{Allow: a})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	count := func(s *Scanner, coll string) int { return len(s.ScanRecord(coll, "id", rec)) }
	if count(mk(), "c") != 2 {
		t.Fatal("baseline")
	}
	if n := count(mk(Allow{Rule: RuleSecretAssign, Collection: "c", ValueSHA256: Hash(val)}), "c"); n != 1 {
		t.Fatalf("by hash: %d", n)
	}
	if n := count(mk(Allow{Rule: RuleSecretAssign, Collection: "c", ValueSHA256: strings.ToUpper(Hash("another value"))}), "c"); n != 2 {
		t.Fatalf("wrong hash must not suppress: %d", n)
	}
	if n := count(mk(Allow{Rule: RuleSecretAssign, Field: "/notes"}), "c"); n != 1 {
		t.Fatalf("by field: %d", n)
	}
	if n := count(mk(Allow{Rule: RuleSecretAssign, Field: "notes"}), "c"); n != 1 {
		t.Fatalf("by field without slash: %d", n)
	}
	if n := count(mk(Allow{Rule: RuleSecretAssign, Collection: "c"}), "c"); n != 0 {
		t.Fatalf("by collection: %d", n)
	}
	if n := count(mk(Allow{Rule: RuleSecretAssign, Collection: "c"}), "d"); n != 2 {
		t.Fatalf("other collection: %d", n)
	}
	if n := count(mk(Allow{Rule: RuleGitHubToken, Collection: "c"}), "c"); n != 2 {
		t.Fatalf("other rule: %d", n)
	}
	// The hash of the secret part of a URL is user:password.
	s := mk(Allow{Rule: RuleURLPassword, Collection: "c", ValueSHA256: Hash("admin:hunter2pass")})
	if n := len(s.ScanRecord("c", "i", map[string]any{"u": urlPw})); n != 0 {
		t.Fatalf("url allow: %d", n)
	}
}

func TestDisableRulesAndEnabledFlag(t *testing.T) {
	s, err := New(Config{DisableRules: []string{RuleSecretAssign, RuleHexKey}})
	if err != nil {
		t.Fatal(err)
	}
	if got := rules(t, s, "password: hunter2hunter2"); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if got := rules(t, s, ghp); !has(got, RuleGitHubToken) {
		t.Fatal("other rules stay on")
	}
	off := false
	s, _ = New(Config{Enabled: &off})
	if s.Enabled() || len(s.ScanRecord("c", "i", map[string]any{"a": ghp})) != 0 || len(s.ScanSchema("c", []byte(`{"default":"`+ghp+`"}`))) != 0 || len(s.ScanState("f", []byte("name: "+ghp))) != 0 {
		t.Fatal("disabled scanner must find nothing")
	}
	var nilScanner *Scanner
	if !nilScanner.Enabled() || len(nilScanner.ScanRecord("c", "i", map[string]any{"a": ghp})) != 1 {
		t.Fatal("a nil scanner scans with the defaults")
	}
}

func TestExtraPatternsAndConfigErrors(t *testing.T) {
	s, err := New(Config{ExtraPatterns: []ExtraPattern{{ID: "corp-token", Pattern: `corp_(tok_[a-z0-9]{12})`}, {ID: "plain", Pattern: `INTERNAL-[0-9]{6}`}}})
	if err != nil {
		t.Fatal(err)
	}
	fs := s.ScanRecord("c", "i", map[string]any{"a": "x corp_tok_abcdef123456 y", "b": "INTERNAL-123456", "c": "nothing"})
	if len(fs) != 2 || fs[0].Rule != "corp-token" || fs[0].Excerpt != "tok_…" || fs[1].Rule != "plain" {
		t.Fatalf("%+v", fs)
	}
	for name, c := range map[string]Config{
		"bad regex":       {ExtraPatterns: []ExtraPattern{{ID: "a", Pattern: "("}}},
		"empty match":     {ExtraPatterns: []ExtraPattern{{ID: "a", Pattern: "x*"}}},
		"bad id":          {ExtraPatterns: []ExtraPattern{{ID: "Bad Id", Pattern: "x"}}},
		"builtin id":      {ExtraPatterns: []ExtraPattern{{ID: RuleJWT, Pattern: "x"}}},
		"unknown disable": {DisableRules: []string{"nope"}},
		"unknown allow":   {Allow: []Allow{{Rule: "nope", Collection: "c"}}},
		"allow too broad": {Allow: []Allow{{Rule: RuleJWT}}},
		"bad hash":        {Allow: []Allow{{Rule: RuleJWT, ValueSHA256: "abc"}}},
		"non hex hash":    {Allow: []Allow{{Rule: RuleJWT, Collection: "c", ValueSHA256: strings.Repeat("z", 64)}}},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// An allow entry may name an extra rule.
	if _, err := New(Config{ExtraPatterns: []ExtraPattern{{ID: "x1", Pattern: "x"}}, Allow: []Allow{{Rule: "x1", Collection: "c"}}}); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaDefaultsAndExamplesAreScanned(t *testing.T) {
	schema := `{"type":"object","description":"password: hunter2hunter2 lives elsewhere","properties":{
	  "a":{"type":"string","title":"token: abcdefgh12345","default":"` + ghp + `"},
	  "b":{"type":"string","examples":["fine","` + aws + `"]},
	  "c":{"enum":["x","` + slack + `"]},
	  "d":{"const":"` + openai + `"},
	  "e":{"type":"string","default":"plain"}}}`
	var got []string
	for _, f := range Default().ScanSchema("c", []byte(schema)) {
		got = append(got, f.Path+" "+f.Rule)
	}
	want := "/schema/description secret-assignment,/schema/properties/a/default github-token,/schema/properties/a/title secret-assignment,/schema/properties/b/examples/1 aws-access-key-id,/schema/properties/c/enum/1 slack-token,/schema/properties/d/const openai-api-key"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v", got)
	}
}

func TestStateFilesScanLabelsOnly(t *testing.T) {
	file := "users:\n  - identity: a@example.com\n    name: Ann\n    handle: " + strings.Repeat("A", 43) + "\n    credentials:\n      - id: " + strings.Repeat("B", 90) + "\n        name: " + ghp + "\n        public_key: " + strings.Repeat("C", 120) + "\ntokens:\n  - name: ci\n    prefix: rbk_abcd\n    sha256: " + strings.Repeat("e", 64) + "\n"
	fs := Default().ScanState(".rackbook/passkeys.yml", []byte(file))
	if len(fs) != 1 || fs[0].Rule != RuleGitHubToken || fs[0].Path != "/users/0/credentials/0/name" || fs[0].Collection != ".rackbook/passkeys.yml" {
		t.Fatalf("%+v", fs)
	}
	clean := strings.Replace(file, ghp, "laptop", 1)
	if fs := Default().ScanState("f", []byte(clean)); len(fs) != 0 {
		t.Fatalf("public keys, ids and hashes are exempt: %+v", fs)
	}
	if fs := Default().ScanState("f", []byte("tokens:\n  - name: \"[bad\"\n  : :")); fs != nil {
		t.Fatal("unparsable content is not this scan's business")
	}
}

func TestIntroduced(t *testing.T) {
	old := Default().ScanRecord("c", "i", map[string]any{"a": ghp})
	both := Default().ScanRecord("c", "i", map[string]any{"a": ghp, "b": aws})
	if got := Introduced(old, both); len(got) != 1 || got[0].Rule != RuleAWSKeyID {
		t.Fatalf("%+v", got)
	}
	if got := Introduced(both, old); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestErrorMessageIsRedacted(t *testing.T) {
	err := AsError(Default().ScanRecord("devices", "web", map[string]any{"notes": ghp}))
	msg := err.Error()
	if !strings.Contains(msg, "devices/web /notes") || !strings.Contains(msg, "github-token") || strings.Contains(msg, ghp[:8]) || !strings.Contains(msg, "secret_scan.allow") {
		t.Fatal(msg)
	}
	if AsError(nil) != nil {
		t.Fatal("no findings, no error")
	}
}

func TestPropertyNamedPasswordWithADefaultIsCaught(t *testing.T) {
	schema := `{"properties":{"password":{"type":"string","default":"Sup3rS3cretPass"},"note":{"type":"string","default":"Sup3rS3cretPass"}}}`
	fs := Default().ScanSchema("c", []byte(schema))
	if len(fs) != 1 || fs[0].Path != "/schema/properties/password/default" || fs[0].Rule != RuleSecretAssign {
		t.Fatalf("%+v", fs)
	}
}

func TestExtraPatternWithAnOptionalGroupAndShortMatches(t *testing.T) {
	s, err := New(Config{ExtraPatterns: []ExtraPattern{{ID: "opt", Pattern: `foo(bar)?baz[0-9]{4}`}, {ID: "short", Pattern: `ZZ-[0-9]{3}`}}})
	if err != nil {
		t.Fatal(err)
	}
	got := rules(t, s, "foobaz1234")
	if len(got) != 1 || got[0] != "opt" {
		t.Fatalf("%v", got)
	}
	if got := rules(t, s, "ZZ-123"); len(got) != 1 || got[0] != "short" {
		t.Fatalf("a short extra match: %v", got)
	}
}

func TestIntroducedIgnoresPositionSoRemovingAnEntryIsNotNewSecrets(t *testing.T) {
	b := []byte("users:\n  - name: " + ghp + "\n")
	d := Default()
	// the secret moved from index 1 to index 0 when the first entry went away
	before := d.ScanState("f", []byte("users:\n  - name: gone\n  - name: "+ghp+"\n"))
	after := d.ScanState("f", b)
	if got := Introduced(before, after); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

const body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"

func pem(t, b string) string {
	return "-----BEGIN " + t + " PRIVATE KEY-----\n" + b + "-----END " + t + " PRIVATE KEY-----"
}

func TestPrivateKeyIsMatchedAndHashedAsAWholeBlock(t *testing.T) {
	k1, k2 := pem("RSA", body), pem("RSA", "ZZZZ"+body)
	fs := Default().ScanRecord("c", "i", map[string]any{"a": "x\n" + k1 + "\ntail"})
	if len(fs) != 1 || fs[0].fp != Hash(k1) {
		t.Fatalf("%+v", fs)
	}
	// a second key of the same type next to an existing one is introduced
	before := Default().ScanRecord("c", "i", map[string]any{"a": k1})
	after := Default().ScanRecord("c", "i", map[string]any{"a": k1 + "\n" + k2})
	if got := Introduced(before, after); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	// allowing one key's hash lets only that key through
	s, err := New(Config{Allow: []Allow{{Rule: RulePrivateKey, Collection: "c", ValueSHA256: Hash(k1)}}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.ScanRecord("c", "i", map[string]any{"a": k1})); n != 0 {
		t.Fatalf("allowed key: %d", n)
	}
	if n := len(s.ScanRecord("c", "i", map[string]any{"a": k2})); n != 1 {
		t.Fatalf("another key: %d", n)
	}
	// without END the body is taken to the end of the text
	trunc := "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk"
	if fs := Default().ScanRecord("c", "i", map[string]any{"a": trunc}); len(fs) != 1 || fs[0].fp != Hash(trunc) {
		t.Fatalf("%+v", fs)
	}
}

func TestSecretNamedFieldsCountTheWholeValue(t *testing.T) {
	d := Default()
	for _, c := range []struct {
		name, value string
		fires       bool
	}{
		{"password", "correct horse battery staple", true},
		{"wifi_passphrase", "my long secret phrase", true},
		{"db-password", "hunter2", true},
		{"dbPassword", "hunter2hunter2", true},
		{"client_secret", "a b c d e f g", true},
		{"api_key", "not a real key but is", true},
		{"private_key", "some words here", true},
		{"psk", "tailscale rules ok", true},
		{"auth_tokens", "abc def ghi", true},
		{"password", "op://Infra/db/password", true},
		{"password", "env:DB_PASSWORD", true},
		{"password", "$DB_PASSWORD", true},
		{"password", "vault:kv/db#pw", true},
		{"password", "/run/secrets/db", true},
		{"password", "待补", false},
		{"password", "TBD", false},
		{"password", "-", false},
		{"password", "***", false},
		{"password", "********", true},
		{"token", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq", true},
		{"public_key", "some words here", false},
		{"password_hint", "my dog's name", false},
		{"notes", "correct horse battery staple", false},
	} {
		got := len(d.ScanRecord("c", "i", map[string]any{c.name: c.value})) > 0
		if got != c.fires {
			t.Errorf("%s=%q: fires=%v want %v", c.name, c.value, got, c.fires)
		}
	}
	// lists and maps under a secret-named key: every string inside
	fs := d.ScanRecord("c", "i", map[string]any{"passwords": []any{"first one here", map[string]any{"x": "second one here"}}, "secrets": map[string]any{"a": []any{"third one here"}}})
	var paths []string
	for _, f := range fs {
		paths = append(paths, f.Path)
	}
	if strings.Join(paths, ",") != "/passwords/0,/passwords/1/x,/secrets/a/0" {
		t.Fatalf("%v", paths)
	}
	// a password field with a spaced default in a schema
	sf := d.ScanSchema("c", []byte(`{"properties":{"password":{"default":"correct horse battery"}}}`))
	if len(sf) != 1 {
		t.Fatalf("%+v", sf)
	}
}

func TestIDBuiltFromASecretNamedFieldIsRedacted(t *testing.T) {
	fs := Default().ScanRecord("accounts", "alice/correct horse battery staple", map[string]any{"user": "alice", "password": "correct horse battery staple"})
	if len(fs) == 0 {
		t.Fatal("no finding")
	}
	for _, f := range fs {
		if strings.Contains(f.ID, "horse") || !strings.Contains(f.ID, "…~") {
			t.Fatalf("id %q", f.ID)
		}
	}
}

func TestMoreKeywordsAndRules(t *testing.T) {
	d := Default()
	for rule, vals := range map[string][]string{
		RuleSecretAssign: {"private key: abcdefgh1234", "passphrase: abcdefgh1234", "wpa_passphrase=abcdefgh1234", "psk: abcdefgh1234", "wifi_psk=abcdefgh1234", "pre-shared-key: abcdefgh1234", "preshared_key = abcdefgh1234", "private_key=abcdefgh1234"},
		RuleGitLabToken:  {"glpat" + "-" + strings.Repeat("aB1_", 6)},
		RuleNPMToken:     {"npm" + "_" + strings.Repeat("aB1", 12)},
		RuleHFToken:      {"hf" + "_" + strings.Repeat("aBcD", 9)},
		RuleTailscaleKey: {"tskey" + "-auth-" + "kABCDE1CNTRL-abcdefghij"},
		RuleSendGridKey:  {"SG" + "." + strings.Repeat("aB1_", 6)[:22] + "." + strings.Repeat("cD2-", 11)[:43]},
		RuleAzureKey:     {"DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + strings.Repeat("aB1/", 11) + "==;"},
		RuleBearer:       {"Authorization: Bearer " + strings.Repeat("aB1.", 6) + "==", "curl -H 'Bearer " + strings.Repeat("xY9", 8) + "'"},
	} {
		for _, v := range vals {
			if got := rules(t, d, v); !has(got, rule) {
				t.Errorf("%s should fire on %q, got %v", rule, v, got)
			}
		}
	}
	for rule, vals := range map[string][]string{
		RuleGitLabToken:  {"glpat-short"},
		RuleNPMToken:     {"npm_short", "npm_" + strings.Repeat("a", 30)},
		RuleHFToken:      {"hf_short", "hf_" + strings.Repeat("a", 20)},
		RuleTailscaleKey: {"tskey-short", "tskey-auth-short"},
		RuleSendGridKey:  {"SG.short.short"},
		RuleAzureKey:     {"AccountKey=short", "AccountKey="},
		RuleBearer:       {"Bearer short", "Bearer <token>"},
		RuleSecretAssign: {"psk: short", "mypsk is set", "the pre-shared key is stored in the vault"},
	} {
		for _, v := range vals {
			if got := rules(t, d, v); has(got, rule) {
				t.Errorf("%s must not fire on %q", rule, v)
			}
		}
	}
}

func TestScanYAMLWalksEveryValue(t *testing.T) {
	fs := Default().ScanYAML("rackbook.yml", []byte("collections:\n  x:\n    title: ok\n    description: \"login with "+ghp+"\"\nrules:\n  - ref: {from: a.b, to: c.d, message: \"password: hunter2hunter2\"}\n"))
	if len(fs) != 2 || fs[0].Collection != "rackbook.yml" {
		t.Fatalf("%+v", fs)
	}
}

func TestExactPlaceholdersAreNeverSecrets(t *testing.T) {
	for _, v := range []string{"待补", "TBD", "tbd", "-", "***", "n/a", "N/A", "none", "empty", ""} {
		if fs := Default().ScanRecord("c", "i", map[string]any{"password": v, "notes": v, "token": []any{v}}); len(fs) != 0 {
			t.Errorf("%q: %+v", v, fs)
		}
	}
	// only the exact value: anything around it is scanned
	for _, v := range []string{"password: *** and more words", "TBD123456", "none of your business"} {
		if fs := Default().ScanRecord("c", "i", map[string]any{"password": v}); len(fs) == 0 {
			t.Errorf("%q must be scanned", v)
		}
	}
}

const sshPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func TestAnnotatedPublicFieldsPassOnlyWithTheStrictFormat(t *testing.T) {
	schema := []byte(`{"properties":{
	 "ssh_key":{"x-rackbook":{"public":"ssh_public_key"}},
	 "fp":{"x-rackbook":{"public":"fingerprint"}},
	 "node":{"x-rackbook":{"public":"nodekey"}},
	 "age":{"x-rackbook":{"public":"age_recipient"}},
	 "pem":{"x-rackbook":{"public":"pem_public_key"}},
	 "jwk":{"x-rackbook":{"public":"jwk_public"}},
	 "hid":{"x-rackbook":{"public":"hex_id"}},
	 "password":{"x-rackbook":{"public":"secret_reference"}},
	 "keys":{"type":"array","items":{"x-rackbook":{"public":"ssh_public_key"}}},
	 "peers":{"type":"array","x-rackbook":{"public":"age_recipient"}},
	 "users":{"type":"array","items":{"properties":{"key":{"x-rackbook":{"public":"hex_id"}}}}}}}`)
	ann := AnnotationsOf(schema)
	hex64 := strings.Repeat("ab", 32)
	age := "age1" + strings.Repeat("q", 58)
	pubPEM := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----"
	good := map[string]any{
		"ssh_key": sshPubKey + " admin@host", "fp": "SHA256:" + strings.Repeat("aB1/", 10) + "aB1", "node": "nodekey:" + hex64,
		"age": age, "pem": pubPEM, "jwk": `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`,
		"hid": strings.Repeat("0123", 4), "password": "op://Infra/db/password",
		"keys":  []any{sshPubKey, sshPubKey + " a@b"},
		"peers": []any{age, age},
		"users": []any{map[string]any{"key": hex64}},
	}
	d := Default()
	if fs := d.ScanRecordWith("c", "i", good, ann); len(fs) != 0 {
		t.Fatalf("valid annotated values must pass: %+v", fs)
	}
	// without the annotations the same record is scanned as text
	if fs := d.ScanRecord("c", "i", good); len(fs) == 0 {
		t.Fatal("no annotations, no exemption")
	}
	bad := map[string]any{
		"ssh_key":  "ssh-ed25519 AAAA ghp_" + strings.Repeat("a1B2", 9), // secret in the comment
		"fp":       "password: hunter2hunter2",                          // not a fingerprint
		"node":     "nodekey:" + hex64 + " password: hunter2hunter2",    // trailing text
		"age":      "AGE-SECRET-KEY-1" + strings.Repeat("Q", 58),        // the private key
		"pem":      pemHead + "\nMIIE\n",                                // private block
		"hid":      "key: " + hex32,                                     // not a bare hex id
		"password": "correct horse battery staple",                      // not a reference
		"keys":     []any{sshPubKey, "password: hunter2hunter2"},
		"peers":    []any{age, "AGE-SECRET-KEY-1" + strings.Repeat("Q", 58)},
		"users":    []any{map[string]any{"key": "key: " + hex32}},
	}
	got := map[string]bool{}
	for _, f := range d.ScanRecordWith("c", "i", bad, ann) {
		got[strings.SplitN(strings.TrimPrefix(f.Path, "/"), "/", 2)[0]] = true
	}
	for k := range bad {
		if !got[k] {
			t.Errorf("an invalid value in %s must still be scanned", k)
		}
	}
	// a JWK with a private member is not "public"
	if d.validFor(KindJWKPublic, `{"kty":"RSA","n":"abc","d":"privateprivateprivate"}`) || d.validFor(KindJWKPublic, `{"kty":"oct","k":"abc"}`) || d.validFor(KindJWKPublic, `{"x":"1"}`) {
		t.Fatal("private JWK members must not be exempt")
	}
	// secret_reference shapes
	for v, ok := range map[string]bool{"op://v/i/f": true, "vault:kv/db#pw": true, "env:DB_PASSWORD": true, "${DB_PASSWORD}": true, "/run/secrets/db": true, "env:lower": false, "op://a b": false, "/tmp/a b": false, "hunter2hunter2": false, "$(cat x)": false} {
		got := len(d.ScanRecordWith("c", "i", map[string]any{"password": v}, ann)) == 0
		if got != ok {
			t.Errorf("secret_reference %q: pass=%v want %v", v, got, ok)
		}
	}
}

func TestSchemaDefaultsOfAnnotatedFieldsFollowTheSameRule(t *testing.T) {
	ok := `{"properties":{"k":{"default":"` + sshPubKey + `","x-rackbook":{"public":"ssh_public_key"}}}}`
	if fs := Default().ScanSchema("c", []byte(ok)); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	bad := `{"properties":{"k":{"default":"password: hunter2hunter2","x-rackbook":{"public":"ssh_public_key"}}}}`
	if fs := Default().ScanSchema("c", []byte(bad)); len(fs) == 0 {
		t.Fatal("an invalid default must be scanned")
	}
}

func TestMapKeysUnderASecretNamedMapAreValues(t *testing.T) {
	fs := Default().ScanRecord("c", "i", map[string]any{"passwords": map[string]any{"correct horse battery staple": "x"}})
	if len(fs) != 1 || fs[0].In != "key" || fs[0].Path != "/passwords" || strings.Contains(fs[0].Excerpt, "horse") {
		t.Fatalf("%+v", fs)
	}
}

func TestSecretNamesAndCaseInsensitiveBearer(t *testing.T) {
	for _, n := range []string{"secret_key", "aws_secret_access_key", "encryption_key", "client_secret", "signing_key", "private_token", "access_token", "refresh_token", "db_secret", "mysql_password", "deploy_token", "accesstoken", "secretKey", "encryptionKey", "signingKey"} {
		if fs := Default().ScanRecord("c", "i", map[string]any{n: "correct horse"}); len(fs) == 0 {
			t.Errorf("%s must be a secret name", n)
		}
	}
	for _, n := range []string{"notes", "name", "key", "public_key", "token_hint", "password_policy"} {
		if fs := Default().ScanRecord("c", "i", map[string]any{n: "correct horse"}); len(fs) != 0 {
			t.Errorf("%s must not be a secret name", n)
		}
	}
	for _, v := range []string{"bearer " + strings.Repeat("aB1.", 6), "BEARER " + strings.Repeat("aB1.", 6), "secret_key: abcdefgh1234", "aws_secret_access_key=abcdefgh1234", "encryption_key: abcdefgh1234", "signing_key = abcdefgh1234", "access_token: abcdefgh1234"} {
		if got := rules(t, Default(), v); len(got) == 0 {
			t.Errorf("%q not caught", v)
		}
	}
}

func TestRedactedIDIsStableShortAndDistinct(t *testing.T) {
	a, b := RedactID("alice/hunter2hunter2"), RedactID("alice/hunter3hunter3")
	if a == b || !strings.HasPrefix(a, "alic…~") || len(a) > len("alic…~")+8 {
		t.Fatal(a, b)
	}
}

// Each secret is wrapped in random punctuation, quotes, brackets, CJK text and
// prefixes and suffixes; every variant must still be caught.
func TestWrappedSecretsAreAlwaysCaught(t *testing.T) {
	corpus := map[string]string{
		RulePrivateKey:   pemHead + "\nb3BlbnNzaC1rZXk\n-----END " + "OPENSSH PRIVATE KEY-----",
		RuleAgeKey:       age,
		RuleGitHubToken:  ghp,
		RuleGitHubPAT:    ghPAT,
		RuleAIKey:        openai,
		RuleSlackToken:   slack,
		RuleAWSKeyID:     aws,
		RuleGoogleKey:    google,
		RuleStripeKey:    stripe,
		RuleJWT:          jwt,
		RuleSecretAssign: "password: *K9q!vR2#mZx7",
		RuleHexKey:       "key: " + hex32,
		RuleURLPassword:  urlPw,
		RuleGitLabToken:  "glpat" + "-" + strings.Repeat("aB1_", 6),
		RuleNPMToken:     "npm" + "_" + strings.Repeat("aB1", 12),
		RuleHFToken:      "hf" + "_" + strings.Repeat("aBcD", 9),
		RuleTailscaleKey: "tskey" + "-auth-" + "kABCDE1CNTRL-abcdefghij",
		RuleSendGridKey:  "SG" + "." + strings.Repeat("aB1_", 6)[:22] + "." + strings.Repeat("cD2-", 11)[:43],
		RuleAzureKey:     "AccountKey=" + strings.Repeat("aB1/", 11) + "==",
		RuleBearer:       "Bearer " + strings.Repeat("aB1.", 6) + "==",
	}
	pre := []string{"", " ", "*", "/", "'", "\"", "[", "<", "(", "{", "`", "，", "密码是：", "注意！", "-", "= ", ": ", "; ", "# ", "> ", "~", "\n", "\t", "– ", "“", "「", "·", "see ", "note: ", "login with "}
	suf := []string{"", " ", "*", "/", "'", "\"", "]", ">", ")", "}", "`", "。", "，请勿外传", "!", ".", ",", ";", "\n", "\t", " (prod)", "”", "」", "·", " and more words"}
	rng := rand.New(rand.NewSource(7))
	d := Default()
	n := 0
	for rule, secret := range corpus {
		for i := 0; i < 120; i++ {
			text := pre[rng.Intn(len(pre))] + pre[rng.Intn(len(pre))] + secret + suf[rng.Intn(len(suf))] + suf[rng.Intn(len(suf))]
			if !has(rules(t, d, text), rule) {
				t.Errorf("%s not caught in %q", rule, text)
			}
			n++
		}
	}
	if n < 2000 {
		t.Fatalf("only %d variants", n)
	}
}

func TestAllowListIsTheOnlyEscapeInFreeText(t *testing.T) {
	for _, v := range []string{"stored in 1Password: password: hunter2hunter2", "host_key: " + hex32, "near fingerprint " + "key: " + hex32, "see vault; token: " + ghp} {
		if fs := Default().ScanRecord("c", "i", map[string]any{"notes": v}); len(fs) == 0 {
			t.Errorf("free text %q has no exemptions", v)
		}
	}
}

func tierOf(t *testing.T, text string) (string, []string) {
	t.Helper()
	fs := Default().ScanRecord("c", "i", map[string]any{"notes": text})
	tier := ""
	for _, f := range fs {
		if f.Tier == TierBlock {
			tier = TierBlock
		} else if tier == "" {
			tier = TierConfirm
		}
	}
	return tier, RuleIDs(fs)
}

func TestMultilingualAssignmentsAreConfirmTier(t *testing.T) {
	for _, v := range []string{
		"root密码：Hunter2Hunter2", "root 密码: Hunter2Hunter2", "password：Hunter2Hunter2", "the root password is Hunter2Hunter2",
		"password＝Hunter2Hunter2", "root密码为Hunter2Hunter2", "root 密码是 Hunter2Hunter2", "密码為 Hunter2Hunter2", "password → Hunter2Hunter2",
		"口令：Hunter2Hunter2", "密钥: Hunter2Hunter2", "令牌=Hunter2Hunter2", "秘钥是Hunter2Hunter2", "凭据：Hunter2Hunter2", "凭证: Hunter2Hunter2",
		"パスワード：Hunter2Hunter2", "비밀번호: Hunter2Hunter2", "pwd: Hunter2Hunter2", "pass = Hunter2Hunter2", "passwd=Hunter2Hunter2",
		"the password for the database was Hunter2Hunter2", "apikey: Hunter2Hunter2", "api key is Hunter2Hunter2", "secret: correcthorse",
		// full-width letters and zero-width characters inside the keyword
		"ｐａｓｓｗｏｒｄ：Hunter2Hunter2", "pass\u200bword: Hunter2Hunter2", "密\u200d码：Hunter2Hunter2", "ｒｏｏｔ　密码：Ｈunter2Hunter2",
	} {
		tier, ids := tierOf(t, v)
		if tier != TierConfirm || !has(ids, RuleSecretAssign) {
			t.Errorf("%q: tier=%q rules=%v", v, tier, ids)
		}
	}
	for _, v := range []string{
		"password policy", "密码策略", "Token Service", "password reset link sent", "the password policy is documented in the wiki",
		"password: 待补", "密码：TBD", "pass the salt please", "bypass: enabled-everywhere", "compass: northeast1234", "密码管理器已启用",
		"token is required for api access", "secret santa is on friday", "密码：<密码>", "password: <redacted>", "password: xxxxxxxx", "password: ********",
		"password: /etc/secrets/db", "password: ${DB_PASSWORD}", "password: env:DB_PASSWORD", "密码是 op://Infra/db/password", "password: secrets/db#password", "password: vault:kv/db#pw",
	} {
		if tier, ids := tierOf(t, v); has(ids, RuleSecretAssign) {
			t.Errorf("%q must not be an assignment: tier=%q %v", v, tier, ids)
		}
	}
	// the remainder of a reference is scanned: not a reference once it holds a token
	for _, v := range []string{"password: op://" + ghp, "password: vault:" + openai, "密码是 op://" + ghp} {
		if tier, _ := tierOf(t, v); tier != TierBlock {
			t.Errorf("%q must be block tier", v)
		}
	}
}

func TestNumbersAndBooleansInSecretNamedFieldsAreScanned(t *testing.T) {
	d := Default()
	for name, v := range map[string]any{"wifi_password": 98765432, "ipmi_password": int64(12345678), "pin_token": float64(12345678), "wifi_密码": uint32(87654321), "secret": json.Number("98765432")} {
		fs := d.ScanRecord("c", "i", map[string]any{name: v})
		if len(fs) != 1 || fs[0].Tier != TierConfirm {
			t.Errorf("%s=%v: %+v", name, v, fs)
		}
	}
	if fs := d.ScanRecord("c", "i", map[string]any{"password": true, "port": 12345678, "token_count": 98765432, "notes": 12345678}); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	// YAML ints decode as int
	fs := d.ScanYAML("rackbook.yml", []byte("ipmi_password: 12345678\nport: 22\n"))
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
	// the scan and Sensitive() agree
	for _, c := range []struct {
		name, v string
		want    bool
	}{{"wifi_password", "98765432", true}, {"port", "98765432", false}, {"ssh_key", hex32, true}, {"label", ghp, true}, {"password", "待补", false}} {
		if got := d.Sensitive(c.name, c.v); got != c.want {
			t.Errorf("Sensitive(%s,%s)=%v", c.name, c.v, got)
		}
	}
}

func TestEveryBlockRuleIsBlockAndConfirmRulesAreConfirm(t *testing.T) {
	blocks := []string{RulePrivateKey, RuleAgeKey, RuleGitHubToken, RuleGitHubPAT, RuleAIKey, RuleSlackToken, RuleAWSKeyID, RuleGoogleKey, RuleStripeKey, RuleJWT,
		RuleURLPassword, RuleGitLabToken, RuleNPMToken, RuleHFToken, RuleTailscaleKey, RuleSendGridKey, RuleAzureKey}
	texts := map[string]string{RulePrivateKey: pemHead + "\nb3Bl", RuleAgeKey: age, RuleGitHubToken: ghp, RuleGitHubPAT: ghPAT, RuleAIKey: openai, RuleSlackToken: slack,
		RuleAWSKeyID: aws, RuleGoogleKey: google, RuleStripeKey: stripe, RuleJWT: jwt, RuleHexKey: "key: " + hex32, RuleURLPassword: urlPw,
		RuleGitLabToken: "glpat" + "-" + strings.Repeat("aB1_", 6), RuleNPMToken: "npm" + "_" + strings.Repeat("aB1", 12), RuleHFToken: "hf" + "_" + strings.Repeat("aBcD", 9),
		RuleTailscaleKey: "tskey" + "-auth-" + "kABCDE1CNTRL-abcdefghij", RuleSendGridKey: "SG" + "." + strings.Repeat("aB1_", 6)[:22] + "." + strings.Repeat("cD2-", 11)[:43],
		RuleAzureKey: "AccountKey=" + strings.Repeat("aB1/", 11) + "=="}
	for _, id := range blocks {
		fs := Default().ScanRecord("c", "i", map[string]any{"a": texts[id]})
		ok := false
		for _, f := range fs {
			if f.Rule == id {
				ok = f.Tier == TierBlock
			}
		}
		if !ok {
			t.Errorf("%s: %+v", id, fs)
		}
	}
	// a long hex string after "key" is ambiguous (nodekey:<hex>, fingerprints,
	// hashes), so it is a heuristic: confirm tier
	if tier, ids := tierOf(t, "api_key: "+strings.Repeat("ab", 32)); tier != TierConfirm || !has(ids, RuleHexKey) {
		t.Errorf("hex-key: %v %v", tier, ids)
	}
	for _, v := range []string{"https://x.example.com/a?api_key=Ab12Cd34Ef56", "https://x.example.com/a?x=1&token=Ab12Cd34Ef56Gh", "https://x/y?key=AbCdEfGh1234"} {
		if tier, ids := tierOf(t, v); tier != TierBlock || !has(ids, RuleURLQuery) {
			t.Errorf("%q: %v", v, ids)
		}
	}
	for _, v := range []string{"https://x.example.com/a?orgId=1&key=short", "https://x/y?page=2&sort=name", "https://x/y?token=abcdefghij"} {
		if _, ids := tierOf(t, v); has(ids, RuleURLQuery) {
			t.Errorf("%q must not fire", v)
		}
	}
	privJWK := `{"kty":"RSA","n":"abc","e":"AQAB","d":"MXx3vN0sG2iPz8WqL1dUfKq"}`
	if tier, ids := tierOf(t, "key: "+privJWK); tier != TierBlock || !has(ids, RulePrivateJWK) {
		t.Errorf("private JWK: %v", ids)
	}
	if tier, ids := tierOf(t, `{"d":"MXx3vN0sG2iPz8WqL1dUfKq","kty":"RSA"}`); tier != TierBlock || !has(ids, RulePrivateJWK) {
		t.Errorf("private JWK, d first: %v", ids)
	}
	for _, v := range []string{
		`{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}`,
		`{"kty":"EC","crv":"P-256","d":"jpsQnnGQmL+YBIffH1136cspYG6/0iY7X1fCE9+E9LI="}`,
		`{\"d\":\"jpsQnnGQmL+YBIffH1136cspYG6/0iY7X1fCE9+E9LI=\",\"kty\":\"EC\"}`,
	} {
		if tier, ids := tierOf(t, v); tier != TierBlock || !has(ids, RulePrivateJWK) {
			t.Errorf("private JWK %q: %v", v, ids)
		}
	}
	if _, ids := tierOf(t, `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}`); has(ids, RulePrivateJWK) {
		t.Error("a public JWK is not private")
	}
}

func TestBase64PEMPrivateKeys(t *testing.T) {
	for _, label := range []string{"OPENSSH", "RSA", "EC", "", "ENCRYPTED", "DSA"} {
		head := "-----BEGIN " + strings.TrimSpace(label+" PRIVATE KEY") + "-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END " + strings.TrimSpace(label+" PRIVATE KEY") + "-----\n"
		enc := base64.StdEncoding.EncodeToString([]byte(head))
		for _, text := range []string{"client-key-data: " + enc, enc, "'" + enc + "'", "x: " + enc[:80]} {
			if tier, ids := tierOf(t, text); tier != TierBlock || !has(ids, RulePrivateB64) {
				t.Errorf("%s in %.40q: %v", label, text, ids)
			}
		}
	}
	for _, v := range []string{"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K", "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg=="} { // public key, certificate
		if _, ids := tierOf(t, v); has(ids, RulePrivateB64) {
			t.Errorf("%s is not a private key", v)
		}
	}
}

func TestDistinctivePrefixesMatchWithoutALeadingBoundary(t *testing.T) {
	for _, c := range []struct{ rule, secret string }{
		{RuleGitHubToken, ghp}, {RuleGitHubPAT, ghPAT}, {RuleGitLabToken, "glpat" + "-" + strings.Repeat("aB1_", 6)}, {RuleSlackToken, slack},
		{RuleAWSKeyID, aws}, {RuleGoogleKey, google}, {RuleHFToken, "hf" + "_" + strings.Repeat("aBcD", 9)}, {RuleNPMToken, "npm" + "_" + strings.Repeat("aB1", 12)},
		{RuleTailscaleKey, "tskey" + "-auth-" + "kABCDE1CNTRL-abcdefghij"}, {RuleAIKey, "sk" + "-ant-" + "api03-Ab12Cd34Ef56Gh78Ij90"}, {RuleAIKey, openai},
		{RuleSendGridKey, "SG" + "." + strings.Repeat("aB1_", 6)[:22] + "." + strings.Repeat("cD2-", 11)[:43]},
	} {
		for _, pre := range []string{"x", "1", "MY_", "token_", "abc"} {
			if got := rules(t, Default(), pre+c.secret); !has(got, c.rule) {
				t.Errorf("%s not caught after %q", c.rule, pre)
			}
		}
	}
	// plausible words still do not look like secrets
	for _, w := range []string{"task-management-system-service-account", "disk-usage-monitoring-dashboard-v", "EURASIA-TRADING", "Euraisan Airlines AKIA", "highlight_reel", "ghost_town", "shf_x", "snpm_x", "risk-assessment-for-all-the-hosts", "tasks-ant-colony", "ESG.report.2024"} {
		if got := rules(t, Default(), w); len(got) != 0 {
			t.Errorf("%q fired %v", w, got)
		}
	}
}

func TestHighEntropyTokensAreConfirmTier(t *testing.T) {
	for _, v := range []string{"login with q7Zx!pL2vN9mTk4Rb8Wc3Yd", "A8f$k2Lq9ZxPw3Vn7TbM5cRd", "key is vT4#nK8qLp2ZxW7mR9bY5cDa", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"} {
		if tier, ids := tierOf(t, v); tier != TierConfirm || !has(ids, RuleEntropy) {
			t.Errorf("%q: %q %v", v, tier, ids)
		}
	}
	for _, v := range []string{"the quick brown fox jumps over the lazy dog every single day", "https://grafana.example.com/d/AbCdEf12GhIjKl34/overview?orgId=1", "0123456789abcdef0123456789abcdef", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1A", "Nginx-Reverse-Proxy-Cluster-2", "/var/lib/docker/overlay2/volumes", "ssh://git@github.com/org/repo.git",
		// paths, host:path, file#key and key=value made of short words
		"/opt/registry-mirror/README.md", "production:/www/server/panel/vhost/cert/kirara-agent.us-sj1.web.example.com/",
		"secrets/4c6g-racknerd-sanjose-ca-us-vps.sops.yaml#cloudflare_dns_token", "Mac:~/.config/sops/age/keys.txt",
		"HostName=dynamic.pqs.cwh.tw.vps.example.org", "4c6g:/etc/ssh/ssh_host_ed25519_key"} {
		if _, ids := tierOf(t, v); has(ids, RuleEntropy) {
			t.Errorf("%q must not fire", v)
		}
	}
	// a block-tier token is not also reported as entropy
	if _, ids := tierOf(t, slack); has(ids, RuleEntropy) {
		t.Errorf("%v", ids)
	}
}

func TestAnnotationNeverOverridesASecretNamedFieldExceptSecretReference(t *testing.T) {
	schema := []byte(`{"properties":{"private_key":{"x-rackbook":{"public":"hex_id"}},"api_token":{"x-rackbook":{"public":"fingerprint"}},"db_password":{"x-rackbook":{"public":"secret_reference"}},"host_id":{"x-rackbook":{"public":"hex_id"}}}}`)
	ann := AnnotationsOf(schema)
	rec := map[string]any{"private_key": hex32, "api_token": strings.Repeat("ab", 32), "db_password": "op://Infra/db/password", "host_id": hex32}
	got := map[string]bool{}
	for _, f := range Default().ScanRecordWith("c", "i", rec, ann) {
		got[strings.TrimPrefix(f.Path, "/")] = true
	}
	if !got["private_key"] || !got["api_token"] || got["db_password"] || got["host_id"] {
		t.Fatalf("%v", got)
	}
	probs := AnnotationProblems(schema)
	if len(probs) != 2 || !strings.Contains(probs[0], "api_token") || !strings.Contains(probs[1], "private_key") {
		t.Fatalf("%v", probs)
	}
	if p := AnnotationProblems([]byte(`{"properties":{"x":{"x-rackbook":{"public":"nonsense"}}}}`)); len(p) != 1 {
		t.Fatalf("%v", p)
	}
}

func TestSecretReferenceRemainderIsScannedAndValueLikePathsAreNotPaths(t *testing.T) {
	ann := AnnotationsOf([]byte(`{"properties":{"password":{"x-rackbook":{"public":"secret_reference"}}}}`))
	for v, ok := range map[string]bool{"op://Infra/db/password": true, "/run/secrets/db": true, "vault:kv/db#pw": true,
		"op://" + ghp: false, "/" + ghp: false, "vault:" + openai: false, "/hunter2hunter2": false, "~/Hunter2Hunter2": false, "/etc/secrets/db_pw": true} {
		got := len(Default().ScanRecordWith("c", "i", map[string]any{"password": v}, ann)) == 0
		if got != ok {
			t.Errorf("%q: pass=%v want %v", v, got, ok)
		}
	}
}

func TestJWKPublicScansItsOtherMembers(t *testing.T) {
	ann := AnnotationsOf([]byte(`{"properties":{"jwk":{"x-rackbook":{"public":"jwk_public"}}}}`))
	pub := `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k1","use":"sig","alg":"ES256","key_ops":["verify"],"x5t":"abc"}`
	if fs := Default().ScanRecordWith("c", "i", map[string]any{"jwk": pub}, ann); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	withSecret := strings.Replace(pub, `"kid":"k1"`, `"note":"password: Hunter2Hunter2","kid":"k1"`, 1)
	if fs := Default().ScanRecordWith("c", "i", map[string]any{"jwk": withSecret}, ann); len(fs) == 0 {
		t.Fatal("a secret in a non-public member must be scanned")
	}
}

func TestRedactIDIsShortStableAndDistinct(t *testing.T) {
	a, b := RedactID("alice/hunter2hunter2"), RedactID("alice/hunter3hunter3")
	if a == b || !strings.HasPrefix(a, "alic…~") || len(strings.SplitN(a, "~", 2)[1]) != 8 || a != RedactID("alice/hunter2hunter2") {
		t.Fatal(a, b)
	}
}

func TestRoundFiveFixes(t *testing.T) {
	d := Default()
	// hex after a quote
	for _, v := range []string{`key: "` + hex32 + `"`, `ssh_key = '` + hex32 + `'`, `privkey="` + hex32 + `"`} {
		if got := rules(t, d, v); !has(got, RuleHexKey) {
			t.Errorf("%q: %v", v, got)
		}
	}
	// leading boundaries: sk-, live keys and JWTs inside a longer word
	for _, c := range []struct{ rule, text string }{
		{RuleAIKey, "xsk" + "-" + "Ab12Cd34Ef56Gh78Ij90Kl12"}, {RuleAIKey, "1sk" + "-ant-" + "api03-Ab12Cd34Ef56Gh78Ij90"},
		{RuleStripeKey, "my" + stripe}, {RuleStripeKey, "x" + "rk_live_" + strings.Repeat("a1B2c3", 4)}, {RuleJWT, "tok" + jwt}, {RuleJWT, "1" + jwt},
	} {
		if got := rules(t, d, c.text); !has(got, c.rule) {
			t.Errorf("%s not caught in %q: %v", c.rule, c.text, got)
		}
	}
	for _, w := range []string{"task-management-system-service-account", "disk-usage-monitoring-dashboard-v", "risk-assessment-for-all-the-hosts"} {
		if got := rules(t, d, w); has(got, RuleAIKey) {
			t.Errorf("%q fired", w)
		}
	}
	// a private JWK stored as an object is block tier wherever it is
	jwk := map[string]any{"kty": "RSA", "n": "abc", "e": "AQAB", "d": "MXx3vN0sG2iPz8WqL1dUfKq"}
	for _, rec := range []map[string]any{{"k": jwk}, {"list": []any{map[string]any{"deep": jwk}}}, {"kty": "EC", "d": "MXx3vN0sG2iPz8WqL1dUfKq"}} {
		var jwkHits int
		for _, f := range d.ScanRecord("c", "i", rec) {
			if f.Rule == RulePrivateJWK {
				jwkHits++
				if f.Tier != TierBlock || len(strings.TrimSuffix(f.Excerpt, "…")) > 4 {
					t.Errorf("%v: %+v", rec, f)
				}
			}
		}
		if jwkHits != 1 {
			t.Errorf("%v: %d private-jwk findings", rec, jwkHits)
		}
	}
	for _, f := range d.ScanRecord("c", "i", map[string]any{"k": map[string]any{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}}) {
		if f.Tier == TierBlock { // a public JWK is at most a heuristic hit (annotate it jwk_public)
			t.Errorf("a public JWK object is not block tier: %+v", f)
		}
	}
	// more invisible characters inside the keyword
	for _, v := range []string{"pass\u200eword: Hunter2Hunter2", "pass\u200fword: Hunter2Hunter2", "pass\u00adword: Hunter2Hunter2", "pass\u2061\u2062\u2063\u2064word: Hunter2Hunter2"} {
		if got := rules(t, d, v); !has(got, RuleSecretAssign) {
			t.Errorf("%q: %v", v, got)
		}
	}
	// more keywords and particles
	for _, v := range []string{"密碼：Hunter2Hunter2", "암호: Hunter2Hunter2", "패스워드: Hunter2Hunter2", "パスワードは Hunter2Hunter2", "パスワードはHunter2Hunter2", "비밀번호는 Hunter2Hunter2", "암호는 Hunter2Hunter2", "비밀번호은 Hunter2Hunter2"} {
		if tier, ids := tierOf(t, v); tier != TierConfirm || !has(ids, RuleSecretAssign) {
			t.Errorf("%q: %q %v", v, tier, ids)
		}
	}
	// camelCase names
	for _, n := range []string{"adminPwd", "dbPass", "wifiPsk", "dbPassword", "apiKey", "密碼", "암호"} {
		if fs := d.ScanRecord("c", "i", map[string]any{n: "correct horse"}); len(fs) == 0 {
			t.Errorf("%s must be a secret name", n)
		}
	}
	for _, n := range []string{"compass", "bypass", "Compass", "passenger", "password_policy"} {
		if fs := d.ScanRecord("c", "i", map[string]any{n: "correct horse"}); len(fs) != 0 {
			t.Errorf("%s must not be a secret name", n)
		}
	}
}

// The rule: block-tier formats are refused in every string, always; schema
// annotations, placeholders and confirm_not_secret only silence the confirm tier.
func TestAnnotationsNeverSilenceTheBlockTier(t *testing.T) {
	ann := AnnotationsOf([]byte(`{"properties":{"ref":{"x-rackbook":{"public":"secret_reference"}},"jwk":{"x-rackbook":{"public":"jwk_public"}},
	 "ssh":{"x-rackbook":{"public":"ssh_public_key"}},"pem":{"x-rackbook":{"public":"pem_public_key"}}}}`))
	b64 := base64.StdEncoding.EncodeToString
	privPEM := "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	cases := []struct{ field, value, rule string }{
		{"ref", "op://" + strings.Repeat("a", 130) + ghp, RuleGitHubToken},
		{"jwk", `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"` + ghp + `"}`, RuleGitHubToken},
		{"jwk", `{"kty":"EC","x5c":[{"kty":"EC","d":"jpsQnnGQmLYBIffH1136cspYG60iY7X1fCE9E9LI"}]}`, RulePrivateJWK},
		{"ssh", "ssh-ed25519 AAAA" + b64([]byte(privPEM)), RulePrivateB64},
		{"ssh", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5+AKIAIOSFODNN7EXAMPLE+abc", RuleAWSKeyID},
		{"pem", "-----BEGIN PUBLIC KEY-----\n" + b64([]byte(privPEM)) + "\n-----END PUBLIC KEY-----", RulePrivateB64},
	}
	for _, c := range cases {
		fs := Default().ScanRecordWith("c", "i", map[string]any{c.field: c.value}, ann)
		found := false
		for _, f := range fs {
			found = found || f.Rule == c.rule && f.Tier == TierBlock
		}
		if !found {
			t.Errorf("%s %.40q: want a block %s finding, got %+v", c.field, c.value, c.rule, fs)
		}
	}
	// the same in a schema default and in an enum
	for _, c := range cases[:1] {
		schema := `{"properties":{"ref":{"x-rackbook":{"public":"secret_reference"},"default":"` + c.value + `","enum":["` + c.value + `"]}}}`
		if fs := Default().ScanSchema("c", []byte(schema)); len(fs) < 2 {
			t.Errorf("schema default and enum: %+v", fs)
		}
	}
}

func TestGenuinelyPublicAnnotatedValuesStayClean(t *testing.T) {
	ann := AnnotationsOf([]byte(`{"properties":{"node":{"x-rackbook":{"public":"nodekey"}},"fp":{"x-rackbook":{"public":"fingerprint"}},
	 "ssh":{"x-rackbook":{"public":"ssh_public_key"}},"age":{"x-rackbook":{"public":"age_recipient"}},"hid":{"x-rackbook":{"public":"hex_id"}}}}`))
	hex64 := strings.Repeat("ab", 32)
	rec := map[string]any{"node": "nodekey:" + hex64, "fp": hex64, "ssh": sshPubKey, "age": "age1" + strings.Repeat("q", 58), "hid": hex32}
	if fs := Default().ScanRecordWith("c", "i", rec, ann); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	// without the annotation the hex after "key" is a confirm-tier finding, not a block
	fs := Default().ScanRecord("c", "i", map[string]any{"node": "nodekey:" + hex64})
	if len(fs) != 1 || fs[0].Rule != RuleHexKey || fs[0].Tier != TierConfirm {
		t.Fatalf("%+v", fs)
	}
}

func TestPrivateJWKHeldAsJSONText(t *testing.T) {
	ann := AnnotationsOf([]byte(`{"properties":{"jwk":{"x-rackbook":{"public":"jwk_public"}}}}`))
	for name, v := range map[string]string{
		"escaped member names": `{"\u006b\u0074\u0079":"EC","crv":"P-256","\u0064":"jpsQnnGQmLYBIffH1136cspYG60iY7X1fCE9E9LI"}`,
		"nested oth":           `{"kty":"RSA","n":"abc","e":"AQAB","oth":[{"kty":"RSA","d":"jpsQnnGQmLYBIffH1136cspYG60iY7X1fCE9E9LI"}]}`,
		"escaped slash in d":   `{"kty":"EC","crv":"P-256","d":"jpsQnnGQmL+YBIffH1136cspYG6\/0iY7X1fCE9+E9LI="}`,
	} {
		for field, a := range map[string]Annotations{"notes": nil, "jwk": ann} {
			fs := Default().ScanRecordWith("c", "i", map[string]any{field: v}, a)
			found := false
			for _, f := range fs {
				found = found || f.Rule == RulePrivateJWK && f.Tier == TierBlock
			}
			if !found {
				t.Errorf("%s in %s: %+v", name, field, fs)
			}
		}
	}
}

func TestSchemaNamesAndOtherStringsGetTheBlockTier(t *testing.T) {
	for _, schema := range []string{
		`{"properties":{"` + ghp + `":{"type":"string"}}}`,
		`{"$comment":"` + ghp + `"}`,
		`{"properties":{"a":{"type":"string","pattern":"` + ghp + `"}}}`,
	} {
		fs := Default().ScanSchema("c", []byte(schema))
		if len(fs) == 0 || fs[0].Rule != RuleGitHubToken || fs[0].Tier != TierBlock {
			t.Errorf("%s: %+v", schema, fs)
		}
	}
}

func TestJWKPublicKeyNumbersDoNotTripTokenPatterns(t *testing.T) {
	ann := AnnotationsOf([]byte(`{"properties":{"jwk":{"x-rackbook":{"public":"jwk_public"}}}}`))
	scan := func(jwk string, a Annotations) []Finding {
		return Default().ScanRecordWith("c", "i", map[string]any{"jwk": jwk}, a)
	}
	pad := strings.Repeat("q7Zx_", 40)
	// a modulus that happens to contain "sk-" and 25 more base64url characters
	n := pad + "sk-" + "Ab12Cd34Ef56Gh78Ij90Kl12M" + pad
	for _, mod := range []string{n, strings.Repeat("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W", 3),
		strings.Repeat("sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboKx", 3)} {
		jwk := `{"kty":"RSA","n":"` + mod + `","e":"AQAB","kid":"k1"}`
		if fs := scan(jwk, ann); len(fs) != 0 {
			t.Errorf("a genuine public JWK must stay clean: %+v", fs)
		}
	}
	blocked := map[string]string{
		"token in kid":            `{"kty":"RSA","n":"abc","e":"AQAB","kid":"` + ghp + `"}`,
		"token in unknown member": `{"kty":"RSA","n":"abc","e":"AQAB","note":"` + ghp + `"}`,
		"token in n with a space": `{"kty":"RSA","n":"abc ` + ghp + `","e":"AQAB"}`,
		"token in nested object":  `{"kty":"RSA","n":"abc","e":"AQAB","meta":{"k":"` + ghp + `"}}`,
		"token in duplicate kid":  `{"kty":"RSA","kid":"` + ghp + `","n":"abc","e":"AQAB","kid":"k1"}`,
	}
	for name, jwk := range blocked {
		found := false
		for _, f := range scan(jwk, ann) {
			found = found || f.Rule == RuleGitHubToken && f.Tier == TierBlock
		}
		if !found {
			t.Errorf("%s must be blocked", name)
		}
	}
}

func TestSchemaTranslationsAndEnumFormsAreScanned(t *testing.T) {
	schema := `{"type":"object","x-rackbook-i18n":{"en-US":{"title":"Ledger ` + ghp + `"}},"properties":{
	  "a":{"type":"string","title":"A","x-rackbook-i18n":{"en-US":{"title":"token: abcdefgh12345","description":"` + aws + `","enum":{"x":"` + slack + `"}}},
	       "oneOf":[{"const":"x","title":"fine"},{"const":"` + openai + `","title":"` + google + `"}],
	       "x-rackbook-enum-icons":{"x":"` + stripe + `"}}}}`
	var got []string
	for _, f := range Default().ScanSchema("c", []byte(schema)) {
		got = append(got, f.Path+" "+f.Rule)
	}
	sort.Strings(got)
	want := []string{
		"/schema/properties/a/oneOf/1/const openai-api-key",
		"/schema/properties/a/oneOf/1/title google-api-key",
		"/schema/properties/a/x-rackbook-enum-icons/x stripe-live-key",
		"/schema/properties/a/x-rackbook-i18n/en-US/description aws-access-key-id",
		"/schema/properties/a/x-rackbook-i18n/en-US/enum/x slack-token",
		"/schema/properties/a/x-rackbook-i18n/en-US/title secret-assignment",
		"/schema/x-rackbook-i18n/en-US/title github-token",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Locale tags are keys of x-rackbook-i18n, not data. The enum labels are walked
// as data, as an enum always was: a confirm-tier secret under a made-up code key
// is reported, and so is a secret used as a code.
func TestSchemaTranslationKeys(t *testing.T) {
	// plain codes and labels, and locale tags that look odd: nothing
	ok := `{"properties":{"a":{"oneOf":[{"const":"static","title":"静态"}],
	  "x-rackbook-i18n":{"password":{"title":"Kind"},"api_key":{"enum":{"static":"Static"}},"en-US":{"title":"Kind","enum":{"static":"Static","title":"Title","default":"D"}}},
	  "x-rackbook-enum-icons":{"static":"key"}}}}`
	if fs := Default().ScanSchema("c", []byte(ok)); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	// ordinary labels under real codes named like secrets: nothing, in any language
	labelsOK := `{"properties":{"k":{"type":"string",
	  "oneOf":[{"const":"password","title":"密码登录"},{"const":"api_key"},{"const":"token"},{"const":"secret"}],
	  "x-rackbook-i18n":{"en-US":{"enum":{"password":"Password login","api_key":"API key","token":"Access token (rotated monthly)","secret":"Client secret"}},
	                     "zh-TW":{"enum":{"password":"密碼登入","secret":"用戶端密鑰"}}}},
	  "legacy":{"type":"string","enum":["password","token"],"x-rackbook-i18n":{"en-US":{"enum":{"password":"Password login","token":"Access token"}}}}}}`
	if fs := Default().ScanSchema("c", []byte(labelsOK)); len(fs) != 0 {
		t.Fatalf("labels of real codes must not be reported: %+v", fs)
	}
	// a label of a real code is still scanned as text
	fs0 := Default().ScanSchema("c", []byte(`{"properties":{"k":{"type":"string","enum":["a"],"x-rackbook-i18n":{"en-US":{"enum":{"a":"`+ghp+`"}}}}}}`))
	if len(fs0) != 1 || fs0[0].Rule != RuleGitHubToken {
		t.Fatalf("%+v", fs0)
	}
	// a secret under a fake code key is found, as before translations existed
	bad := `{"properties":{"a":{"type":"string","x-rackbook-i18n":{"en-US":{"enum":{"password":"hunter2hunter2"}}}}}}`
	fs := Default().ScanSchema("c", []byte(bad))
	if len(fs) != 1 || fs[0].Path != "/schema/properties/a/x-rackbook-i18n/en-US/enum/password" {
		t.Fatalf("%+v", fs)
	}
	// a secret used as a code
	fs = Default().ScanSchema("c", []byte(`{"x-rackbook-i18n":{"en-US":{"enum":{"`+ghp+`":"label"}}}}`))
	if len(fs) == 0 {
		t.Fatal("a secret as a code must be reported")
	}
	// title and description under a language are plain text
	if fs := Default().ScanSchema("c", []byte(`{"x-rackbook-i18n":{"en-US":{"description":"password: hunter2hunter2"}}}`)); len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
}

func TestRackbookYmlTranslationsAreScanned(t *testing.T) {
	src := "title: t\ni18n:\n  en-US: {title: \"Ledger " + ghp + "\"}\ncollections:\n  a:\n    title: x\n    i18n:\n      en-US: {title: " + aws + "}\nnotes:\n  - title: n\n    i18n: {zh-TW: {title: \"" + openai + "\"}}\n"
	var got []string
	for _, f := range Default().ScanYAML("rackbook.yml", []byte(src)) {
		got = append(got, f.Path)
	}
	sort.Strings(got)
	want := "/collections/a/i18n/en-US/title,/i18n/en-US/title,/notes/0/i18n/zh-TW/title"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v", got)
	}
	clean := "i18n:\n  en-US: {title: Ledger}\n  zh-TW: {title: 台帳}\n"
	if fs := Default().ScanYAML("rackbook.yml", []byte(clean)); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
}
