package secretscan

import (
	"encoding/json"
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
			[]string{"ghp_short", "ghx_" + strings.Repeat("a", 40), "highp_" + strings.Repeat("a", 40)}},
		{RuleGitHubPAT,
			[]string{ghPAT},
			[]string{"github_pat_short", "my_github_pat_" + strings.Repeat("a", 30)}},
		{RuleAIKey,
			[]string{openai, "sk" + "-ant-" + "api03-Ab12Cd34Ef56Gh78Ij90", "use sk" + "-" + "Ab12Cd34Ef56Gh78Ij90Kl12 here"},
			[]string{"task-management-system-service-account", "disk-usage-monitoring-dashboard-v", "sk-short", "sk-prod-database-primary-host-name", "risk-assessment-for-all-the-hosts"}},
		{RuleSlackToken,
			[]string{slack, "xox" + "p-" + "1234567890-abcdefghij"},
			[]string{"xoxb-short", "xoxz-1234567890-abcdefghij", "boxb-1234567890-abcdefghij"}},
		{RuleAWSKeyID,
			[]string{aws, "ASIA" + "IOSFODNN7EXAMPLE", "id=" + aws + " ok"},
			[]string{"AKIA" + "IOSFODNN7EXAMPL", "AKIA" + "IOSFODNN7EXAMPLE9", "XAKIA" + "IOSFODNN7EXAMPLE", "akia" + "iosfodnn7example"}},
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
			[]string{"password: hunter2hunter2", "{\"password\": \"Hunter2Hunter2x\"}", "password: $uperS3cretPass", "db password = correcthorse", "API_KEY=abcdefgh12345", "api-key: abcdefgh12345", "client_secret: abcdefgh", "my token: abcdefgh", "privkey=abcdefgh", "passwd:abcdefgh", "notes: root password: changeme123!"},
			[]string{"password: short", "token: 1234567", "the password is stored in the vault", "passwords: rotated-quarterly", "token_count: 12345678", "password: ********", "password: ${DB_PASSWORD}", "password: op://Infra/db/password", "token: env:GITHUB_TOKEN", "password: vault:kv/db#pw", "secret: /run/secrets/db_password", "token: $GITHUB_TOKEN", "password: %DB_PASSWORD%", "api_key: https://vault.example.com/ui/kv", "password: <redacted>", "secret: {{ vault }}", "password: xxxxxxxxxx", "token_ttl: 3600 seconds"}},
		{RuleHexKey,
			[]string{"key: " + hex32, "preshared key: " + hex32, "privkey=" + hex32, "ssh host key = " + hex32 + strings.Repeat("ab", 8), "KEY:" + strings.ToUpper(hex32)},
			[]string{"key: " + hex32[:31], "fingerprint: " + hex32 + hex32, "sha256: " + hex32 + hex32, "key: " + hex32 + "zz", "public key: " + hex32, "key_fingerprint: " + hex32, "host_pub_key: " + hex32}},
		{RuleURLPassword,
			[]string{urlPw, "see https://bob:pw@example.com/x", "ssh://git:token@host"},
			[]string{"https://example.com/path", "https://host:8080/path", "ssh://git@github.com/org/repo.git", "git@github.com:org/repo.git", "https://example.com:8080", "https://user:${PASSWORD}@host/", "https://user:<password>@host/", "mailto:admin@example.com"}},
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
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@host",
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
		if strings.Contains(f.ID, "a1B2a1B2") || f.ID != Excerpt(ghp) {
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
	if strings.Join(paths, ",") != "/password,/ssh_key" {
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
	if n := count(mk(Allow{Rule: RuleSecretAssign, ValueSHA256: Hash(val)}), "c"); n != 1 {
		t.Fatalf("by hash: %d", n)
	}
	if n := count(mk(Allow{Rule: RuleSecretAssign, ValueSHA256: strings.ToUpper(Hash("another value"))}), "c"); n != 2 {
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
	s := mk(Allow{Rule: RuleURLPassword, ValueSHA256: Hash("admin:hunter2pass")})
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
		"non hex hash":    {Allow: []Allow{{Rule: RuleJWT, ValueSHA256: strings.Repeat("z", 64)}}},
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
	want := "/schema/properties/a/default github-token,/schema/properties/b/examples/1 aws-access-key-id,/schema/properties/c/enum/1 slack-token,/schema/properties/d/const openai-api-key"
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
