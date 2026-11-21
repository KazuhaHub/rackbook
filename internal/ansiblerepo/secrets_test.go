package ansiblerepo

import (
	"strings"
	"testing"
)

const encVal = "ENC[AES256_GCM,data:abc=,iv:def=,tag:ghi==,type:str]"

func sopsFile(body string, recipients ...string) string {
	s := body + "sops:\n    age:\n"
	for _, r := range recipients {
		s += "        - enc: |\n            -----BEGIN AGE ENCRYPTED FILE-----\n            xyz\n            -----END AGE ENCRYPTED FILE-----\n          recipient: " + r + "\n"
	}
	return s + "    lastmodified: \"2026-11-21T00:00:00Z\"\n    mac: " + encVal + "\n    version: 3.13.3\n"
}

func joinCodes(is []Issue) string {
	var c []string
	for _, i := range is {
		c = append(c, i.Code)
	}
	return strings.Join(c, ",")
}

func TestSecretsFileIssues(t *testing.T) {
	conf := "creation_rules:\n  - path_regex: ^secrets/a\\.sops\\.yaml$\n    age: \"age1b, age1a\"\n  - path_regex: ^secrets/g\\.sops\\.yaml$\n    key_groups:\n      - age: [age1a, age1b]\n"
	tree := memTree{".sops.yaml": conf}
	for name, c := range map[string]struct {
		file, body string
		want       string
	}{
		"fine":                 {"secrets/a.sops.yaml", sopsFile("k: "+encVal+"\n", "age1a", "age1b"), ""},
		"nested values":        {"secrets/a.sops.yaml", sopsFile("k:\n  - "+encVal+"\n  - n: "+encVal+"\n", "age1b", "age1a"), ""},
		"key groups rule":      {"secrets/g.sops.yaml", sopsFile("k: "+encVal+"\n", "age1a", "age1b"), ""},
		"plaintext value":      {"secrets/a.sops.yaml", sopsFile("k: hunter2\n", "age1a", "age1b"), "secrets.not_encrypted"},
		"plaintext number":     {"secrets/a.sops.yaml", sopsFile("k: 5\n", "age1a", "age1b"), "secrets.not_encrypted"},
		"null":                 {"secrets/a.sops.yaml", sopsFile("k:\n", "age1a", "age1b"), "secrets.not_encrypted"},
		"unencrypted suffix":   {"secrets/a.sops.yaml", sopsFile("k_unencrypted: "+encVal+"\n", "age1a", "age1b"), "secrets.not_encrypted"},
		"plain in a list":      {"secrets/a.sops.yaml", sopsFile("k:\n  - "+encVal+"\n  - plain\n", "age1a", "age1b"), "secrets.not_encrypted"},
		"missing recipient":    {"secrets/a.sops.yaml", sopsFile("k: "+encVal+"\n", "age1a"), "secrets.recipients"},
		"extra recipient":      {"secrets/a.sops.yaml", sopsFile("k: "+encVal+"\n", "age1a", "age1b", "age1c"), "secrets.recipients"},
		"no rule":              {"secrets/z.sops.yaml", sopsFile("k: "+encVal+"\n", "age1a"), "secrets.no_rule"},
		"no metadata":          {"secrets/a.sops.yaml", "k: " + encVal + "\n", "secrets.no_metadata"},
		"metadata without mac": {"secrets/a.sops.yaml", "k: " + encVal + "\nsops:\n  age: []\n", "secrets.no_metadata"},
		"not a mapping":        {"secrets/a.sops.yaml", "- a\n- b\n", "secrets.invalid"},
		"a pgp recipient too":  {"secrets/a.sops.yaml", sopsFile("k: "+encVal+"\n", "age1a", "age1b") + "    pgp:\n        - fp: ABCD\n", "secrets.recipients"},
	} {
		if got := joinCodes(secretsFileIssues(tree, c.file, []byte(c.body))); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if got := joinCodes(secretsFileIssues(memTree{}, "secrets/a.sops.yaml", []byte(sopsFile("k: "+encVal+"\n", "age1a")))); got != "secrets.no_rule" {
		t.Errorf("no .sops.yaml: %q", got)
	}
}

func TestSecretKeyAndValueRules(t *testing.T) {
	for k, ok := range map[string]bool{
		"cloudflare_dns_token": true, "feature_beszel-agent_token": true, "a": true, "9": true,
		"": false, "Upper": false, "has space": false, "dot.ted": false, "sops": false, "a_unencrypted": false,
		"x/y": false, "../x": false, strings.Repeat("a", 129): false, "new\nline": false,
	} {
		if ValidSecretKey(k) != ok {
			t.Errorf("ValidSecretKey(%q) = %v", k, !ok)
		}
	}
	for v, why := range map[string]string{"x": "", "multi\nline": "", "": "empty", strings.Repeat("x", MaxSecretValue+1): "too_large", "a\x00b": "not_text", "\xff": "not_text"} {
		if got := ValidSecretValue(v); got != why {
			t.Errorf("ValidSecretValue(%.10q) = %q, want %q", v, got, why)
		}
	}
	if !isSecretsPath("secrets/alpha.sops.yaml") || isSecretsPath("secrets/../x.sops.yaml") || isSecretsPath("secrets/a/b.sops.yaml") || isSecretsPath("inventory/host_vars/a.yml") || isSecretsPath("secrets/a.yaml") || isSecretsPath(".sops.yaml") {
		t.Error("isSecretsPath")
	}
}

func TestSecretsDiffShowsNamesOnly(t *testing.T) {
	before := sopsFile("a: "+encVal+"\nb: "+encVal+"\n", "age1a")
	after := sopsFile("a: "+encVal+"\nc: "+encVal+"\n", "age1a")
	d := secretsDiff("secrets/x.sops.yaml", []byte(before), []byte(after)).Diff
	if !strings.Contains(d, "\n a\n") || !strings.Contains(d, "\n-b\n") || !strings.Contains(d, "\n+c\n") || strings.Contains(d, "ENC[") {
		t.Fatalf("%s", d)
	}
}
