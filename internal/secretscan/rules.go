package secretscan

import (
	"regexp"
	"strings"
)

// rule is one compiled pattern. group is the submatch that holds the secret
// itself (0 = the whole match); it is what an excerpt shows and what
// allow[].value_sha256 hashes. accept, when set, drops a match that is
// recognisably not a secret (a placeholder, a public key).
type rule struct {
	id          string
	description string
	re          *regexp.Regexp
	group       int
	accept      func(value, before string) bool
}

// The built-in rule IDs. They are stable: allow lists and disable_rules in
// rackbook.yml refer to them.
const (
	RulePrivateKey   = "private-key"
	RuleAgeKey       = "age-secret-key"
	RuleGitHubToken  = "github-token"
	RuleGitHubPAT    = "github-pat"
	RuleAIKey        = "openai-api-key"
	RuleSlackToken   = "slack-token"
	RuleAWSKeyID     = "aws-access-key-id"
	RuleGoogleKey    = "google-api-key"
	RuleStripeKey    = "stripe-live-key"
	RuleJWT          = "jwt"
	RuleSecretAssign = "secret-assignment"
	RuleHexKey       = "hex-key"
	RuleURLPassword  = "url-credentials"
	RuleGitLabToken  = "gitlab-token"
	RuleNPMToken     = "npm-token"
	RuleHFToken      = "huggingface-token"
	RuleTailscaleKey = "tailscale-key"
	RuleSendGridKey  = "sendgrid-key"
	RuleAzureKey     = "azure-account-key"
	RuleBearer       = "bearer-token"
)

// keywordAssign is the "password: hunter2hunter2" shape. It is also applied to
// a field name and its string value, so a field called password is caught.
const keywordAssign = `(?i)(?:(?:^|[^a-z])psk|private[_ -]?key|privkey|secret|password|passwd|passphrase|wpa_passphrase|pre[_-]?shared[_-]?key|token|api[_-]?key)["']?\s*[:=]\s*["']?(\S{8,})`

const hexAssign = `(?i)(?:key|privkey)\s*[:=]\s*([0-9a-f]{32,})\b`

func builtin() []*rule {
	return []*rule{
		{id: RulePrivateKey, description: "PEM private key block", re: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)`)},
		{id: RuleAgeKey, description: "age secret key", re: regexp.MustCompile(`\bAGE-SECRET-KEY-1[0-9A-Z]{58}`)},
		{id: RuleGitHubToken, description: "GitHub token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`)},
		{id: RuleGitHubPAT, description: "GitHub fine-grained token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}`)},
		{id: RuleAIKey, description: "OpenAI or Anthropic style API key", re: regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`), accept: mixedCase},
		{id: RuleSlackToken, description: "Slack token", re: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
		{id: RuleAWSKeyID, description: "AWS access key ID", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{id: RuleGoogleKey, description: "Google API key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
		{id: RuleStripeKey, description: "Stripe live secret key", re: regexp.MustCompile(`\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}`)},
		{id: RuleJWT, description: "JSON Web Token", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
		{id: RuleSecretAssign, description: "secret, password or token assigned in text", re: regexp.MustCompile(keywordAssign), group: 1, accept: notPlaceholder},
		{id: RuleHexKey, description: "long hex string assigned to a key", re: regexp.MustCompile(hexAssign), group: 1, accept: notPublic},
		{id: RuleGitLabToken, description: "GitLab personal access token", re: regexp.MustCompile(`\bglpat-[0-9A-Za-z_-]{20,}`)},
		{id: RuleNPMToken, description: "npm access token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}`)},
		{id: RuleHFToken, description: "Hugging Face token", re: regexp.MustCompile(`\bhf_[A-Za-z]{34,}`)},
		{id: RuleTailscaleKey, description: "Tailscale auth key", re: regexp.MustCompile(`\btskey-[a-z]+-[A-Za-z0-9-]{10,}`)},
		{id: RuleSendGridKey, description: "SendGrid API key", re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)},
		{id: RuleAzureKey, description: "Azure storage account key", re: regexp.MustCompile(`AccountKey=([A-Za-z0-9+/=]{40,})`), group: 1},
		{id: RuleBearer, description: "bearer token", re: regexp.MustCompile(`\bBearer ([A-Za-z0-9._~+/-]{20,}=*)`), group: 1, accept: mixedCase},
		{id: RuleURLPassword, description: "URL with a user name and password", re: regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^/\s:@]+:[^/\s@]+)@`), group: 1, accept: urlPassword},
	}
}

// builtinIDs is the set of built-in rule IDs.
func builtinIDs() map[string]bool {
	m := map[string]bool{}
	for _, r := range builtin() {
		m[r.id] = true
	}
	return m
}

// mixedCase keeps "sk-prod-database-primary-host" (a hostname) from looking
// like a key: real keys carry a digit or an upper-case letter.
func mixedCase(value, _ string) bool {
	return strings.ContainsAny(value, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// notPlaceholder drops values that are not a secret: masks, template
// variables, angle-bracket placeholders and references to where the secret
// lives (a URI such as op://vault/item, env:NAME, a file path), which is what
// the ledger should hold instead.
func notPlaceholder(value, _ string) bool {
	v := strings.Trim(value, `"',;`)
	if v == "" {
		return false
	}
	switch {
	case strings.HasPrefix(v, "${"), strings.HasPrefix(v, "$("), strings.HasPrefix(v, "{{"), strings.HasPrefix(v, "<"),
		strings.HasPrefix(v, "["), strings.HasPrefix(v, "*"), strings.HasPrefix(v, "/"), strings.HasPrefix(v, "~/"):
		return false
	}
	if strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%") {
		return false
	}
	if uriRef.MatchString(v) || envRef.MatchString(v) {
		return false
	}
	if strings.Trim(v, "*xX.#-_•") == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "tbd", "todo", "n/a", "na", "none", "null", "unknown", "empty", "redacted", "changeme-later", "待补", "待定", "无", "暂无", "未设置":
		return false
	}
	// Public values: SSH and age public keys, nostr public keys.
	for _, p := range []string{"ssh-", "ecdsa-sha2-", "age1", "npub1"} {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	return true
}

// namedSecret reports whether a field name says its value is a secret:
// password, passphrase, secret, token, api key, private key, psk... as the last
// word of the name (client_secret, db-password, authTokens).
var namedSecret = regexp.MustCompile(`(?i)(?:^|[^a-z])(?:password|passwd|passphrase|secrets?|tokens?|api[_ -]?keys?|private[_ -]?keys?|privkey|psk|pre[_-]?shared[_-]?keys?|wpa[_ -]?passphrase)s?$`)

func isSecretName(name string) bool {
	if namedSecret.MatchString(name) {
		return true
	}
	// camelCase: dbPassword, apiKey, privateKey
	return namedCamel.MatchString(name)
}

var namedCamel = regexp.MustCompile(`(?:Password|Passphrase|Secrets?|Tokens?|ApiKeys?|PrivateKeys?|Psk)$`)

var (
	// scheme:// with no user:password in it is a reference or a plain URL.
	uriRef = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^@\s]*$`)
	// $NAME, env:NAME, vault:path and friends.
	envRef = regexp.MustCompile(`^(?:\$[A-Z_][A-Z0-9_]*|(?i:env|vault|op|ssm|kms|pass|bw|keychain|file):\S+)$`)
)

var nonLetters = regexp.MustCompile(`[^a-z]+`)

// notPublic drops "public key: <hex>", fingerprints and hashes, judged by the
// words just before the keyword.
func notPublic(_, before string) bool {
	if len(before) > 24 {
		before = before[len(before)-24:]
	}
	for _, w := range nonLetters.Split(strings.ToLower(before), -1) {
		switch w {
		// nodekey, machinekey and discokey are Tailscale's public keys; host keys,
		// GPG and PGP key IDs and fingerprints are public too.
		case "pub", "public", "fingerprint", "hash", "sha", "digest", "checksum", "node", "machine", "disco", "host", "gpg", "pgp":
			return false
		}
	}
	return true
}

// urlPassword drops "user:${PASSWORD}" and "user:<password>".
func urlPassword(value, _ string) bool {
	i := strings.Index(value, ":")
	if i < 0 {
		return false
	}
	return notPlaceholder(value[i+1:], "")
}
