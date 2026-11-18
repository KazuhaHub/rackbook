package secretscan

import (
	"regexp"
	"strings"
)

// rule is one compiled pattern. group is the submatch that holds the secret
// itself (0 = the whole match); it is what an excerpt shows and what
// allow[].value_sha256 hashes. There are no text-context exemptions: a value
// is exempt only through a schema annotation (see annotations.go) or the
// allow list.
type rule struct {
	id          string
	description string
	re          *regexp.Regexp
	group       int
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
const keywordAssign = `(?i)(?:(?:^|[^a-z])psk|secret[_ -]?(?:access[_ -]?)?key|encryption[_ -]?key|signing[_ -]?key|private[_ -]?key|privkey|secret|password|passwd|passphrase|wpa_passphrase|pre[_-]?shared[_-]?key|token|api[_-]?key)["']?\s*[:=]\s*["']?(\S{8,})`

const hexAssign = `(?i)(?:key|privkey)\s*[:=]\s*([0-9a-f]{32,})\b`

func builtin() []*rule {
	return []*rule{
		{id: RulePrivateKey, description: "PEM private key block", re: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)`)},
		{id: RuleAgeKey, description: "age secret key", re: regexp.MustCompile(`\bAGE-SECRET-KEY-1[0-9A-Z]{58}`)},
		{id: RuleGitHubToken, description: "GitHub token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`)},
		{id: RuleGitHubPAT, description: "GitHub fine-grained token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}`)},
		{id: RuleAIKey, description: "OpenAI or Anthropic style API key", re: regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`)},
		{id: RuleSlackToken, description: "Slack token", re: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
		{id: RuleAWSKeyID, description: "AWS access key ID", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{id: RuleGoogleKey, description: "Google API key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
		{id: RuleStripeKey, description: "Stripe live secret key", re: regexp.MustCompile(`\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}`)},
		{id: RuleJWT, description: "JSON Web Token", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
		{id: RuleSecretAssign, description: "secret, password or token assigned in text", re: regexp.MustCompile(keywordAssign), group: 1},
		{id: RuleHexKey, description: "long hex string assigned to a key", re: regexp.MustCompile(hexAssign), group: 1},
		{id: RuleGitLabToken, description: "GitLab personal access token", re: regexp.MustCompile(`\bglpat-[0-9A-Za-z_-]{20,}`)},
		{id: RuleNPMToken, description: "npm access token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}`)},
		{id: RuleHFToken, description: "Hugging Face token", re: regexp.MustCompile(`\bhf_[A-Za-z]{34,}`)},
		{id: RuleTailscaleKey, description: "Tailscale auth key", re: regexp.MustCompile(`\btskey-[a-z]+-[A-Za-z0-9-]{10,}`)},
		{id: RuleSendGridKey, description: "SendGrid API key", re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)},
		{id: RuleAzureKey, description: "Azure storage account key", re: regexp.MustCompile(`AccountKey=([A-Za-z0-9+/=]{40,})`), group: 1},
		{id: RuleBearer, description: "bearer token", re: regexp.MustCompile(`(?i)\bBearer ([A-Za-z0-9._~+/-]{20,}=*)`), group: 1},
		{id: RuleURLPassword, description: "URL with a user name and password", re: regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^/\s:@]+:[^/\s@]+)@`), group: 1},
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

// secretName says whether a field name marks its value as a secret:
// password, passphrase, secret, token, api key, private key, psk, secret_key,
// encryption_key, signing_key ... as the last word of the name, with or without
// a separator (client_secret, db-password, authTokens, accesstoken).
var secretName = regexp.MustCompile(`(?i)(?:password|passwd|passphrase|secrets?|tokens?)s?$|(?:^|[^a-z])(?:api[_ -]?keys?|private[_ -]?keys?|privkey|psk|pre[_-]?shared[_-]?keys?|wpa[_ -]?passphrase|secret[_ -]?(?:access[_ -]?)?keys?|encryption[_ -]?keys?|signing[_ -]?keys?)$|(?:ApiKey|PrivateKey|SecretKey|EncryptionKey|SigningKey|Psk)s?$`)

func isSecretName(name string) bool { return secretName.MatchString(name) }

// placeholders are the only values that are never secrets anywhere, matched
// as the whole (trimmed) value.
func isPlaceholder(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "待补", "tbd", "-", "***", "n/a", "none", "empty":
		return true
	}
	return false
}
