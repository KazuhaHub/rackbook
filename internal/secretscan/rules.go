package secretscan

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// Tiers. The block tier is deterministic: key material and known token
// formats are refused in every string, always; schema annotations,
// placeholders and confirm_not_secret never silence it, and only the allow list
// (by value hash) overrides it. The confirm tier is heuristic: keyword
// assignments in any language, a long hex string after "key", the whole value
// of a secret-named field and high-entropy tokens. The editor may confirm "this
// is not a secret" (the confirmation is recorded in the commit); annotations and
// placeholders silence it too; `rackbook check` reports it as warnings.
const (
	TierBlock   = "block"
	TierConfirm = "confirm"
)

// rule is one compiled pattern or a procedural matcher. group is the submatch
// that holds the secret itself (0 = the whole match); it is what an excerpt shows
// and what allow[].value_sha256 hashes. hints are literal substrings one of
// which the text must contain for the rule to run at all (a cheap prefilter);
// ci says they match case-insensitively. There are no text-context exemptions:
// a confirm-tier value is exempt only through a schema annotation
// (annotations.go), an exact placeholder or the allow list; a block-tier value
// only through the allow list.
// span is a byte range of the normalised text.
type span struct{ start, end int }

type rule struct {
	id          string
	description string
	tier        string
	re          *regexp.Regexp
	group       int
	hints       []string
	ci          bool
	filter      func(value string) bool                     // drops a match whose value fails it
	proc        func(s *Scanner, text, lower string) []span // byte spans of the matched values in text
}

// The built-in rule IDs. They are stable: allow lists and disable_rules in
// rackbook.yml refer to them.
const (
	RulePrivateKey   = "private-key"
	RulePrivateB64   = "private-key-base64"
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
	RuleURLQuery     = "url-query-secret"
	RuleGitLabToken  = "gitlab-token"
	RuleNPMToken     = "npm-token"
	RuleHFToken      = "huggingface-token"
	RuleTailscaleKey = "tailscale-key"
	RuleSendGridKey  = "sendgrid-key"
	RuleAzureKey     = "azure-account-key"
	RuleBearer       = "bearer-token"
	RulePrivateJWK   = "private-jwk"
	RuleEntropy      = "high-entropy"
)

// jwkPrivate: a "kty" member and a "d" member in the same object, in either
// order; the quotes may be JSON-escaped (\" inside a string) and d may be
// base64url or standard base64.
const (
	jwkQ       = `\\?"`
	jwkPrivate = `(?s)\{[^{}]*` + jwkQ + `kty` + jwkQ + `[^{}]*` + jwkQ + `d` + jwkQ + `\s*:\s*` + jwkQ + `[A-Za-z0-9_+/=-]{8,}` + jwkQ +
		`|\{[^{}]*` + jwkQ + `d` + jwkQ + `\s*:\s*` + jwkQ + `[A-Za-z0-9_+/=-]{8,}` + jwkQ + `[^{}]*` + jwkQ + `kty` + jwkQ
)

const hexAssign = `(?i)(?:key|privkey)\s*[:=]\s*["']?([0-9a-f]{32,})\b`

// pemB64 is the base64 of "-----BEGIN <label> PRIVATE KEY-----" as it starts a
// base64-encoded PEM file (kubeconfig client-key-data and the like): only the
// prefix that does not depend on the bytes that follow.
func pemB64() string {
	var alts []string
	for _, l := range []string{"OPENSSH", "RSA", "EC", "DSA", "", "ENCRYPTED"} {
		head := "-----BEGIN " + strings.TrimSpace(l+" PRIVATE KEY") + "-----"
		enc := base64.StdEncoding.EncodeToString([]byte(head))
		alts = append(alts, regexp.QuoteMeta(enc[:len(head)/3*4]))
	}
	return `(?:` + strings.Join(alts, "|") + `)[A-Za-z0-9+/]*={0,2}`
}

func builtin() []*rule {
	return []*rule{
		{id: RulePrivateKey, tier: TierBlock, description: "PEM private key block", hints: []string{"PRIVATE KEY"},
			re: regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)`)},
		{id: RulePrivateB64, tier: TierBlock, description: "base64-encoded PEM private key", hints: []string{"LS0tLS1CRUdJTi"}, re: regexp.MustCompile(pemB64())},
		{id: RuleAgeKey, tier: TierBlock, description: "age secret key", hints: []string{"AGE-SECRET-KEY-1"}, re: regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]{58}`)},
		{id: RuleGitHubToken, tier: TierBlock, description: "GitHub token", hints: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
		{id: RuleGitHubPAT, tier: TierBlock, description: "GitHub fine-grained token", hints: []string{"github_pat_"}, re: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)},
		{id: RuleAIKey, tier: TierBlock, description: "OpenAI or Anthropic style API key", hints: []string{"sk-"}, re: regexp.MustCompile(`sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`), filter: skKey},
		{id: RuleSlackToken, tier: TierBlock, description: "Slack token", hints: []string{"xox", "xapp-"}, re: regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}|xapp-[0-9]-[A-Za-z0-9-]{10,}`)},
		{id: RuleAWSKeyID, tier: TierBlock, description: "AWS access key ID", hints: []string{"AKIA", "ASIA"}, re: regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)},
		{id: RuleGoogleKey, tier: TierBlock, description: "Google API key", hints: []string{"AIza"}, re: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
		{id: RuleStripeKey, tier: TierBlock, description: "Stripe live secret key", hints: []string{"_live_"}, re: regexp.MustCompile(`(?:sk|rk)_live_[0-9a-zA-Z]{24,}`)},
		{id: RuleJWT, tier: TierBlock, description: "JSON Web Token", hints: []string{"eyJ"}, re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
		{id: RuleGitLabToken, tier: TierBlock, description: "GitLab personal access token", hints: []string{"glpat-"}, re: regexp.MustCompile(`glpat-[0-9A-Za-z_-]{20,}`)},
		{id: RuleNPMToken, tier: TierBlock, description: "npm access token", hints: []string{"npm_"}, re: regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
		{id: RuleHFToken, tier: TierBlock, description: "Hugging Face token", hints: []string{"hf_"}, re: regexp.MustCompile(`hf_[A-Za-z]{34,}`)},
		{id: RuleTailscaleKey, tier: TierBlock, description: "Tailscale auth key", hints: []string{"tskey-"}, re: regexp.MustCompile(`tskey-[a-z]+-[A-Za-z0-9-]{10,}`)},
		{id: RuleSendGridKey, tier: TierBlock, description: "SendGrid API key", hints: []string{"SG."}, re: regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)},
		{id: RuleAzureKey, tier: TierBlock, description: "Azure storage account key", hints: []string{"AccountKey="}, re: regexp.MustCompile(`AccountKey=([A-Za-z0-9+/=]{40,})`), group: 1},
		{id: RuleURLPassword, tier: TierBlock, description: "URL with a user name and password", hints: []string{"://"}, re: regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^/\s:@]+:[^/\s@]+)@`), group: 1},
		{id: RuleURLQuery, tier: TierBlock, description: "secret in a URL query parameter", hints: []string{"?", "&"}, filter: credLike,
			re: regexp.MustCompile(`(?i)[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|password|passwd|key|sig|signature)=([^&\s#"'<>]{8,})`), group: 1},
		{id: RulePrivateJWK, tier: TierBlock, description: "JSON Web Key with a private member", hints: []string{"kty"},
			re: regexp.MustCompile(jwkPrivate)},
		{id: RuleHexKey, tier: TierConfirm, description: "long hex string assigned to a key", hints: []string{"key"}, ci: true, re: regexp.MustCompile(hexAssign), group: 1},
		{id: RuleBearer, tier: TierConfirm, description: "bearer token", hints: []string{"bearer"}, ci: true, re: regexp.MustCompile(`(?i)\bBearer ([A-Za-z0-9._~+/-]{20,}=*)`), group: 1},
		{id: RuleSecretAssign, tier: TierConfirm, description: "secret, password or token assigned in text (any language)", proc: assignments},
		{id: RuleEntropy, tier: TierConfirm, description: "high-entropy token", proc: entropyTokens},
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

// skKey: an "sk-ant-" or "sk-proj-" key always counts; a plain "sk-" needs a
// digit or an upper-case letter, so that words like "task-management-system-
// service-account" (no word boundary is required before "sk-") do not fire.
func skKey(v string) bool {
	return strings.HasPrefix(v, "sk-ant-") || strings.HasPrefix(v, "sk-proj-") || strings.ContainsAny(v, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// credLike says a value looks like a credential: it contains a digit, or mixes
// upper and lower case (an upper-case letter after the first character), or
// contains a symbol.
func credLike(v string) bool {
	hasLower, innerUpper := false, false
	for i, r := range v {
		switch {
		case r >= '0' && r <= '9':
			return true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			if i > 0 {
				innerUpper = true
			}
		case r < 0x80 && r > ' ':
			return true // ASCII symbol
		}
	}
	return hasLower && innerUpper
}

// secretName says whether a field name marks its value as a secret:
// password, passphrase, secret, token, api key, private key, psk, secret_key,
// encryption_key, signing_key, 密码 and the like, as the last word of the name,
// with or without a separator (client_secret, db-password, authTokens).
var secretName = regexp.MustCompile(`(?i)(?:password|passwd|passphrase|secrets?|tokens?)s?$|(?:^|[^a-z])(?:pwd|pass|api[_ -]?keys?|apikey|private[_ -]?keys?|privkey|psk|pre[_-]?shared[_-]?keys?|wpa[_ -]?passphrase|secret[_ -]?(?:access[_ -]?)?keys?|encryption[_ -]?keys?|signing[_ -]?keys?)$|(?-i:(?:^|[A-Za-z0-9_ -])(?:ApiKey|PrivateKey|SecretKey|EncryptionKey|SigningKey|Psk|Pwd|Pass)s?$)|(?:密码|密碼|口令|密钥|令牌|秘钥|凭据|凭证|授权码|私钥|访问密钥|パスワード|비밀번호|암호|패스워드)$`)

func isSecretName(name string) bool { return secretName.MatchString(normalizeText(name)) }

// placeholders are the only values that are never secrets anywhere, matched
// as the whole (trimmed) value.
func isPlaceholder(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "待补", "tbd", "-", "***", "n/a", "none", "empty":
		return true
	}
	return false
}
