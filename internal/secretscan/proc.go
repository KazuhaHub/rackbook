package secretscan

import (
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// normalizeText is applied before any matching: zero-width characters are
// removed and the text is NFKC-normalised, so full-width "：" "＝" and letters
// match as their ASCII forms. Pure ASCII text is returned as it is.
func normalizeText(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	// zero-width and invisible formatting characters
	if strings.ContainsAny(s, "\u200b\u200c\u200d\u200e\u200f\u00ad\u2060\u2061\u2062\u2063\u2064\ufeff") {
		s = strings.Map(func(r rune) rune {
			switch {
			case r >= 0x200B && r <= 0x200F, r == 0x00AD, r >= 0x2060 && r <= 0x2064, r == 0xFEFF:
				return -1
			}
			return r
		}, s)
	}
	if norm.NFKC.IsNormalString(s) {
		return s
	}
	return norm.NFKC.String(s)
}

var cjkKeywords = []string{"访问密钥", "密码", "密碼", "口令", "密钥", "令牌", "秘钥", "凭据", "凭证", "授权码", "私钥", "パスワード", "비밀번호", "패스워드", "암호"}

// asciiLower lowercases ASCII letters byte by byte, so indices stay aligned.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// sepAt skips one optional " ", "_" or "-" at pos.
func sepAt(s string, pos int) int {
	if pos < len(s) && (s[pos] == ' ' || s[pos] == '_' || s[pos] == '-') {
		return pos + 1
	}
	return pos
}

// wordsAt matches lower-case words, each optionally separated by a space, "_" or
// "-", at pos, and returns the end of the match or -1. A word starting with "?"
// is optional (its trailing separator too).
func wordsAt(s string, pos int, words ...string) int {
	for i, w := range words {
		if !strings.HasPrefix(s[pos:], w) {
			return -1
		}
		pos += len(w)
		if i < len(words)-1 {
			pos = sepAt(s, pos)
		}
	}
	return pos
}

// keywordEnd reports the end of an assignment keyword starting at i in the
// ASCII-lowered text lt (original text t), or -1. Longest forms come first.
func keywordEnd(t, lt string, i int) int {
	try := func(ws ...string) int { return wordsAt(lt, i, ws...) }
	first := func(ends ...int) int {
		for _, e := range ends {
			if e >= 0 {
				return e
			}
		}
		return -1
	}
	switch lt[i] {
	case 'p':
		return first(try("privkey"), try("private", "key"), try("pre", "shared", "key"), try("passphrase"), try("password"), try("passwd"), try("pwd"), try("pass"), try("psk"))
	case 's':
		return first(try("secret", "access", "key"), try("secret", "key"), try("secret"), try("signing", "key"))
	case 't':
		return try("token")
	case 'a':
		return first(try("api", "key"), try("apikey"))
	case 'e':
		return try("encryption", "key")
	}
	if lt[i] >= 0xE0 {
		for _, k := range cjkKeywords {
			if strings.HasPrefix(t[i:], k) {
				return i + len(k)
			}
		}
	}
	return -1
}

// keywordSpans finds the assignment keywords in text without a regexp: a single
// pass over the bytes, which is what keeps scanning a megabyte cheap.
func keywordSpans(text, lt string) [][2]int {
	var out [][2]int
	for i := 0; i < len(lt); {
		if e := keywordEnd(text, lt, i); e > i {
			out = append(out, [2]int{i, e})
			i = e
		} else {
			i++
		}
	}
	return out
}

func isASCIILetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

// assignments finds "<keyword> <separator> <value>" in any of the supported
// languages: separators ":", "=", "→", "is", "was", "是", "为", "為", with up to
// three plain words between the keyword and the separator ("the root password
// for db is X", "root 密码是 X"). The value is the next token: at least 8
// characters, not a placeholder, a path or a reference. After a word separator
// or intervening words it must also look like a credential.
func assignments(s *Scanner, text, lt string) []string {
	var out []string
	for _, m := range keywordSpans(text, lt) {
		a, e := m[0], m[1]
		kw := text[a:e]
		if kw[0] < 0x80 { // ASCII keywords must stand on their own
			if e < len(text) && isASCIILetter(text[e]) {
				continue
			}
			lk := strings.ToLower(kw)
			if (lk == "pass" || lk == "pwd" || lk == "psk") && a > 0 && isASCIILetter(text[a-1]) {
				continue
			}
		}
		// each keyword reads a bounded window, so a long run of "password=" stays linear
		win := text[e:min(len(text), e+maxWindow)]
		if v, ok := assignedValue(s, win); ok {
			out = append(out, v)
		}
	}
	return out
}

// maxWindow bounds how far after a keyword the value is looked for; the value
// itself is at most maxValue bytes.
const (
	maxWindow = 320
	maxValue  = 256
)

func assignedValue(s *Scanner, rest string) (string, bool) {
	pos := 0
	if pos < len(rest) && (rest[pos] == '"' || rest[pos] == '\'') {
		pos++
	}
	words, wordSep := 0, false
	for {
		for pos < len(rest) && (rest[pos] == ' ' || rest[pos] == '\t') {
			pos++
		}
		if pos >= len(rest) {
			return "", false
		}
		r, size := utf8.DecodeRuneInString(rest[pos:])
		switch {
		case r == ':' || r == '=':
			pos += size
		case r == '→' || r == '是' || r == '为' || r == '為' || r == 'は' || r == '는' || r == '은':
			pos += size
			wordSep = true
		case isWordAt(rest, pos, "is") || isWordAt(rest, pos, "was"):
			for pos < len(rest) && isASCIILetter(rest[pos]) {
				pos++
			}
			wordSep = true
		case words < 3 && isASCIILetter(rest[pos]):
			for pos < len(rest) && isASCIILetter(rest[pos]) {
				pos++
			}
			words++
			continue
		default:
			return "", false
		}
		break
	}
	for pos < len(rest) && (rest[pos] == ' ' || rest[pos] == '\t') {
		pos++
	}
	for pos < len(rest) {
		r, size := utf8.DecodeRuneInString(rest[pos:])
		if r == '"' || r == '\'' || r == '“' || r == '‘' || r == '「' {
			pos += size
			continue
		}
		break
	}
	end := pos
	for end < len(rest) && end-pos < maxValue {
		r, size := utf8.DecodeRuneInString(rest[end:])
		if unicode.IsSpace(r) {
			break
		}
		end += size
	}
	v := strings.Trim(rest[pos:end], `"',;。，；”’」`)
	if utf8.RuneCountInString(v) < 8 || isPlaceholderValue(v) || isPathValue(v) || s.isReference(v) {
		return "", false
	}
	if (wordSep || words > 0) && !credLike(v) {
		return "", false
	}
	return v, true
}

func isWordAt(s string, pos int, w string) bool {
	if len(s)-pos <= len(w) || !strings.EqualFold(s[pos:pos+len(w)], w) {
		return false
	}
	return !isASCIILetter(s[pos+len(w)])
}

var (
	maskValue = regexp.MustCompile(`^(?:[xX*#•]{3,}|<[A-Za-z _-]{1,30}>)$`)
	pathValue = regexp.MustCompile(`^(?:/|~/|\./)[A-Za-z0-9._@%+=,:/-]+$`)
	refOP     = regexp.MustCompile(`^op://(\S+)$`)
	refVault  = regexp.MustCompile(`^vault:(\S+)$`)
	refEnv    = regexp.MustCompile(`^(?:env:[A-Z_][A-Z0-9_]*|\$\{[A-Z_][A-Z0-9_]*\})$`)
	refStore  = regexp.MustCompile(`^secrets?/[A-Za-z0-9._/-]+#[A-Za-z0-9._-]+$`)
)

func isPlaceholderValue(v string) bool { return isPlaceholder(v) || maskValue.MatchString(v) }

// isPathValue: an absolute or home path of safe characters that does not look
// like a value (a single segment of 8 or more characters with a digit or mixed
// case is a password that happens to start with "/").
func isPathValue(v string) bool {
	if !pathValue.MatchString(v) {
		return false
	}
	seg := strings.TrimLeft(v, "~./")
	if !strings.Contains(seg, "/") && utf8.RuneCountInString(seg) >= 8 && credLike(seg) {
		return false
	}
	return true
}

// isReference: where a secret lives rather than the secret: op://, vault:,
// env:NAME, ${NAME} or secrets/path#key. What follows the prefix is scanned
// again, so "op://ghp_..." is not a reference.
func (s *Scanner) isReference(v string) bool {
	// the remainder is checked with the block-tier rules only, once: never with
	// the keyword rule again (that would recurse on "password=op://password=op://...")
	if refEnv.MatchString(v) || refStore.MatchString(v) && len(s.blockMatches(v)) == 0 {
		return true
	}
	for _, re := range []*regexp.Regexp{refOP, refVault} {
		if m := re.FindStringSubmatch(v); m != nil {
			rem := m[1]
			if len(rem) > 128 { // a token is far shorter; keeps long runs cheap
				rem = rem[:128]
			}
			return len(s.blockMatches(rem)) == 0
		}
	}
	return false
}

// entropyTokens finds long, mixed, high-entropy tokens in free text: at least
// 20 characters, three or more of the classes upper, lower, digit and symbol,
// and Shannon entropy of at least 4.0 bits per character. Tokens are runs of
// ASCII characters between whitespace, quotes, brackets and commas; URLs are
// skipped (the userinfo and query rules look at those).
func entropyTokens(_ *Scanner, text, _ string) []string {
	var out []string
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		tok := text[start:end]
		start = -1
		if len(tok) >= 20 && len(tok) <= 512 && entropyOK(tok) {
			out = append(out, tok)
		}
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		delim := c <= ' ' || c >= 0x7f || strings.IndexByte(",;()[]{}<>\"'`|", c) >= 0
		if delim {
			flush(i)
		} else if start < 0 {
			start = i
		}
	}
	flush(len(text))
	return out
}

func entropyOK(tok string) bool {
	if strings.Contains(tok, "://") {
		return false
	}
	// hyphenated or dotted names are made of short words, not of a key
	longest, run := 0, 0
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; c == '-' || c == '_' || c == '.' {
			run = 0
		} else if run++; run > longest {
			longest = run
		}
	}
	if longest < 12 {
		return false
	}
	var counts [128]int
	var up, lo, dg, sy bool
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		counts[c]++
		switch {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= '0' && c <= '9':
			dg = true
		default:
			sy = true
		}
	}
	classes := 0
	for _, b := range []bool{up, lo, dg, sy} {
		if b {
			classes++
		}
	}
	if classes < 3 {
		return false
	}
	n := float64(len(tok))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h >= 4.0
}
