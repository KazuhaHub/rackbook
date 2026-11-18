// Package secretscan is Rackbook's built-in scan for secrets in the data it is
// about to write. Rackbook runs Git with hooks disabled, so a pre-commit hook
// in the data repository (gitleaks and the like) never sees its commits; this
// scan runs before anything reaches the disk or Git instead. It is
// deterministic, pattern based and never runs anything from the data
// repository.
package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Config is the secret_scan block of rackbook.yml.
type Config struct {
	// Enabled defaults to true.
	Enabled       *bool          `yaml:"enabled" json:"enabled,omitempty"`
	ExtraPatterns []ExtraPattern `yaml:"extra_patterns" json:"extra_patterns,omitempty"`
	Allow         []Allow        `yaml:"allow" json:"allow,omitempty"`
	DisableRules  []string       `yaml:"disable_rules" json:"disable_rules,omitempty"`
}

// ExtraPattern adds a rule. When the pattern has a capture group, group 1 is
// the secret (what is shown redacted and hashed); otherwise the whole match.
type ExtraPattern struct {
	ID          string `yaml:"id" json:"id"`
	Pattern     string `yaml:"pattern" json:"pattern"`
	Description string `yaml:"description" json:"description,omitempty"`
}

// Allow suppresses a known false positive. Rule is required and at least one of
// the other fields must narrow it; value_sha256 must come with a collection. Field is a JSON pointer inside the record
// (a leading "/" is optional) and covers everything below it. ValueSHA256 is the
// hex SHA-256 of the matched value: the whole match, except for the
// secret-assignment and hex-key rules (the text after the ":" or "="), the
// url-credentials rule ("user:password") and extra patterns with a capture
// group (group 1). Surrounding quotes and a trailing "," or ";" are not part of it.
type Allow struct {
	Rule        string `yaml:"rule" json:"rule"`
	Collection  string `yaml:"collection" json:"collection,omitempty"`
	Field       string `yaml:"field" json:"field,omitempty"`
	ValueSHA256 string `yaml:"value_sha256" json:"value_sha256,omitempty"`
}

// Finding is one match. It never carries the secret: Excerpt is at most the
// first 4 characters of it plus an ellipsis.
type Finding struct {
	Rule       string `json:"rule"`
	Collection string `json:"collection"`
	ID         string `json:"id,omitempty"`
	// Path is the JSON pointer of the field inside the record. For a secret
	// found in a map key it is the pointer of the map, and In is "key".
	Path    string `json:"path"`
	Excerpt string `json:"excerpt"`
	In      string `json:"in,omitempty"`
	// Tier is "block" (key material and known token formats: always refused) or
	// "confirm" (heuristic: the editor may confirm it is not a secret).
	Tier string `json:"tier"`

	fp string // sha256 of the matched value, to tell new findings from old ones
}

// Message is the one-line description used in check output and errors.
func (f Finding) Message() string {
	where := ""
	if f.In == "key" {
		where = " in a field name"
	}
	return fmt.Sprintf("possible secret%s (%s): %s", where, f.Rule, f.Excerpt)
}

// Error is returned by a write that the scan refused. Nothing was written.
type Error struct{ Findings []Finding }

// Suspected reports that every finding is confirm tier: the editor may confirm
// they are not secrets and retry. Any block-tier finding makes it false.
func (e *Error) Suspected() bool {
	for _, f := range e.Findings {
		if f.Tier != TierConfirm {
			return false
		}
	}
	return len(e.Findings) > 0
}

// RuleIDs lists the distinct rule IDs of fs, sorted.
func RuleIDs(fs []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			out = append(out, f.Rule)
		}
	}
	sort.Strings(out)
	return out
}

// Split separates block-tier from confirm-tier findings.
func Split(fs []Finding) (block, confirm []Finding) {
	for _, f := range fs {
		if f.Tier == TierConfirm {
			confirm = append(confirm, f)
		} else {
			block = append(block, f)
		}
	}
	return
}

func (e *Error) Error() string {
	var b strings.Builder
	if e.Suspected() {
		b.WriteString("this looks like a secret, nothing was written (confirm it is not one to save):")
	} else {
		b.WriteString("secret detected, nothing was written:")
	}
	for _, f := range e.Findings {
		b.WriteString("\n  " + f.Location() + ": " + f.Message())
	}
	b.WriteString("\nKeep secrets out of the ledger (store a reference to a password manager or an environment variable). If this is a false positive, add a precise entry to secret_scan.allow in rackbook.yml.")
	return b.String()
}

// Location is "collection/id path" for messages.
func (f Finding) Location() string {
	s := f.Collection
	if f.ID != "" {
		s += "/" + f.ID
	}
	if f.Path != "" {
		s += " " + f.Path
	}
	return s
}

// AsError wraps findings in an *Error; nil when there are none.
func AsError(fs []Finding) error {
	if len(fs) == 0 {
		return nil
	}
	return &Error{Findings: fs}
}

type allowRule struct {
	rule, collection, field, sha string
}

// Scanner is a compiled configuration. A nil *Scanner scans with the defaults
// (every built-in rule), never with nothing: forgetting to configure it must
// not switch the protection off.
type Scanner struct {
	enabled bool
	minLen  int // shortest string worth matching
	rules   []*rule
	allow   []allowRule
}

var defaultScanner = mustNew(Config{})

func mustNew(c Config) *Scanner {
	s, err := New(c)
	if err != nil {
		panic(err)
	}
	return s
}

// Default is the scanner with every built-in rule on.
func Default() *Scanner { return defaultScanner }

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// New compiles c. An invalid pattern, id or allow entry is an error.
func New(c Config) (*Scanner, error) {
	s := &Scanner{enabled: c.Enabled == nil || *c.Enabled, minLen: minLen}
	known := builtinIDs()
	disabled := map[string]bool{}
	var extra []*rule
	for i, p := range c.ExtraPatterns {
		if !idRe.MatchString(p.ID) {
			return nil, fmt.Errorf("secret_scan.extra_patterns[%d]: id %q must be lower-case letters, digits, '.', '_' or '-'", i, p.ID)
		}
		if known[p.ID] {
			return nil, fmt.Errorf("secret_scan.extra_patterns[%d]: id %q is already used", i, p.ID)
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("secret_scan.extra_patterns[%d] (%s): %w", i, p.ID, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("secret_scan.extra_patterns[%d] (%s): the pattern matches the empty string", i, p.ID)
		}
		s.minLen = 1 // an extra pattern may match anything
		known[p.ID] = true
		r := &rule{id: p.ID, description: p.Description, re: re, tier: TierBlock}
		if re.NumSubexp() > 0 {
			r.group = 1
		}
		extra = append(extra, r)
	}
	for _, id := range c.DisableRules {
		if !known[id] {
			return nil, fmt.Errorf("secret_scan.disable_rules: unknown rule %q", id)
		}
		disabled[id] = true
	}
	for _, r := range append(builtin(), extra...) {
		if !disabled[r.id] {
			s.rules = append(s.rules, r)
		}
	}
	for i, a := range c.Allow {
		if !known[a.Rule] {
			return nil, fmt.Errorf("secret_scan.allow[%d]: unknown rule %q", i, a.Rule)
		}
		if a.Collection == "" && a.Field == "" && a.ValueSHA256 == "" {
			return nil, fmt.Errorf("secret_scan.allow[%d]: give a collection, a field or a value_sha256 so that the entry stays precise", i)
		}
		sha := strings.ToLower(a.ValueSHA256)
		if sha != "" && a.Collection == "" {
			return nil, fmt.Errorf("secret_scan.allow[%d]: value_sha256 needs a collection; a value allowed in every collection would also let the same secret in anywhere", i)
		}
		if sha != "" {
			if b, err := hex.DecodeString(sha); err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("secret_scan.allow[%d]: value_sha256 must be 64 hex characters", i)
			}
		}
		s.allow = append(s.allow, allowRule{rule: a.Rule, collection: a.Collection, field: strings.TrimPrefix(a.Field, "/"), sha: sha})
	}
	return s, nil
}

func (s *Scanner) get() *Scanner {
	if s == nil {
		return defaultScanner
	}
	return s
}

// Enabled reports whether the scan runs at all.
func (s *Scanner) Enabled() bool { return s.get().enabled }

// RuleIDs lists the active rules in order.
func (s *Scanner) RuleIDs() []string {
	var out []string
	for _, r := range s.get().rules {
		out = append(out, r.id)
	}
	return out
}

// Hash is the SHA-256 hex digest an allow entry's value_sha256 is compared with.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Excerpt shows at most 4 characters of a secret (a third of it for short
// ones) and an ellipsis; never the secret itself.
func Excerpt(value string) string {
	n := utf8.RuneCountInString(value) / 3
	if n > 4 {
		n = 4
	}
	r := []rune(value)
	return string(r[:n]) + "…"
}

// minLen is the shortest string any rule can match.
const minLen = 8

type hit struct {
	rule  string
	value string
	tier  string
	// start and end are the byte span of value in the normalised text a rule
	// found it in (set by run; unused elsewhere).
	start, end int
}

// matches runs every rule over text. The text is normalised first (NFKC,
// zero-width characters removed). The rules are unanchored, so they find a
// secret wherever it sits: after a "*", "/", quote, bracket or CJK text.
func (s *Scanner) matches(text string) []hit { return s.matchText(text) }

// matchText runs every rule over one piece of text.
func (s *Scanner) matchText(text string) []hit { return s.run(text, false) }

// blockMatches runs only the block-tier regexp rules: the check applied to the
// remainder of a reference, which never recurses into the keyword rule.
func (s *Scanner) blockMatches(text string) []hit { return s.run(text, true) }

func (s *Scanner) run(text string, blockOnly bool) []hit {
	if len(text) < s.minLen {
		return nil
	}
	text = normalizeText(text)
	var lower string
	haveLower := false
	lowered := func() string {
		if !haveLower {
			lower, haveLower = asciiLower(text), true
		}
		return lower
	}
	var out []hit
	for _, r := range s.rules {
		if blockOnly && (r.tier != TierBlock || r.proc != nil) {
			continue
		}
		if len(r.hints) > 0 { // cheap prefilter: skip the regexp unless a literal is there
			hay := text
			if r.ci {
				hay = lowered()
			}
			found := false
			for _, h := range r.hints {
				if strings.Contains(hay, h) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if r.proc != nil {
			for _, sp := range r.proc(s, text, lowered()) {
				out = append(out, hit{rule: r.id, value: text[sp.start:sp.end], tier: r.tier, start: sp.start, end: sp.end})
			}
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			g := r.group
			if m[2*g] < 0 { // an optional group that did not take part: the whole match
				g = 0
			}
			value := text[m[2*g]:m[2*g+1]]
			if g > 0 {
				value = strings.Trim(value, `"',;`)
			}
			if r.filter != nil && !r.filter(value) {
				continue
			}
			out = append(out, hit{rule: r.id, value: value, tier: r.tier, start: m[2*g], end: m[2*g+1]})
		}
	}
	return dropCovered(out)
}

// dropCovered removes a high-entropy hit that is only another rule's match seen
// again (a token, or the body of a private key): one whose span overlaps the
// span of a non-entropy hit. The other spans are sorted by start with a running
// maximum of their ends, so each entropy hit is one binary search: O(n log n),
// where comparing every pair of hits took quadratic time on a megabyte of
// keyword assignments and tokens.
func dropCovered(hits []hit) []hit {
	var others []hit
	for _, h := range hits {
		if h.rule != RuleEntropy {
			others = append(others, h)
		}
	}
	if len(others) == len(hits) || len(others) == 0 {
		return hits // nothing to compare, or no other rule matched at all
	}
	sort.Slice(others, func(i, j int) bool { return others[i].start < others[j].start })
	maxEnd := make([]int, len(others)) // maxEnd[i]: the largest end among others[:i+1]
	for i, o := range others {
		maxEnd[i] = o.end
		if i > 0 && maxEnd[i-1] > o.end {
			maxEnd[i] = maxEnd[i-1]
		}
	}
	out := hits[:0:0]
	for _, h := range hits {
		if h.rule == RuleEntropy {
			// the others that start before h ends: one of them reaching past h's start overlaps it
			n := sort.Search(len(others), func(i int) bool { return others[i].start >= h.end })
			if n > 0 && maxEnd[n-1] > h.start {
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

// namedHit applies the "field named like a secret" rule: the whole string
// value counts, spaces included ("correct horse battery staple"). Only the
// exact placeholders (and, upstream, an annotated secret_reference field) are
// exempt.
func (s *Scanner) namedHit(value string) (hit, bool) {
	v := strings.TrimSpace(value)
	if len(v) < 6 || isPlaceholder(v) || !s.ruleOn(RuleSecretAssign) {
		return hit{}, false
	}
	return hit{rule: RuleSecretAssign, value: v, tier: TierConfirm}, true
}

func (s *Scanner) ruleOn(id string) bool {
	for _, r := range s.rules {
		if r.id == id {
			return true
		}
	}
	return false
}

// pairMatches runs the hex-key rule over "name: value" for a field name and its
// string value, so that a field called ssh_key holding hex is caught.
func (s *Scanner) pairMatches(name, value string) []hit {
	if len(value) < minLen {
		return nil
	}
	var out []hit
	for _, r := range s.rules {
		if r.id != RuleHexKey {
			continue
		}
		text := normalizeText(name + ": " + value)
		nameLen := len(normalizeText(name))
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			if m[2] < 0 || m[0] >= nameLen { // the keyword must be in the field name
				continue
			}
			v := strings.Trim(text[m[2]:m[3]], `"',;`)
			out = append(out, hit{rule: r.id, value: v, tier: r.tier})
		}
	}
	return out
}

func (s *Scanner) allowed(h hit, collection, path string) bool {
	for _, a := range s.allow {
		if a.rule != h.rule {
			continue
		}
		if a.collection != "" && a.collection != collection {
			continue
		}
		if a.field != "" {
			p := strings.TrimPrefix(path, "/")
			if p != a.field && !strings.HasPrefix(p, a.field+"/") {
				continue
			}
		}
		if a.sha != "" && a.sha != Hash(h.value) {
			continue
		}
		return true
	}
	return false
}

// collector gathers findings for one scan.
type collector struct {
	s          *Scanner
	collection string
	id         string
	seen       map[string]bool
	out        []Finding
	ann        Annotations
	// kind and name, when set, replace the annotation lookup: the schema scan
	// sets them to the property whose default, example or enum it is walking.
	kind, name string
}

func (c *collector) add(h hit, path, in string) {
	if c.s.allowed(h, c.collection, path) {
		return
	}
	f := Finding{Rule: h.rule, Collection: c.collection, ID: c.id, Path: path, Excerpt: Excerpt(h.value), In: in, Tier: h.tier, fp: Hash(h.value)}
	k := f.Rule + "\x00" + f.Path + "\x00" + f.In + "\x00" + f.fp
	if c.seen[k] {
		return
	}
	c.seen[k] = true
	c.out = append(c.out, f)
}

// exemptValue says a confirm-tier finding in text needs no report: an exact
// placeholder, or an annotated field (kind, on a field called name) holding the
// strict format of its kind. An annotation never overrides a secret-named
// field, except secret_reference. This is the one exemption function; it never
// silences the block tier (see text).
func (s *Scanner) exemptValue(text, kind, name string) bool {
	if isPlaceholder(text) {
		return true
	}
	if kind == "" || (kind != KindSecretReference && isSecretName(name)) {
		return false
	}
	return s.validFor(kind, text)
}

// exempt is exemptValue for the string at a data path of a record (or, in a
// schema scan, for the kind and name of the property being scanned).
func (c *collector) exempt(text, path string) bool {
	kind, name := c.kindName(path)
	return c.s.exemptValue(text, kind, name)
}

func (c *collector) kindName(path string) (kind, name string) {
	if c.kind != "" {
		return c.kind, c.name
	}
	return c.ann.kindOf(path), lastName(path)
}

var base64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// blankJWKNumbers empties the n, e, x and y members of a JWK when each is a pure
// base64url string: they are random key numbers that would trip token patterns
// (sk-...) by chance. The values are removed from the original text (a pure
// base64url string appears there literally), not by re-encoding the parsed
// object, so every other member stays exactly as written, duplicates included.
// Text that does not parse as a JSON object is returned as it is.
func blankJWKNumbers(text string) string {
	var m map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(text)), &m) != nil {
		return text
	}
	for _, k := range []string{"n", "e", "x", "y"} {
		if v, ok := m[k].(string); ok && base64URL.MatchString(v) {
			text = strings.ReplaceAll(text, `"`+v+`"`, `""`)
		}
	}
	return text
}

// text scans one string. Block-tier formats are refused in every string,
// always: an exempt string is still run through the block-tier rules, whole.
// Exemption only silences the confirm tier.
func (c *collector) text(text, path, in string, named bool) {
	exempt := in == "" && c.exempt(text, path)
	// a private JWK held as JSON text, whatever its escaping or nesting (block
	// tier, so exempt values too); the parsed value is not parsed again
	if t := strings.TrimSpace(text); t != "" && (t[0] == '{' || t[0] == '[') && c.s.ruleOn(RulePrivateJWK) {
		var v any
		if json.Unmarshal([]byte(t), &v) == nil {
			c.privateJWKs(v, path, in)
		}
	}
	if named && !exempt {
		if h, ok := c.s.namedHit(text); ok {
			c.add(h, path, in)
		}
	}
	scan := text
	if kind, _ := c.kindName(path); exempt && in == "" && kind == KindJWKPublic {
		scan = blankJWKNumbers(text)
	}
	for _, h := range c.s.matches(scan) {
		if exempt && h.tier != TierBlock {
			continue
		}
		if named && h.rule == RuleSecretAssign {
			continue // the whole value was judged already
		}
		c.add(h, path, in)
	}
}

// privateJWKs reports every object at any depth of a parsed JSON value that has
// a "kty" member and a "d" string member of 8 or more characters.
func (c *collector) privateJWKs(v any, path, in string) {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["kty"]; ok {
			if d, ok := x["d"].(string); ok && len(d) >= 8 {
				c.add(hit{rule: RulePrivateJWK, value: d, tier: TierBlock}, path, in)
			}
		}
		for _, e := range x {
			c.privateJWKs(e, path, in)
		}
	case []any:
		for _, e := range x {
			c.privateJWKs(e, path, in)
		}
	}
}

// scalarString renders a number or boolean the way a person would type it.
func scalarString(rv reflect.Value) string {
	switch rv.Kind() {
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(rv.Float(), 'f', -1, 64)
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10)
	}
	return strconv.FormatInt(rv.Int(), 10)
}

// ptr escapes one JSON pointer segment.
func ptr(seg string) string {
	return strings.ReplaceAll(strings.ReplaceAll(seg, "~", "~0"), "/", "~1")
}

// walk scans every string under v. Map keys are scanned too; a key that is
// itself a secret is never put in a path (the path shows "*" instead).
func (c *collector) walk(v any, path string, named bool) {
	switch x := v.(type) {
	case nil:
		return
	case string:
		c.text(x, path, "", named)
		return
	case json.Number:
		if named {
			c.text(x.String(), path, "", true)
		}
		return
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.Bool:
		if named { // numbers and booleans in a secret-named field are scanned as text
			c.text(scalarString(rv), path, "", true)
		}
	case reflect.Map:
		keys := make([]string, 0, rv.Len())
		byKey := map[string]reflect.Value{}
		it := rv.MapRange()
		for it.Next() {
			k := fmt.Sprint(it.Key().Interface())
			keys = append(keys, k)
			byKey[k] = it.Value()
		}
		sort.Strings(keys)
		// a private JWK stored as an object (kty and d members) is block tier wherever it is
		if _, ok := byKey["kty"]; ok {
			if dv, ok := byKey["d"]; ok {
				if d, ok := dv.Interface().(string); ok && len(d) >= 8 && c.s.ruleOn(RulePrivateJWK) {
					c.add(hit{rule: RulePrivateJWK, value: d, tier: TierBlock}, path, "")
				}
			}
		}
		for _, k := range keys {
			seg := ptr(k)
			hs := c.s.matches(k)
			if named { // under a secret-named map the keys are values
				if h, ok := c.s.namedHit(k); ok {
					hs = append(hs, h)
				}
			}
			if len(hs) > 0 {
				for _, h := range hs {
					c.add(h, path, "key")
				}
				seg = "*"
			}
			val := byKey[k].Interface()
			if s, ok := val.(string); ok && !c.exempt(s, path+"/"+seg) {
				for _, h := range c.s.pairMatches(k, s) {
					c.add(h, path+"/"+seg, "")
				}
			}
			// Everything under a field named like a secret counts, strings in
			// lists and maps included.
			c.walk(val, path+"/"+seg, named || isSecretName(k))
		}
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < rv.Len(); i++ {
			c.walk(rv.Index(i).Interface(), path+"/"+strconv.Itoa(i), named)
		}
	case reflect.String:
		c.text(rv.String(), path, "", named)
	}
}

// RedactID is how a record id that carries a secret is shown everywhere: at
// most 4 characters of it and a short hash so that it stays stable and
// distinct (history lookups use it too). The hash is not secure: it only tells
// ids apart.
func RedactID(id string) string { return Excerpt(id) + "~" + Hash(id)[:8] }

// Sensitive reports whether the value of a key field called name would be
// flagged: it matches a rule, or the field is named like a secret.
func (s *Scanner) Sensitive(name, value string) bool {
	s = s.get()
	if !s.enabled || isPlaceholder(value) {
		return false
	}
	if len(s.matches(value)) > 0 || len(s.pairMatches(name, value)) > 0 {
		return true
	}
	if isSecretName(name) {
		_, ok := s.namedHit(value)
		return ok
	}
	return false
}

// safeID keeps a secret that is part of a record id out of a report: an id that
// matches a rule, or that is built from the value of a secret-named top-level
// field, is cut to an excerpt.
func (s *Scanner) safeID(id string, data any) string {
	if len(s.matches(id)) > 0 {
		return RedactID(id)
	}
	if m, ok := data.(map[string]any); ok {
		for k, v := range m {
			if str, ok := v.(string); ok && isSecretName(k) && strings.TrimSpace(str) != "" && (strings.Contains(id, str) || strings.Contains(id, strings.NewReplacer("%", "%25", "/", "%2F").Replace(str))) {
				return RedactID(id)
			}
		}
	}
	return id
}

// ScanRecord scans one record's data. id is the record id (cut to an excerpt
// when it is itself a secret).
func (s *Scanner) ScanRecord(collection, id string, data any) []Finding {
	return s.ScanRecordWith(collection, id, data, nil)
}

// ScanRecordWith is ScanRecord with the schema's public-kind annotations.
func (s *Scanner) ScanRecordWith(collection, id string, data any, ann Annotations) []Finding {
	s = s.get()
	if !s.enabled {
		return nil
	}
	c := &collector{s: s, collection: collection, id: s.safeID(id, data), seen: map[string]bool{}, ann: ann}
	c.walk(data, "", false)
	return c.out
}

// schemaKeys are the keywords of a JSON Schema whose values are data: a default
// or an example is typed in by whoever edits the data type.
var schemaKeys = map[string]bool{"default": true, "examples": true, "example": true, "const": true, "enum": true}

// ScanSchema scans the defaults, examples, constants, enum values, titles and
// descriptions of a JSON Schema document, wherever they are in it, and a
// property's default together with the property's name (a field called password
// with a default). Paths start
// with "/schema" so that they read the same in check output and allow entries.
func (s *Scanner) ScanSchema(collection string, schema []byte) []Finding {
	s = s.get()
	if !s.enabled {
		return nil
	}
	var doc any
	dec := json.NewDecoder(strings.NewReader(string(schema)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil
	}
	c := &collector{s: s, collection: collection, seen: map[string]bool{}}
	var visit func(v any, path, name string)
	visit = func(v any, path, name string) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			kind := ""
			if xr, ok := x["x-rackbook"].(map[string]any); ok {
				kind, _ = xr["public"].(string)
			}
			if props, ok := x["properties"].(map[string]any); ok { // a property called password with a default
				for pname, p := range props {
					pm, ok := p.(map[string]any)
					if !ok {
						continue
					}
					pk := ""
					if xr, ok := pm["x-rackbook"].(map[string]any); ok {
						pk, _ = xr["public"].(string)
					}
					d, ok := pm["default"].(string)
					if !ok || s.exemptValue(d, pk, pname) {
						continue // the default is walked below in any case, block tier included
					}
					dp := path + "/properties/" + ptr(pname) + "/default"
					for _, h := range s.pairMatches(pname, d) {
						c.add(h, dp, "")
					}
					if isSecretName(pname) {
						c.walk(d, dp, true)
					}
				}
			}
			for _, k := range keys {
				switch {
				case k == "title" || k == "description":
					if str, ok := x[k].(string); ok {
						c.text(str, path+"/"+ptr(k), "", false)
						continue
					}
					visit(x[k], path+"/"+ptr(k), name)
				case schemaKeys[k]:
					// a default, example or enum is scanned under its property's
					// annotation, which silences the confirm tier only
					c.kind, c.name = kind, name
					c.walk(x[k], path+"/"+ptr(k), false)
					c.kind, c.name = "", ""
				case k == "properties":
					if props, ok := x[k].(map[string]any); ok {
						names := make([]string, 0, len(props))
						for n := range props {
							names = append(names, n)
						}
						sort.Strings(names)
						for _, n := range names {
							visit(props[n], path+"/properties/"+ptr(n), n)
						}
						continue
					}
					visit(x[k], path+"/"+ptr(k), name)
				default:
					visit(x[k], path+"/"+ptr(k), name)
				}
			}
		case []any:
			for i, e := range x {
				visit(e, path+"/"+strconv.Itoa(i), name)
			}
		}
	}
	visit(doc, "/schema", "")
	// block tier everywhere: every key and every string of the document, whatever
	// the keyword ($comment, pattern, a property name); the walk above has
	// already added what it found, and c.add drops the duplicates
	var blockPass func(v any, path string)
	blockPass = func(v any, path string) {
		switch x := v.(type) {
		case string:
			c.blockOnly(x, path, "")
		case map[string]any:
			for k, e := range x {
				c.blockOnly(k, path, "key")
				blockPass(e, path+"/"+ptr(k))
			}
		case []any:
			for i, e := range x {
				blockPass(e, path+"/"+strconv.Itoa(i))
			}
		}
	}
	blockPass(doc, "/schema")
	return c.out
}

// blockOnly adds the block-tier findings of one string.
func (c *collector) blockOnly(text, path, in string) {
	for _, h := range c.s.matches(text) {
		if h.tier == TierBlock {
			c.add(h, path, in)
		}
	}
}

// ScanYAML scans every value of a YAML file the way a record is scanned. It is
// for files Rackbook rewrites as a whole (rackbook.yml, data files); callers use
// Introduced against the old content so that what was already there is not
// refused.
func (s *Scanner) ScanYAML(rel string, content []byte) []Finding {
	s = s.get()
	if !s.enabled {
		return nil
	}
	var doc any
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil
	}
	c := &collector{s: s, collection: rel, seen: map[string]bool{}}
	c.walk(doc, "", false)
	return c.out
}

// stateLabels are the fields of Rackbook's state files (.rackbook/*.yml) that
// hold text a person chose. Everything else in them is a public key, an id or a
// hash by design and is not scanned.
var stateLabels = map[string]bool{"name": true, "identity": true, "created_by": true, "revoked_by": true}

// ScanState scans the label fields of a state file (passkeys, tokens). rel is
// the file path, reported as the collection.
func (s *Scanner) ScanState(rel string, content []byte) []Finding {
	s = s.get()
	if !s.enabled {
		return nil
	}
	var doc any
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil
	}
	c := &collector{s: s, collection: rel, seen: map[string]bool{}}
	var visit func(v any, path string)
	visit = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if str, ok := x[k].(string); ok {
					if stateLabels[k] {
						c.text(str, path+"/"+ptr(k), "", false)
					}
					continue
				}
				visit(x[k], path+"/"+ptr(k))
			}
		case []any:
			for i, e := range x {
				visit(e, path+"/"+strconv.Itoa(i))
			}
		}
	}
	visit(doc, "")
	return c.out
}

// Introduced returns the findings in after that are not in before: the same
// rule on the same collection with the same value, wherever in the record. (The
// position is left out on purpose: removing an entry from a list moves the
// others.) Used where the scan must not block a change over something that was
// already there.
func Introduced(before, after []Finding) []Finding {
	seen := map[string]bool{}
	key := func(f Finding) string {
		return f.Rule + "\x00" + f.Collection + "\x00" + f.In + "\x00" + f.fp
	}
	for _, f := range before {
		seen[key(f)] = true
	}
	var out []Finding
	for _, f := range after {
		if !seen[key(f)] {
			out = append(out, f)
		}
	}
	return out
}
