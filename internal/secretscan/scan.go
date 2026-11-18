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
// the other fields must narrow it. Field is a JSON pointer inside the record
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

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("secret detected, nothing was written:")
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
		r := &rule{id: p.ID, description: p.Description, re: re}
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
}

// matches runs every rule over text.
func (s *Scanner) matches(text string) []hit {
	if len(text) < s.minLen {
		return nil
	}
	var out []hit
	for _, r := range s.rules {
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			g := r.group
			if m[2*g] < 0 { // an optional group that did not take part: the whole match
				g = 0
			}
			value := text[m[2*g]:m[2*g+1]]
			if g > 0 {
				value = strings.Trim(value, `"',;`)
			}
			if r.accept != nil && !r.accept(value, text[:m[0]]) {
				continue
			}
			out = append(out, hit{r.id, value})
		}
	}
	return out
}

// pairMatches runs the two assignment rules over "name: value" for a field
// name and its string value, so that a field called password is caught.
func (s *Scanner) pairMatches(name, value string) []hit {
	if len(value) < minLen {
		return nil
	}
	var out []hit
	for _, r := range s.rules {
		if r.id != RuleSecretAssign && r.id != RuleHexKey {
			continue
		}
		text := name + ": " + value
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			if m[2] < 0 || m[0] >= len(name) { // the keyword must be in the field name
				continue
			}
			v := strings.Trim(text[m[2]:m[3]], `"',;`)
			if r.accept != nil && !r.accept(v, text[:m[0]]) {
				continue
			}
			out = append(out, hit{r.id, v})
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
}

func (c *collector) add(h hit, path, in string) {
	if c.s.allowed(h, c.collection, path) {
		return
	}
	f := Finding{Rule: h.rule, Collection: c.collection, ID: c.id, Path: path, Excerpt: Excerpt(h.value), In: in, fp: Hash(h.value)}
	k := f.Rule + "\x00" + f.Path + "\x00" + f.In + "\x00" + f.fp
	if c.seen[k] {
		return
	}
	c.seen[k] = true
	c.out = append(c.out, f)
}

func (c *collector) text(text, path, in string) {
	for _, h := range c.s.matches(text) {
		c.add(h, path, in)
	}
}

// ptr escapes one JSON pointer segment.
func ptr(seg string) string {
	return strings.ReplaceAll(strings.ReplaceAll(seg, "~", "~0"), "/", "~1")
}

// walk scans every string under v. Map keys are scanned too; a key that is
// itself a secret is never put in a path (the path shows "*" instead).
func (c *collector) walk(v any, path string) {
	switch x := v.(type) {
	case nil:
		return
	case string:
		c.text(x, path, "")
		return
	case json.Number:
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
		for _, k := range keys {
			seg := ptr(k)
			if hs := c.s.matches(k); len(hs) > 0 {
				for _, h := range hs {
					c.add(h, path, "key")
				}
				seg = "*"
			}
			val := byKey[k].Interface()
			if s, ok := val.(string); ok {
				for _, h := range c.s.pairMatches(k, s) {
					c.add(h, path+"/"+seg, "")
				}
			}
			c.walk(val, path+"/"+seg)
		}
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < rv.Len(); i++ {
			c.walk(rv.Index(i).Interface(), path+"/"+strconv.Itoa(i))
		}
	case reflect.String:
		c.text(rv.String(), path, "")
	}
}

// safeID keeps a secret that is part of a record id out of a report.
func (s *Scanner) safeID(id string) string {
	if len(s.matches(id)) > 0 {
		return Excerpt(id)
	}
	return id
}

// ScanRecord scans one record's data. id is the record id (cut to an excerpt
// when it is itself a secret).
func (s *Scanner) ScanRecord(collection, id string, data any) []Finding {
	s = s.get()
	if !s.enabled {
		return nil
	}
	c := &collector{s: s, collection: collection, id: s.safeID(id), seen: map[string]bool{}}
	c.walk(data, "")
	return c.out
}

// schemaKeys are the keywords of a JSON Schema whose values are data: a default
// or an example is typed in by whoever edits the data type. Titles and
// descriptions are help text and are not scanned.
var schemaKeys = map[string]bool{"default": true, "examples": true, "example": true, "const": true, "enum": true}

// ScanSchema scans the defaults, examples, constants and enum values of a JSON
// Schema document, wherever they are in it, and a property's default together
// with the property's name (a field called password with a default). Paths start
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
	var visit func(v any, path string)
	visit = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if props, ok := x["properties"].(map[string]any); ok { // a property called password with a default
				for name, p := range props {
					if pm, ok := p.(map[string]any); ok {
						if d, ok := pm["default"].(string); ok {
							for _, h := range s.pairMatches(name, d) {
								c.add(h, path+"/properties/"+ptr(name)+"/default", "")
							}
						}
					}
				}
			}
			for _, k := range keys {
				if schemaKeys[k] {
					c.walk(x[k], path+"/"+ptr(k))
				} else {
					visit(x[k], path+"/"+ptr(k))
				}
			}
		case []any:
			for i, e := range x {
				visit(e, path+"/"+strconv.Itoa(i))
			}
		}
	}
	visit(doc, "/schema")
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
						c.text(str, path+"/"+ptr(k), "")
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
