// Package validate checks a loaded ledger: JSON Schema per record, key
// uniqueness, and the cross-collection rules from rackbook.yml.
package validate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

var printer = message.NewPrinter(language.English)

// Run returns every problem in the ledger: load issues first, then schema,
// unique, ref and same_set findings. The order is deterministic.
func Run(l *ledger.Ledger) []ledger.Issue { return RunWith(l, Options{}) }

// Options adjusts RunWith.
type Options struct {
	// Confirmed says an editor confirmed "this is not a secret" for the record in
	// the last commit that changed it; its confirm-tier secret findings are then
	// not reported at all.
	Confirmed func(collection, id string) bool
}

// Split separates errors from warnings.
func Split(issues []ledger.Issue) (errs, warns []ledger.Issue) {
	errs, warns = []ledger.Issue{}, []ledger.Issue{}
	for _, i := range issues {
		if i.Warning() {
			warns = append(warns, i)
		} else {
			errs = append(errs, i)
		}
	}
	return
}

// RunWith is Run with options.
func RunWith(l *ledger.Ledger, o Options) []ledger.Issue {
	issues := append([]ledger.Issue{}, l.Issues...)
	for _, c := range l.Collections {
		issues = append(issues, keyIssues(c)...)
		issues = append(issues, schemaIssues(c)...)
		issues = append(issues, uniqueIssues(c, c.Key, true)...)
		issues = append(issues, secretIssues(l, c, o)...)
	}
	issues = append(issues, stateSecretIssues(l)...)
	for _, r := range l.Config.Rules {
		switch {
		case r.Unique != nil:
			if c := l.Collection(r.Unique.Collection); c != nil {
				issues = append(issues, uniqueIssues(c, r.Unique.Fields, false)...)
			}
		case r.Ref != nil:
			issues = append(issues, refIssues(l, r.Ref)...)
		case r.SameSet != nil:
			issues = append(issues, sameSetIssues(l, r.SameSet)...)
		}
	}
	// An id that carries a secret is never shown, whatever the kind of issue.
	for i := range issues {
		if issues[i].ID != "" && issues[i].Collection != "" {
			issues[i].ID = ledger.SafeID(l.Config, issues[i].Collection, issues[i].ID)
		}
	}
	return issues
}

func secretIssue(f secretscan.Finding, c *ledger.Collection, hash string) ledger.Issue {
	i := ledger.Issue{Collection: c.Name, ID: f.ID, Path: f.Path, Rule: ledger.RuleSecret, Message: f.Message(), Hash: hash}
	if f.Tier == secretscan.TierConfirm {
		i.Severity = "warning"
	}
	return i
}

// secretIssues reports secrets that are already in the data (hand-committed,
// or from before the scan existed), with the same redaction as a refused write.
// Block-tier findings are errors; confirm-tier ones are warnings, and are left
// out when the record's last commit carries a confirmation.
func secretIssues(l *ledger.Ledger, c *ledger.Collection, o Options) []ledger.Issue {
	sc := l.Config.SecretScanner()
	if !sc.Enabled() {
		return nil
	}
	var out []ledger.Issue
	ann := secretscan.AnnotationsOf(c.SchemaRaw)
	for _, r := range c.Records {
		id := ledger.SafeID(l.Config, c.Name, r.ID)
		for _, f := range sc.ScanRecordWith(c.Name, id, r.Data, ann) {
			i := secretIssue(f, c, r.Hash)
			if i.Warning() && o.Confirmed != nil && o.Confirmed(c.Name, i.ID) {
				continue
			}
			out = append(out, i)
		}
	}
	if c.SchemaRaw != nil {
		for _, f := range sc.ScanSchema(c.Name, c.SchemaRaw) {
			i := secretIssue(f, c, "")
			i.ID = ""
			out = append(out, i)
		}
	}
	return out
}

// stateSecretIssues scans the names and labels in .rackbook/*.yml (passkeys,
// tokens); the public keys and hashes in them are by design not secrets.
func stateSecretIssues(l *ledger.Ledger) []ledger.Issue {
	sc := l.Config.SecretScanner()
	if !sc.Enabled() {
		return nil
	}
	dir := filepath.Join(l.Config.Dir, config.StateDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []ledger.Issue
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		p := filepath.Join(dir, name)
		if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel := config.StateDir + "/" + name
		for _, f := range sc.ScanState(rel, b) {
			i := ledger.Issue{Collection: rel, Path: f.Path, Rule: ledger.RuleSecret, Message: f.Message()}
			if f.Tier == secretscan.TierConfirm {
				i.Severity = "warning"
			}
			out = append(out, i)
		}
	}
	return out
}

var lineRe = regexp.MustCompile(`line \d+`)

type issueKey struct{ collection, rule, path, message, who string }

// Introduced returns the issues in after that are not already present in
// before. An issue is already present when the same message exists on the same
// record id or on a record with the same content hash (keyless collections
// address records by position, so their ids shift when a record is deleted).
// Line numbers in yaml issues are ignored. Secret findings are never "introduced".
func Introduced(before, after []ledger.Issue) []ledger.Issue {
	norm := func(i ledger.Issue) string {
		if i.Rule == ledger.RuleYAML {
			return lineRe.ReplaceAllString(i.Message, "line N")
		}
		return i.Message
	}
	seen := map[issueKey]bool{}
	for _, i := range before {
		seen[issueKey{i.Collection, i.Rule, i.Path, norm(i), "id:" + i.ID}] = true
		if i.Hash != "" {
			seen[issueKey{i.Collection, i.Rule, i.Path, norm(i), "hash:" + i.Hash}] = true
		}
	}
	out := []ledger.Issue{}
	for _, i := range after {
		// Secrets are the secret scan's to refuse, on the data being written. An
		// old one in a record that a change merely touched (its id or hash moves)
		// is for `check` to report, not a reason to refuse the change.
		if i.Rule == ledger.RuleSecret {
			continue
		}
		if seen[issueKey{i.Collection, i.Rule, i.Path, norm(i), "id:" + i.ID}] {
			continue
		}
		if i.Hash != "" && seen[issueKey{i.Collection, i.Rule, i.Path, norm(i), "hash:" + i.Hash}] {
			continue
		}
		out = append(out, i)
	}
	return out
}

// keyIssues rejects key values that cannot be used safely in ids, URLs,
// commit subjects and log lines: control characters, "." and "..".
func keyIssues(c *ledger.Collection) []ledger.Issue {
	var out []ledger.Issue
	for _, r := range c.Records {
		for _, k := range c.Key {
			v := ledger.Str(r.Data[k])
			bad := v == "." || v == ".."
			for _, ch := range v {
				if ch < 0x20 || ch == 0x7f {
					bad = true
				}
			}
			if bad {
				out = append(out, ledger.Issue{Collection: c.Name, ID: r.ID, Path: "/" + k, Rule: ledger.RuleSchema, Hash: r.Hash,
					Message: `key fields must not be "." or ".." or contain control characters (including newlines)`})
			}
		}
	}
	return out
}

func schemaIssues(c *ledger.Collection) []ledger.Issue {
	if c.SchemaRaw == nil || len(c.Records) == 0 {
		return nil
	}
	sch, err := compile(c)
	if err != nil {
		return []ledger.Issue{{Collection: c.Name, Rule: ledger.RuleConfig, Message: fmt.Sprintf("schema %s: %v", c.Collection.Schema, err)}}
	}
	var out []ledger.Issue
	for _, r := range c.Records {
		err := sch.Validate(r.Data)
		if err == nil {
			continue
		}
		verr, ok := err.(*jsonschema.ValidationError)
		if !ok {
			out = append(out, ledger.Issue{Collection: c.Name, ID: r.ID, Rule: ledger.RuleSchema, Hash: r.Hash, Message: err.Error()})
			continue
		}
		seen := map[string]bool{}
		for _, leaf := range leaves(verr) {
			path := "/" + strings.Join(escapeTokens(leaf.InstanceLocation), "/")
			if len(leaf.InstanceLocation) == 0 {
				path = ""
			}
			msg := leaf.ErrorKind.LocalizedString(printer)
			if key := path + "\x00" + msg; !seen[key] {
				seen[key] = true
				out = append(out, ledger.Issue{Collection: c.Name, ID: r.ID, Path: path, Rule: ledger.RuleSchema, Hash: r.Hash, Message: msg})
			}
		}
	}
	return out
}

func compile(c *ledger.Collection) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(c.SchemaRaw))
	if err != nil {
		return nil, err
	}
	comp := jsonschema.NewCompiler()
	registerFormats(comp)
	url := "mem:///" + c.Name + ".json"
	if err := comp.AddResource(url, doc); err != nil {
		return nil, err
	}
	return comp.Compile(url)
}

func leaves(e *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(e.Causes) == 0 {
		return []*jsonschema.ValidationError{e}
	}
	var out []*jsonschema.ValidationError
	for _, c := range e.Causes {
		out = append(out, leaves(c)...)
	}
	return out
}

func escapeTokens(t []string) []string {
	out := make([]string, len(t))
	for i, s := range t {
		out[i] = strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
	}
	return out
}

// uniqueIssues flags records sharing the same values for fields. implicit
// marks the uniqueness implied by a collection's key.
func uniqueIssues(c *ledger.Collection, fields []string, implicit bool) []ledger.Issue {
	if len(fields) == 0 {
		return nil
	}
	seen := map[string]*ledger.Record{}
	var out []ledger.Issue
	for _, r := range c.Records {
		parts := make([]string, len(fields))
		for i, f := range fields {
			parts[i] = strconv.Quote(ledger.Str(r.Data[f]))
		}
		k := strings.Join(parts, "/")
		if _, dup := seen[k]; dup {
			what := "key"
			if !implicit {
				what = "values"
			}
			out = append(out, ledger.Issue{
				Collection: c.Name, ID: r.ID, Path: "/" + fields[0], Rule: ledger.RuleUnique, Hash: r.Hash,
				Message: fmt.Sprintf("duplicate %s %s (%s)", what, strings.Join(parts, " / "), strings.Join(fields, "+")),
			})
			continue
		}
		seen[k] = r
	}
	return out
}

func refIssues(l *ledger.Ledger, rule *config.RefRule) []ledger.Issue {
	fc, ff, _ := config.SplitRef(rule.From)
	tc, tf, _ := config.SplitRef(rule.To)
	from, to := l.Collection(fc), l.Collection(tc)
	if from == nil || to == nil {
		return nil
	}
	targets := map[string]bool{}
	for _, r := range to.Records {
		targets[ledger.Str(r.Data[tf])] = true
	}
	allow := map[string]bool{}
	for _, a := range rule.Allow {
		allow[a] = true
	}
	var out []ledger.Issue
	for _, r := range from.Records {
		v, ok := r.Data[ff]
		if !ok || v == nil {
			continue
		}
		check := func(x any, path string) {
			s := ledger.Str(x)
			if allow[s] || targets[s] {
				return
			}
			msg := fmt.Sprintf("unknown %s.%s %q", tc, tf, s)
			if rule.Message != "" {
				msg = rule.Message + ": " + msg
			}
			out = append(out, ledger.Issue{Collection: fc, ID: r.ID, Path: path, Rule: ledger.RuleRef, Hash: r.Hash, Message: msg})
		}
		if list, isList := v.([]any); isList && rule.Many {
			for i, x := range list {
				check(x, "/"+ff+"/"+strconv.Itoa(i))
			}
			continue
		}
		check(v, "/"+ff)
	}
	return out
}

func sameSetIssues(l *ledger.Ledger, rule *config.SameSetRule) []ledger.Issue {
	left := l.Collection(rule.Left.Collection)
	if left == nil {
		return nil
	}
	msg := rule.Message
	if msg == "" {
		msg = fmt.Sprintf("%s.%s must equal %s %s", rule.Left.Collection, rule.Left.Field, rule.Right.File, rule.Right.Path)
	}
	leftSet := map[string]*ledger.Record{}
	var leftOrder []string
	for _, r := range left.Records {
		if !whereMatches(r, rule.Left.Where) {
			continue
		}
		v := ledger.Str(r.Data[rule.Left.Field])
		if _, dup := leftSet[v]; !dup {
			leftSet[v] = r
			leftOrder = append(leftOrder, v)
		}
	}
	right, err := rightSet(l, rule.Right)
	if err != nil {
		return []ledger.Issue{{Collection: rule.Left.Collection, Rule: ledger.RuleSameSet, Message: msg + ": " + err.Error()}}
	}
	var out []ledger.Issue
	for _, v := range leftOrder {
		if !right[v] {
			r := leftSet[v]
			out = append(out, ledger.Issue{Collection: left.Name, ID: r.ID, Path: "/" + rule.Left.Field, Rule: ledger.RuleSameSet, Hash: r.Hash,
				Message: fmt.Sprintf("%s: %q is in %s but not in %s %s", msg, v, left.Name, rule.Right.File, rule.Right.Path)})
		}
	}
	var onlyRight []string
	for v := range right {
		if _, ok := leftSet[v]; !ok {
			onlyRight = append(onlyRight, v)
		}
	}
	sort.Strings(onlyRight)
	for _, v := range onlyRight {
		out = append(out, ledger.Issue{Collection: left.Name, Rule: ledger.RuleSameSet,
			Message: fmt.Sprintf("%s: %q is in %s %s but has no matching %s record", msg, v, rule.Right.File, rule.Right.Path, left.Name)})
	}
	return out
}

func whereMatches(r *ledger.Record, where map[string]any) bool {
	for k, want := range where {
		if ledger.Str(r.Data[k]) != ledger.Str(want) {
			return false
		}
	}
	return true
}

func rightSet(l *ledger.Ledger, r config.SameSetRight) (map[string]bool, error) {
	b, err := l.ReadFile(r.File)
	if err != nil {
		return nil, err
	}
	doc, err := yamledit.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.File, err)
	}
	n, ok := doc.Lookup(r.Path)
	if !ok {
		return nil, fmt.Errorf("%s has no %s", r.File, r.Path)
	}
	set := map[string]bool{}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if r.Take == "values" {
				set[ledger.Str(yamledit.Value(n.Content[i+1]))] = true
			} else {
				set[n.Content[i].Value] = true
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			set[ledger.Str(yamledit.Value(c))] = true
		}
	case yaml.ScalarNode:
		if n.Tag != "!!null" {
			return nil, fmt.Errorf("%s %s is a scalar, expected a mapping or list", r.File, r.Path)
		}
	}
	return set, nil
}
