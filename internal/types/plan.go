package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/labels"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/locale"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// Operation kinds.
const (
	OpCreate = "create"
	OpUpdate = "update"
	OpDelete = "delete"
)

// Migration kinds: changes to existing records that make a type change valid.
const (
	MigRemoveField = "remove-field" // delete a removed field from the records that have it
	MigFillDefault = "fill-default" // give a new required field a value in the records that lack it
)

// Request is what the console asks for: the wanted type and the migrations it
// chose. Name is the collection (for create, the new name).
type Request struct {
	Op         string      `json:"op"`
	Name       string      `json:"name"`
	Type       *Type       `json:"type,omitempty"`
	Migrations []Migration `json:"migrations,omitempty"`
	// Version is the base version of an update or delete (see Type.Version).
	Version string `json:"version,omitempty"`
}

// Migration is a chosen migration.
type Migration struct {
	Kind  string `json:"kind"`
	Field string `json:"field"`
	Value any    `json:"value,omitempty"` // fill-default: the value (else the field's default)
}

// Offer is a migration the plan found useful.
type Offer struct {
	Kind    string   `json:"kind"`
	Field   string   `json:"field"`
	Count   int      `json:"count"`
	Records []string `json:"records"` // ids, at most 20
	Default any      `json:"default,omitempty"`
	Applied bool     `json:"applied"`
}

// Refusal is a change the planner will not make.
type Refusal struct {
	Code    string   `json:"code"`
	Field   string   `json:"field,omitempty"`
	Message string   `json:"message"`
	Records []string `json:"records,omitempty"` // offending record ids, at most 20
	Count   int      `json:"count,omitempty"`
}

// FileChange is one file of the commit.
type FileChange struct {
	Path   string `json:"path"`
	Status string `json:"status"` // added | modified | removed
	Diff   string `json:"diff"`   // unified
}

// BackrefChange says a collection gains or loses a back-reference section.
type BackrefChange struct {
	Collection string `json:"collection"` // the target
	From       string `json:"from"`       // collection.field that points at it
	Change     string `json:"change"`     // gained | lost
}

// Plan is the dry run of a type change.
type Plan struct {
	Op      string `json:"op"`
	Name    string `json:"name"`
	Clean   bool   `json:"clean"` // the change can be saved
	Changed bool   `json:"changed"`
	Subject string `json:"subject"`

	Files      []FileChange    `json:"files"`
	Invalid    []ledger.Issue  `json:"invalid"`  // records that would stop matching the schema
	Dangling   []ledger.Issue  `json:"dangling"` // references that would point nowhere
	Other      []ledger.Issue  `json:"other"`    // unique, config and the like
	Backrefs   []BackrefChange `json:"backrefs"`
	Migrations []Offer         `json:"migrations"`
	Refusals   []Refusal       `json:"refusals"`
	Type       *Type           `json:"type,omitempty"` // the type as it would be saved
	Truncated  bool            `json:"truncated,omitempty"`

	// internal
	files   map[string][]byte // new content; nil = delete
	subject string
}

// String renders the plan as JSON (for logs and test failures).
func (p *Plan) String() string {
	b, _ := json.MarshalIndent(p, "", " ")
	return string(b)
}

const maxList = 200

// PlanError is returned by Apply when the plan is not clean.
type PlanError struct{ Plan *Plan }

func (e *PlanError) Error() string {
	var parts []string
	for _, r := range e.Plan.Refusals {
		parts = append(parts, r.Message)
	}
	for _, i := range e.Plan.Invalid {
		parts = append(parts, i.String())
		if len(parts) > 5 {
			break
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "the change would make the ledger invalid")
	}
	return "the type change is refused: " + strings.Join(parts, "; ")
}

// ErrUnknownType means the named collection does not exist.
var ErrUnknownType = errors.New("unknown data type")

var (
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	fieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
)

// Load reads the Type of a collection.
func Load(l *ledger.Ledger, name string) (*Type, error) {
	c := l.Collection(name)
	if c == nil {
		return nil, fmt.Errorf("%w %q", ErrUnknownType, name)
	}
	t, err := ParseType(c.Collection, c.SchemaRaw, l.Config.Rules, len(c.Records))
	if err != nil {
		return nil, err
	}
	t.Version = versionOf(t, c.SchemaRaw)
	return t, nil
}

// versionOf hashes what a type edit starts from: the schema bytes, the
// collection's entry in rackbook.yml and the rules that mention it. The record
// count is not part of it, so record edits do not make a type stale.
func versionOf(t *Type, schemaRaw []byte) string {
	rules, _ := json.Marshal(t.Rules())
	h := sha256.New()
	h.Write(schemaRaw)
	h.Write([]byte{0})
	h.Write([]byte(canonJSON(entryValues(t))))
	h.Write([]byte{0})
	h.Write(rules)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// VersionError means the type changed since the caller read it.
type VersionError struct{ Current *Type }

func (e *VersionError) Error() string {
	return "the data type changed since you opened it; reload it and apply your change again"
}

// baseVersion is the version the request starts from: Version, else the one
// carried by the type it sends.
func (r Request) baseVersion() string {
	if r.Version != "" {
		return r.Version
	}
	if r.Type != nil {
		return r.Type.Version
	}
	return ""
}

// checkVersion refuses a request whose base version is not the current one.
func checkVersion(req Request, cur *Type) error {
	if v := req.baseVersion(); v != "" && v != cur.Version {
		return &VersionError{Current: cur}
	}
	return nil
}

// Build plans req against the files under cfg.Dir without touching them.
func Build(cfg *config.Config, req Request) (*Plan, error) {
	base := ledger.Load(cfg, nil)
	p := &Plan{Op: req.Op, Name: req.Name, files: map[string][]byte{},
		Files: []FileChange{}, Invalid: []ledger.Issue{}, Dangling: []ledger.Issue{}, Other: []ledger.Issue{},
		Backrefs: []BackrefChange{}, Migrations: []Offer{}, Refusals: []Refusal{}}
	var err error
	switch req.Op {
	case OpCreate:
		err = planCreate(base, req, p)
	case OpUpdate:
		err = planUpdate(base, req, p)
	case OpDelete:
		err = planDelete(base, req, p)
	default:
		return nil, fmt.Errorf("unknown operation %q", req.Op)
	}
	if err != nil {
		return nil, err
	}
	p.finish(base)
	return p, nil
}

func (p *Plan) refuse(code, field, format string, a ...any) {
	p.Refusals = append(p.Refusals, Refusal{Code: code, Field: field, Message: fmt.Sprintf(format, a...)})
}

// finish computes file diffs and the verdict.
func (p *Plan) finish(base *ledger.Ledger) {
	paths := make([]string, 0, len(p.files))
	for f := range p.files {
		paths = append(paths, f)
	}
	sort.Strings(paths)
	cfgRel := configRel(base.Config)
	sort.SliceStable(paths, func(i, j int) bool { return paths[i] == cfgRel && paths[j] != cfgRel })
	for _, f := range paths {
		old, _ := base.ReadFile(f)
		nw := p.files[f]
		status := "modified"
		switch {
		case nw == nil:
			status = "removed"
		case old == nil:
			status = "added"
		}
		p.Files = append(p.Files, FileChange{Path: f, Status: status, Diff: unifiedDiff(f, string(old), string(nw))})
	}
	for _, f := range paths {
		if b := p.files[f]; b != nil && strings.HasSuffix(f, ".json") {
			for _, msg := range secretscan.AnnotationProblems(b) {
				p.refuse("annotation", "", "%s: %s", f, msg)
			}
		}
	}
	p.Changed = len(p.files) > 0
	p.Clean = len(p.Refusals) == 0 && len(p.Invalid) == 0 && len(p.Dangling) == 0 && len(p.Other) == 0
	p.Subject = p.subject
}

func configRel(cfg *config.Config) string {
	rel, err := filepath.Rel(cfg.Dir, cfg.Path)
	if err != nil {
		return filepath.Base(cfg.Path)
	}
	return filepath.ToSlash(rel)
}

// readConfig returns the current text of rackbook.yml.
func readConfig(cfg *config.Config) ([]byte, error) { return os.ReadFile(cfg.Path) }

// sharedSchema lists the other collections that use the same schema file.
func sharedSchema(cfg *config.Config, name, schema string) []string {
	var out []string
	for _, c := range cfg.Collections {
		if c.Name != name && c.Schema == schema {
			out = append(out, c.Name)
		}
	}
	return out
}

// ---- validation of the wanted type -------------------------------------

func checkType(l *ledger.Ledger, old, nt *Type, p *Plan) {
	if strings.TrimSpace(nt.Title) == "" {
		p.refuse("invalid", "", "the title must not be empty")
	}
	if len(nt.Fields) == 0 {
		p.refuse("invalid", "", "a data type needs at least one field")
	}
	checkTexts(p, "", "the type's translations", nt.I18n, "title", "description", "group")
	seen := map[string]bool{}
	for i := range nt.Fields {
		f := &nt.Fields[i]
		if seen[f.Name] {
			p.refuse("invalid", f.Name, "field %q appears twice", f.Name)
		}
		seen[f.Name] = true
		of := (*Field)(nil)
		if old != nil {
			of = old.Field(f.Name)
		}
		if of == nil && !fieldRe.MatchString(f.Name) {
			p.refuse("invalid", f.Name, "field name %q: use letters, digits, _ and -, starting with a letter or _", f.Name)
		}
		checkField(l, nt, f, of, p)
	}
	has := func(name string) bool { return seen[name] }
	for _, k := range nt.Key {
		if !has(k) {
			p.refuse("invalid", k, "key field %q is not a field of this type", k)
		}
	}
	if nt.Label != "" && !has(nt.Label) {
		p.refuse("invalid", nt.Label, "label field %q is not a field of this type", nt.Label)
	}
	for _, k := range nt.List {
		if !has(k) {
			p.refuse("invalid", k, "list column %q is not a field of this type", k)
		}
	}
	for _, f := range nt.Facets {
		if !has(f.Field) {
			p.refuse("invalid", f.Field, "facet field %q is not a field of this type", f.Field)
		}
		switch f.Match {
		case "", "exact", "contains", "prefix":
		default:
			p.refuse("invalid", f.Field, "facet %q: unknown match %q", f.Field, f.Match)
		}
	}
	for _, u := range nt.Unique {
		if len(u) < 2 {
			p.refuse("invalid", "", "a unique rule over several fields needs at least two fields")
		}
		for _, k := range u {
			if !has(k) {
				p.refuse("invalid", k, "unique rule field %q is not a field of this type", k)
			}
		}
	}
	if old != nil {
		for _, mine := range [][2]string{{"file", old.File}, {"path", old.Path}, {"schemaFile", old.SchemaFile}} {
			got := map[string]string{"file": nt.File, "path": nt.Path, "schemaFile": nt.SchemaFile}[mine[0]]
			if got != mine[1] {
				p.refuse("layout", "", "the data file, path and schema file are fixed once a type exists (%s)", mine[0])
			}
		}
	}
}

func checkField(l *ledger.Ledger, t *Type, f *Field, old *Field, p *Plan) {
	ok := false
	for _, ty := range FieldTypes {
		ok = ok || ty == f.Type
	}
	if f.Type == TAdvanced && old != nil && old.Type == TAdvanced {
		ok = true
	}
	if !ok {
		p.refuse("invalid", f.Name, "field %q: unknown type %q", f.Name, f.Type)
		return
	}
	if f.Type == TAdvanced && f.Ref != nil && old != nil && old.Ref == nil {
		p.refuse("invalid", f.Name, "field %q: a reference needs the reference type", f.Name)
	}
	if f.Type == TRef && f.Ref == nil {
		p.refuse("invalid", f.Name, "field %q: a reference field needs a target", f.Name)
	}
	if f.Type != TRef && f.Type != TAdvanced && f.Ref != nil {
		f.Ref = nil
	}
	if f.Ref != nil {
		target := t
		if f.Ref.To != t.Name {
			c := l.Collection(f.Ref.To)
			if c == nil {
				p.refuse("invalid", f.Name, "field %q: unknown target collection %q", f.Name, f.Ref.To)
				return
			}
			tt, err := ParseType(c.Collection, c.SchemaRaw, nil, 0)
			if err != nil {
				p.refuse("invalid", f.Name, "field %q: %v", f.Name, err)
				return
			}
			target = tt
		}
		if f.Ref.ToField == "" {
			if len(target.Key) > 0 {
				f.Ref.ToField = target.Key[0]
			}
		}
		if target.Field(f.Ref.ToField) == nil {
			p.refuse("invalid", f.Name, "field %q: %q has no field %q", f.Name, f.Ref.To, f.Ref.ToField)
		}
	}
	if hasExtra(f.Extras, kwI18n) && old != nil && translationsChanged(old, f) {
		p.refuse("invalid", f.Name, "x-rackbook-i18n on %s is not in the expected shape; fix it in the schema file or remove it", f.Name)
	}
	checkTexts(p, f.Name, fmt.Sprintf("field %q translations", f.Name), f.I18n, "title", "description")
	if f.Ref != nil {
		checkTexts(p, f.Name, fmt.Sprintf("field %q reference translations", f.Name), f.Ref.I18n, "message", "backref_title")
	}
	if f.Type == TEnum {
		for _, it := range f.Enum {
			if it.Icon != "" && (len(it.Icon) > 64 || !labels.ValidIcon(it.Icon)) {
				p.refuse("invalid", f.Name, "field %q: the icon of %q is not an icon name (lowercase letters, digits and hyphens, up to 64 characters, like circle-check)", f.Name, it.Value)
			}
			for _, l := range sortedKeys(it.Labels) {
				if !labels.Supported(l) {
					p.refuse("invalid", f.Name, "field %q: the label of %q is given for %q, which is not a supported language (use %s)", f.Name, it.Value, l, strings.Join(locale.Supported, ", "))
				}
			}
		}
		if old == nil || !reflect.DeepEqual(old.Enum, f.Enum) {
			checkLabelClashes(p, f)
		}
		if len(f.Enum) == 0 {
			p.refuse("invalid", f.Name, "field %q: an enum needs at least one value", f.Name)
		}
		vals := map[string]bool{}
		for _, it := range f.Enum {
			if it.Value == "" || vals[it.Value] {
				p.refuse("invalid", f.Name, "field %q: enum values must be non-empty and different", f.Name)
				break
			}
			vals[it.Value] = true
		}
	}
	if f.MinLength != nil && f.MaxLength != nil && *f.MinLength > *f.MaxLength {
		p.refuse("invalid", f.Name, "field %q: the minimum length is above the maximum", f.Name)
	}
	if f.Min != nil && f.Max != nil && *f.Min > *f.Max {
		p.refuse("invalid", f.Name, "field %q: the minimum is above the maximum", f.Name)
	}
	if f.Pattern != "" {
		if _, err := regexp.Compile(f.Pattern); err != nil {
			p.refuse("invalid", f.Name, "field %q: the pattern does not compile: %v", f.Name, err)
		}
	}
}

// ---- update --------------------------------------------------------------

func planUpdate(base *ledger.Ledger, req Request, p *Plan) error {
	cfg := base.Config
	col := base.Collection(req.Name)
	if col == nil {
		return fmt.Errorf("%w %q", ErrUnknownType, req.Name)
	}
	if req.Type == nil {
		return errors.New("type is required")
	}
	old, err := Load(base, req.Name)
	if err != nil {
		return err
	}
	if err := checkVersion(req, old); err != nil {
		return err
	}
	nt := normalizeIncoming(*req.Type, old)
	nt.Version = old.Version
	if nt.Name != "" && nt.Name != req.Name {
		p.refuse("rename", "", "renaming a data type is not supported (%q to %q)", req.Name, nt.Name)
	}
	nt.Name = req.Name
	p.Type = nt
	checkType(base, old, nt, p)
	if len(p.Refusals) > 0 {
		return nil
	}
	checkRemovedFieldsInUse(base, old, nt, p)

	// schema and config text
	var schemaRaw []byte
	if col.SchemaRaw != nil {
		schemaRaw = col.SchemaRaw
	}
	newSchema, err := applySchema(schemaRaw, old, nt)
	if err != nil {
		return err
	}
	if schemaRaw != nil && sameSchema(schemaRaw, newSchema) {
		newSchema = schemaRaw
	}
	schemaChanged := string(newSchema) != string(schemaRaw)
	if schemaChanged {
		if others := sharedSchema(cfg, req.Name, col.Collection.Schema); len(others) > 0 {
			p.refuse("shared-schema", "", "the schema %s is shared with %s; change its fields in the schema file by hand", col.Collection.Schema, strings.Join(others, ", "))
			return nil
		}
	}
	cfgSrc, err := readConfig(cfg)
	if err != nil {
		return err
	}
	newCfg := cfgSrc
	if ch := entryChanges(old, nt); len(ch) > 0 {
		if newCfg, err = setEntry(newCfg, req.Name, ch); err != nil {
			return err
		}
	}
	if newCfg, err = spliceRules(newCfg, cfg, req.Name, nt.Rules()); err != nil {
		return err
	}

	overlay := map[string][]byte{}
	if schemaChanged {
		overlay[col.Collection.Schema] = newSchema
		p.files[col.Collection.Schema] = newSchema
	}
	rel := configRel(cfg)
	if string(newCfg) != string(cfgSrc) {
		p.files[rel] = newCfg
	}

	// migrations of existing records
	order := nt.fieldOrder()
	edits := map[int]map[string]any{}
	offerMigrations(col, old, nt, req.Migrations, p, edits)
	if err := rewriteRecords(base, col, edits, order, overlay); err != nil {
		return err
	}
	if b, ok := overlay[col.File]; ok {
		p.files[col.File] = b
	}
	if len(p.files) == 0 {
		return nil // nothing changes
	}
	p.subject = updateSubject(old, nt, p)
	return p.validateAfter(base, newCfg, overlay, old, nt)
}

// fieldOrder is the order new fields are written into records.
func (t *Type) fieldOrder() []string {
	out := make([]string, len(t.Fields))
	for i, f := range t.Fields {
		out[i] = f.Name
	}
	return out
}

func normalizeIncoming(in Type, old *Type) *Type {
	nt := in
	if nt.Key == nil {
		nt.Key = []string{}
	}
	if nt.List == nil {
		nt.List = []string{}
	}
	// translations left out keep what the type has; an empty object clears them
	nt.I18n = cleanTexts(in.I18n)
	if in.I18n == nil && old != nil {
		nt.I18n = old.I18n
	}
	nt.Fields = append([]Field(nil), in.Fields...)
	for i := range nt.Fields {
		f := &nt.Fields[i]
		inI18n := f.I18n
		f.I18n = cleanTexts(inI18n)
		if inI18n == nil && old != nil {
			if of := old.Field(f.Name); of != nil {
				f.I18n = of.I18n
			}
		}
		if f.Enum != nil {
			f.Enum = append([]EnumItem(nil), f.Enum...)
			for j := range f.Enum {
				f.Enum[j].Labels = cleanLabels(f.Enum[j].Labels)
			}
		}
		f.Extras, f.Advanced = nil, false
		if f.Ref != nil {
			r := *f.Ref
			r.I18n = cleanTexts(r.I18n)
			if f.Ref.I18n == nil && old != nil {
				if of := old.Field(f.Name); of != nil && of.Ref != nil {
					r.I18n = of.Ref.I18n // left out: the rule keeps its translations
				}
			}
			f.Ref = &r
		}
		if old != nil {
			if of := old.Field(f.Name); of != nil {
				f.Extras = of.Extras // the server's copy is the truth
				f.Advanced = of.Advanced || len(of.Extras) > 0
			}
		}
		if f.Type == TAdvanced {
			f.Advanced = true
		}
	}
	if old != nil {
		nt.Extras, nt.SameSet = old.Extras, old.SameSet
		if nt.File == "" {
			nt.File = old.File
		}
		if nt.SchemaFile == "" {
			nt.SchemaFile = old.SchemaFile
		}
		if nt.Path == "" {
			nt.Path = old.Path
		}
	}
	return &nt
}

// cleanTexts returns a copy of m without empty text and empty languages; nil
// when nothing is left, so that "no translations" has one shape.
func cleanTexts(m map[string]map[string]string) map[string]map[string]string {
	var out map[string]map[string]string
	for loc, texts := range m {
		for k, v := range texts {
			if strings.TrimSpace(v) == "" {
				continue
			}
			if out == nil {
				out = map[string]map[string]string{}
			}
			if out[loc] == nil {
				out[loc] = map[string]string{}
			}
			out[loc][k] = v
		}
	}
	return out
}

func cleanLabels(m map[string]string) map[string]string {
	var out map[string]string
	for loc, v := range m {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[loc] = v
	}
	return out
}

// checkTexts refuses a translation for a language the console does not have
// and a key the object does not take. what names the object for the message.
func checkTexts(p *Plan, field, what string, m map[string]map[string]string, allowed ...string) {
	locs := make([]string, 0, len(m))
	for l := range m {
		locs = append(locs, l)
	}
	sort.Strings(locs)
	for _, l := range locs {
		if !labels.Supported(l) {
			p.refuse("invalid", field, "%s: %q is not a supported language (use %s)", what, l, strings.Join(locale.Supported, ", "))
			continue
		}
		keys := make([]string, 0, len(m[l]))
		for k := range m[l] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ok := false
			for _, a := range allowed {
				ok = ok || a == k
			}
			if !ok {
				hint := ""
				if k == "enum" {
					hint = "; give enum labels on the enum items"
				}
				p.refuse("invalid", field, "%s: %s has no %q text (use %s)%s", what, l, k, strings.Join(allowed, ", "), hint)
			}
		}
	}
}

// checkRemovedFieldsInUse refuses to drop a field that other parts of the
// configuration point at.
func checkRemovedFieldsInUse(l *ledger.Ledger, old, nt *Type, p *Plan) {
	for _, f := range old.Fields {
		if nt.Field(f.Name) != nil {
			continue
		}
		for _, r := range l.Config.Rules {
			switch {
			case r.Ref != nil:
				if tc, tf, _ := config.SplitRef(r.Ref.To); tc == old.Name && tf == f.Name {
					fc, ff, _ := config.SplitRef(r.Ref.From)
					if fc != old.Name {
						p.refuse("field-in-use", f.Name, "field %q is referenced by %s.%s; remove that reference first", f.Name, fc, ff)
					}
				}
			case r.SameSet != nil:
				if r.SameSet.Left.Collection == old.Name && r.SameSet.Left.Field == f.Name {
					p.refuse("field-in-use", f.Name, "field %q is used by a same_set rule in rackbook.yml; edit that rule first", f.Name)
				}
			}
		}
	}
}

// offerMigrations finds the migrations a change calls for, applies the chosen
// ones to edits (record position -> new data) and lists all of them.
func offerMigrations(col *ledger.Collection, old, nt *Type, chosen []Migration, p *Plan, edits map[int]map[string]any) {
	pick := func(kind, field string) *Migration {
		for i := range chosen {
			if chosen[i].Kind == kind && chosen[i].Field == field {
				return &chosen[i]
			}
		}
		return nil
	}
	data := func(r *ledger.Record) map[string]any {
		d, ok := edits[r.Index]
		if !ok {
			d = map[string]any{}
			for k, v := range r.Data {
				d[k] = v
			}
			edits[r.Index] = d
		}
		return d
	}
	ids := func(rs []*ledger.Record) []string {
		out := []string{}
		for _, r := range rs {
			if len(out) == 20 {
				break
			}
			out = append(out, r.ID)
		}
		return out
	}
	for _, f := range old.Fields {
		if nt.Field(f.Name) != nil {
			continue
		}
		var with []*ledger.Record
		for _, r := range col.Records {
			if _, has := r.Data[f.Name]; has {
				with = append(with, r)
			}
		}
		if len(with) == 0 {
			continue
		}
		off := Offer{Kind: MigRemoveField, Field: f.Name, Count: len(with), Records: ids(with)}
		if pick(MigRemoveField, f.Name) != nil {
			off.Applied = true
			for _, r := range with {
				delete(data(r), f.Name)
			}
		} else {
			// Whatever the schema's additionalProperties says, values are never
			// silently orphaned: removing the field takes a decision about them.
			p.refuse("field-has-values", f.Name, "field %q has values in %d record(s); choose the remove-field migration to delete them", f.Name, len(with))
		}
		p.Migrations = append(p.Migrations, off)
	}
	for _, f := range nt.Fields {
		of := old.Field(f.Name)
		if !f.Required || (of != nil && of.Required) {
			continue
		}
		var without []*ledger.Record
		for _, r := range col.Records {
			if v, has := r.Data[f.Name]; !has || v == nil {
				without = append(without, r)
			}
		}
		if len(without) == 0 {
			continue
		}
		off := Offer{Kind: MigFillDefault, Field: f.Name, Count: len(without), Records: ids(without), Default: f.Default}
		if m := pick(MigFillDefault, f.Name); m != nil {
			val := m.Value
			if val == nil {
				val = f.Default
			}
			if val != nil {
				off.Applied = true
				v := edit.Normalize(map[string]any{"v": val})["v"]
				for _, r := range without {
					data(r)[f.Name] = v
				}
			}
		}
		p.Migrations = append(p.Migrations, off)
	}
}

func updateSubject(old, nt *Type, p *Plan) string {
	var parts []string
	for _, f := range nt.Fields {
		if old.Field(f.Name) == nil {
			parts = append(parts, fmt.Sprintf("add field %q", f.Name))
		}
	}
	for _, f := range old.Fields {
		if nt.Field(f.Name) == nil {
			parts = append(parts, fmt.Sprintf("remove field %q", f.Name))
		}
	}
	for _, f := range nt.Fields {
		if of := old.Field(f.Name); of != nil && !reflect.DeepEqual(*of, f) {
			parts = append(parts, fmt.Sprintf("change field %q", f.Name))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "settings")
	}
	s := "ledger(types): edit " + nt.Name + " — " + strings.Join(parts, ", ")
	if r := []rune(s); len(r) > 100 {
		s = string(r[:100]) + "…"
	}
	return s
}

// validateAfter loads the changed ledger in memory, runs every check and sorts
// what the change would newly break.
func (p *Plan) validateAfter(base *ledger.Ledger, newCfgSrc []byte, overlay map[string][]byte, old, nt *Type) error {
	cfg := base.Config
	newCfg, err := config.Parse(newCfgSrc, cfg.Path)
	if err != nil {
		p.refuse("config", "", "the new rackbook.yml would not load: %v", err)
		return nil
	}
	after := ledger.Load(newCfg, overlay)
	bad := validate.Introduced(validate.Run(base), validate.Run(after))
	narrowed := map[string][]string{}
	for _, is := range bad {
		switch is.Rule {
		case ledger.RuleSchema:
			p.Invalid = append(p.Invalid, is)
			if f := fieldOfPath(is.Path); f != "" && old != nil {
				if of, nf := old.Field(f), nt.Field(f); of != nil && nf != nil && !sameInSchema(*of, *nf) {
					narrowed[f] = append(narrowed[f], is.ID)
				}
			}
		case ledger.RuleRef:
			p.Dangling = append(p.Dangling, is)
		default:
			p.Other = append(p.Other, is)
		}
	}
	fields := make([]string, 0, len(narrowed))
	for f := range narrowed {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		ids := dedup(narrowed[f])
		r := Refusal{Code: "narrowing", Field: f, Count: len(ids), Records: head(ids, 20),
			Message: fmt.Sprintf("changing field %q would make %d existing record(s) invalid; fix them first, then retry", f, len(ids))}
		p.Refusals = append(p.Refusals, r)
	}
	p.capLists()
	p.Backrefs = backrefChanges(old, nt)
	return nil
}

func (p *Plan) capLists() {
	if len(p.Invalid) > maxList {
		p.Invalid, p.Truncated = p.Invalid[:maxList], true
	}
	if len(p.Dangling) > maxList {
		p.Dangling, p.Truncated = p.Dangling[:maxList], true
	}
	if len(p.Other) > maxList {
		p.Other, p.Truncated = p.Other[:maxList], true
	}
}

func fieldOfPath(path string) string {
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	f, _, _ := strings.Cut(path[1:], "/")
	return strings.NewReplacer("~1", "/", "~0", "~").Replace(f)
}

// translationsChanged reports whether f carries other translations than the ones
// read into old: its field translations or the other-language labels of its
// items. The default-language label (the oneOf title) is not part of
// x-rackbook-i18n and does not count.
func translationsChanged(old *Field, f *Field) bool {
	if !reflect.DeepEqual(cleanTexts(old.I18n), cleanTexts(f.I18n)) {
		return true
	}
	oldLabels := map[string]map[string]string{}
	for _, it := range old.Enum {
		oldLabels[it.Value] = cleanLabels(it.Labels)
	}
	for _, it := range f.Enum {
		if !reflect.DeepEqual(oldLabels[it.Value], cleanLabels(it.Labels)) {
			return true
		}
	}
	return false
}

// checkLabelClashes refuses a label that two codes of one field share in a
// language, and a label that is another code of the field: either would make
// "type the label" pick the wrong code.
func checkLabelClashes(p *Plan, f *Field) {
	codes := map[string]bool{}
	for _, it := range f.Enum {
		codes[it.Value] = true
	}
	seen := map[string]string{} // language + label -> code
	for _, it := range f.Enum {
		check := func(loc, label string) {
			if label == "" {
				return
			}
			if other, ok := seen[loc+"\x00"+label]; ok && other != it.Value {
				p.refuse("invalid", f.Name, "field %q: the label %q is used for both %q and %q (%s)", f.Name, label, other, it.Value, loc)
			}
			seen[loc+"\x00"+label] = it.Value
			if codes[label] && label != it.Value {
				p.refuse("invalid", f.Name, "field %q: the label %q of %q is the code of another value", f.Name, label, it.Value)
			}
		}
		check("default", it.Label)
		for _, loc := range sortedKeys(it.Labels) {
			check(loc, it.Labels[loc])
		}
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedup(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func head(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// backrefChanges compares the outgoing references of old and nt.
func backrefChanges(old, nt *Type) []BackrefChange {
	out := []BackrefChange{}
	key := func(t *Type) map[string]string {
		m := map[string]string{}
		if t == nil {
			return m
		}
		for _, f := range t.Fields {
			if f.Ref != nil {
				m[t.Name+"."+f.Name] = f.Ref.To
			}
		}
		return m
	}
	o, n := key(old), key(nt)
	var froms []string
	for k := range o {
		froms = append(froms, k)
	}
	for k := range n {
		if _, ok := o[k]; !ok {
			froms = append(froms, k)
		}
	}
	sort.Strings(froms)
	for _, k := range froms {
		ot, hadOld := o[k]
		nn, hasNew := n[k]
		switch {
		case hadOld && !hasNew:
			out = append(out, BackrefChange{Collection: ot, From: k, Change: "lost"})
		case !hadOld && hasNew:
			out = append(out, BackrefChange{Collection: nn, From: k, Change: "gained"})
		case ot != nn:
			out = append(out, BackrefChange{Collection: ot, From: k, Change: "lost"}, BackrefChange{Collection: nn, From: k, Change: "gained"})
		}
	}
	return out
}
