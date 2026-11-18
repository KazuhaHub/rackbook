// Package config loads and checks rackbook.yml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/roles"
)

// FileName is the default config file name.
const FileName = "rackbook.yml"

// Config is a parsed rackbook.yml.
type Config struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`

	Collections []*Collection `yaml:"-"` // in file order
	Notes       []Note        `yaml:"notes"`
	Rules       []Rule        `yaml:"rules"`
	Write       Write         `yaml:"write"`
	Auth        Auth          `yaml:"auth"`

	// Path is the absolute path of the config file; Dir its directory.
	Path string `yaml:"-"`
	Dir  string `yaml:"-"`
}

// Collection is a list of records inside one YAML file.
type Collection struct {
	Name        string   `yaml:"-"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Group       string   `yaml:"group"`
	File        string   `yaml:"file"`
	Path        string   `yaml:"path"` // dotted path of the list inside the file; "" = top level
	Schema      string   `yaml:"schema"`
	Key         []string `yaml:"key"`
	Label       string   `yaml:"label"`
	List        []string `yaml:"list"`
	Facets      []Facet  `yaml:"facets"`
}

// Facet is a filter hint for the console.
type Facet struct {
	Field  string   `yaml:"field" json:"field"`
	Match  string   `yaml:"match" json:"match"` // exact | contains | prefix
	Values []string `yaml:"values" json:"values"`
}

// UnmarshalYAML accepts the string shorthand and both spellings of the tag form
// ({match: contains, values: [...]} and {contains: [...]}).
func (f *Facet) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*f = Facet{Field: n.Value, Match: "exact"}
		return nil
	}
	var raw struct {
		Field    string   `yaml:"field"`
		Match    string   `yaml:"match"`
		Values   []string `yaml:"values"`
		Contains []string `yaml:"contains"`
		Prefix   []string `yaml:"prefix"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	*f = Facet{Field: raw.Field, Match: raw.Match, Values: raw.Values}
	switch {
	case len(raw.Contains) > 0:
		f.Match, f.Values = "contains", raw.Contains
	case len(raw.Prefix) > 0:
		f.Match, f.Values = "prefix", raw.Prefix
	}
	if f.Match == "" {
		f.Match = "exact"
	}
	return nil
}

// Note is free text (not a record) shown next to a collection.
type Note struct {
	Title      string `yaml:"title"`
	File       string `yaml:"file"`
	Path       string `yaml:"path"`
	Collection string `yaml:"collection"`
}

// Rule is one cross-collection check; exactly one field is set.
type Rule struct {
	Ref     *RefRule     `yaml:"ref"`
	SameSet *SameSetRule `yaml:"same_set"`
	Unique  *UniqueRule  `yaml:"unique"`
}

// RefRule: every value of From ("collection.field") must exist as To ("collection.field").
type RefRule struct {
	From    string   `yaml:"from"`
	To      string   `yaml:"to"`
	Allow   []string `yaml:"allow"`
	Many    bool     `yaml:"many"`
	Message string   `yaml:"message"`
}

// SameSetRule: the set of values of a collection field equals a key set in another file.
type SameSetRule struct {
	Left    SameSetLeft  `yaml:"left"`
	Right   SameSetRight `yaml:"right"`
	Message string       `yaml:"message"`
}

type SameSetLeft struct {
	Collection string         `yaml:"collection"`
	Field      string         `yaml:"field"`
	Where      map[string]any `yaml:"where"`
}

type SameSetRight struct {
	File string `yaml:"file"`
	Path string `yaml:"path"`
	Take string `yaml:"take"` // keys | values
}

// UniqueRule: the combination of Fields must be unique in Collection.
type UniqueRule struct {
	Collection string   `yaml:"collection"`
	Fields     []string `yaml:"fields"`
}

// Write configures the write path.
type Write struct {
	Mode   string `yaml:"mode"` // push | pr
	Branch string `yaml:"branch"`
}

// Auth holds the access policy. Roles is nil when rackbook.yml has no
// auth.roles block (every authenticated identity may then edit). Editors is
// the v0.1 allow-list; it is read as extra editor entries.
type Auth struct {
	Editors []string    `yaml:"editors"`
	Roles   *roles.Spec `yaml:"roles"`
	MCP     AuthMCP     `yaml:"mcp"`
}

// AuthMCP is the auth.mcp block (MCP over MCPHub tokens).
type AuthMCP struct {
	// MatchEmail lets exact and *@domain role entries match an MCPHub user
	// whose username is an e-mail address. Default false: MCPHub users match
	// only mcphub:<username> entries.
	MatchEmail bool `yaml:"match_email"`
}

// Collection returns the collection with the given name, or nil.
func (c *Config) Collection(name string) *Collection {
	for _, col := range c.Collections {
		if col.Name == name {
			return col
		}
	}
	return nil
}

// Resolve turns a config-relative path into an absolute path and refuses
// anything that would leave the config directory.
func (c *Config) Resolve(rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %q must be relative to the config directory", rel)
	}
	abs := filepath.Join(c.Dir, rel)
	if !within(c.Dir, abs) {
		return "", fmt.Errorf("path %q escapes the config directory", rel)
	}
	// Symlinks must not lead out either: resolve the longest existing prefix.
	root, err := filepath.EvalSymlinks(c.Dir)
	if err != nil {
		return abs, nil // the config directory itself is unreadable; reading will fail anyway
	}
	for cur := abs; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			if !within(root, real) {
				return "", fmt.Errorf("path %q resolves outside the config directory", rel)
			}
			break
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return abs, nil
}

func within(root, p string) bool {
	r, err := filepath.Rel(root, p)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}

// Find searches for rackbook.yml in dir and each of its parents.
func Find(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, FileName)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%s not found in the current directory or any parent", FileName)
		}
		dir = parent
	}
}

// Load reads and checks the config at path.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return Parse(data, abs)
}

// Parse parses config bytes; path is the (absolute) location used to resolve relative paths.
func Parse(data []byte, path string) (*Config, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg := &Config{Path: path, Dir: filepath.Dir(path)}
	if root.Kind == 0 {
		return nil, fmt.Errorf("%s: empty config", path)
	}
	if err := root.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Collections are decoded by hand to keep the file order.
	top := root.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "collections" {
			continue
		}
		m := top.Content[i+1]
		for j := 0; j+1 < len(m.Content); j += 2 {
			col := &Collection{Name: m.Content[j].Value}
			if err := m.Content[j+1].Decode(col); err != nil {
				return nil, fmt.Errorf("%s: collection %q: %w", path, col.Name, err)
			}
			cfg.Collections = append(cfg.Collections, col)
		}
	}
	if err := cfg.finish(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) finish() error {
	if c.Write.Mode == "" {
		c.Write.Mode = "push"
	}
	if c.Write.Mode != "push" && c.Write.Mode != "pr" {
		return fmt.Errorf("write.mode must be push or pr, got %q", c.Write.Mode)
	}
	if _, err := roles.Compile(c.Auth.Roles, roles.Options{MCPMatchEmail: c.Auth.MCP.MatchEmail}, c.Auth.Editors...); err != nil {
		return err
	}
	if len(c.Collections) == 0 {
		return errors.New("no collections defined")
	}
	seen := map[string]bool{}
	for _, col := range c.Collections {
		if seen[col.Name] {
			return fmt.Errorf("duplicate collection %q", col.Name)
		}
		seen[col.Name] = true
		if col.Title == "" {
			col.Title = col.Name
		}
		if col.File == "" || col.Schema == "" {
			return fmt.Errorf("collection %q needs file and schema", col.Name)
		}
		for _, p := range []string{col.File, col.Schema} {
			if _, err := c.Resolve(p); err != nil {
				return fmt.Errorf("collection %q: %w", col.Name, err)
			}
		}
		for i := range col.Facets {
			if col.Facets[i].Field == "" {
				return fmt.Errorf("collection %q: facet without field", col.Name)
			}
			switch col.Facets[i].Match {
			case "exact", "contains", "prefix":
			default:
				return fmt.Errorf("collection %q: facet %q: unknown match %q", col.Name, col.Facets[i].Field, col.Facets[i].Match)
			}
		}
	}
	for _, n := range c.Notes {
		if n.File == "" || n.Path == "" {
			return fmt.Errorf("note %q needs file and path", n.Title)
		}
		if _, err := c.Resolve(n.File); err != nil {
			return fmt.Errorf("note %q: %w", n.Title, err)
		}
		if n.Collection != "" && !seen[n.Collection] {
			return fmt.Errorf("note %q: unknown collection %q", n.Title, n.Collection)
		}
	}
	for i, r := range c.Rules {
		if err := c.checkRule(r, seen); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

// SplitRef splits "collection.field".
func SplitRef(s string) (collection, field string, ok bool) {
	i := strings.LastIndex(s, ".")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func (c *Config) checkRule(r Rule, cols map[string]bool) error {
	n := 0
	if r.Ref != nil {
		n++
		for _, s := range []string{r.Ref.From, r.Ref.To} {
			col, _, ok := SplitRef(s)
			if !ok || !cols[col] {
				return fmt.Errorf("ref: %q must be <collection>.<field> of a known collection", s)
			}
		}
	}
	if r.SameSet != nil {
		n++
		s := r.SameSet
		if !cols[s.Left.Collection] || s.Left.Field == "" {
			return fmt.Errorf("same_set: left needs a known collection and field")
		}
		if s.Right.File == "" || s.Right.Path == "" {
			return fmt.Errorf("same_set: right needs file and path")
		}
		if _, err := c.Resolve(s.Right.File); err != nil {
			return fmt.Errorf("same_set: %w", err)
		}
		switch s.Right.Take {
		case "", "keys", "values":
		default:
			return fmt.Errorf("same_set: take must be keys or values")
		}
	}
	if r.Unique != nil {
		n++
		if !cols[r.Unique.Collection] || len(r.Unique.Fields) == 0 {
			return fmt.Errorf("unique: needs a known collection and fields")
		}
	}
	if n != 1 {
		return errors.New("each rule must have exactly one of ref, same_set, unique")
	}
	return nil
}
