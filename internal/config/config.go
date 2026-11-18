// Package config loads and checks rackbook.yml.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/secretscan"
)

// FileName is the default config file name.
const FileName = "rackbook.yml"

// StateDir is the directory in the data repository that holds Rackbook's own
// state (.rackbook/passkeys.yml, .rackbook/tokens.yml). It is never a ledger
// collection, note or export source.
const StateDir = ".rackbook"

// Config is a parsed rackbook.yml.
type Config struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`

	Collections []*Collection `yaml:"-"` // in file order
	Notes       []Note        `yaml:"notes"`
	Rules       []Rule        `yaml:"rules"`
	Write       Write         `yaml:"write"`
	Auth        Auth          `yaml:"auth"`
	Types       Types         `yaml:"types"`
	// Modules is the allow list of write modules (docs/modules.md), by name.
	Modules map[string]*Module `yaml:"modules"`
	// SecretScan configures the built-in scan for secrets on every write. It is
	// on unless secret_scan.enabled is false.
	SecretScan secretscan.Config `yaml:"secret_scan"`

	// Path is the absolute path of the config file; Dir its directory.
	Path string `yaml:"-"`
	Dir  string `yaml:"-"`

	scanner *secretscan.Scanner
}

// SecretScanner is the compiled secret_scan block. It is never nil, and a
// config that was not built by Parse still scans with every built-in rule.
func (c *Config) SecretScanner() *secretscan.Scanner {
	if c == nil || c.scanner == nil {
		return secretscan.Default()
	}
	return c.scanner
}

// Module is one entry of the modules block: a token that may only create and
// update records of one collection, tagged with the module's name as source.
type Module struct {
	Token      string   `yaml:"token"`
	Collection string   `yaml:"collection"`
	Fields     []string `yaml:"fields"`
	DirectPush bool     `yaml:"direct_push"`
}

// ModuleForToken returns the module that uses the named API token, if any.
func (c *Config) ModuleForToken(token string) (string, *Module) {
	if c == nil || token == "" {
		return "", nil
	}
	for name, m := range c.Modules {
		if m != nil && m.Token == token {
			return name, m
		}
	}
	return "", nil
}

func (c *Config) checkModules() error {
	tokens := map[string]string{}
	for name, m := range c.Modules {
		if !aliasRe.MatchString(name) || name == "manual" {
			return fmt.Errorf("modules.%s: the name must be 1-32 characters of a-z 0-9 . _ - and not \"manual\"", name)
		}
		if m == nil || m.Token == "" {
			return fmt.Errorf("modules.%s.token is required", name)
		}
		if other, dup := tokens[m.Token]; dup {
			return fmt.Errorf("modules.%s.token %q is also used by modules.%s", name, m.Token, other)
		}
		tokens[m.Token] = name
		if c.Collection(m.Collection) == nil {
			return fmt.Errorf("modules.%s.collection %q is not a known collection", name, m.Collection)
		}
		if len(m.Fields) == 0 {
			return fmt.Errorf("modules.%s.fields must list the fields the module may write", name)
		}
		for _, f := range m.Fields {
			if f == "source" {
				return fmt.Errorf("modules.%s.fields must not list source: it is always the module's name", name)
			}
		}
	}
	return nil
}

// Types holds where the console puts the files of a new data type.
type Types struct {
	DataDir   string `yaml:"data_dir"`   // default docs/ledger
	SchemaDir string `yaml:"schema_dir"` // default schemas
}

// Collection is a list of records inside one YAML file.
type Collection struct {
	Name        string   `yaml:"-"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Group       string   `yaml:"group"`
	Icon        string   `yaml:"icon"` // optional lucide icon name for the console
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
	// BackrefTitle and BackrefColumns shape the section that lists, on the
	// target's detail page, the records pointing at it.
	BackrefTitle   string   `yaml:"backref_title"`
	BackrefColumns []string `yaml:"backref_columns"`
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
	Login   `yaml:",inline"` // mode, oidc, passkeys, session (login.go)
	Editors []string         `yaml:"editors"`
	Roles   *roles.Spec      `yaml:"roles"`
	MCP     AuthMCP          `yaml:"mcp"`
}

// AuthMCP is the auth.mcp block (MCP over MCPHub tokens).
type AuthMCP struct {
	// MatchEmail lets exact and *@domain role entries match an MCPHub user
	// whose username is an e-mail address. Default false: MCPHub users match
	// only mcphub:<username> entries.
	MatchEmail bool `yaml:"match_email"`

	// Resource is the public URL of /mcp, the OAuth protected resource
	// (RFC 9728). Required with trusted_issuers.
	Resource string `yaml:"resource"`
	// TrustedIssuers are the authorization servers (MCPHub) whose RFC 9068
	// access tokens /mcp accepts.
	TrustedIssuers []TrustedIssuer `yaml:"trusted_issuers"`
	// Scopes maps OAuth scopes to what they allow.
	Scopes MCPScopes `yaml:"scopes"`
	// DirectPush lists who may push create and update from MCP straight to the
	// tracked branch. Everything else an MCPHub user or token does through
	// MCP becomes a pull request; deletes always do.
	DirectPush []DirectPush `yaml:"direct_push"`
}

// Issuer kinds.
const (
	KindOAuth  = "oauth"  // any OAuth 2.0 / OIDC authorization server (default)
	KindMCPHub = "mcphub" // MCPHub: identities match mcphub:<user> role entries
)

// DefaultAlgorithms are the signing algorithms accepted when an issuer does not
// list its own.
var DefaultAlgorithms = []string{"ES256", "RS256", "PS256", "EdDSA"}

// AllowedAlgorithms is every algorithm an issuer may list. HS* (shared
// secrets) and none are never accepted, whatever the config says.
var AllowedAlgorithms = map[string]bool{
	"ES256": true, "ES384": true, "ES512": true, "RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true, "EdDSA": true,
}

// TrustedIssuer is one authorization server /mcp trusts.
type TrustedIssuer struct {
	Issuer string `yaml:"issuer"`
	// Alias names the issuer in role entries (oauth:<alias>:<user>) and in the
	// Edited-via trailer. Required for kind oauth; default "mcphub" for kind
	// mcphub.
	Alias string `yaml:"alias"`
	// Kind is oauth (default) or mcphub.
	Kind string `yaml:"kind"`
	// Audience the token must carry; default Resource. It need not be a URL
	// (Entra uses api://<client-id> or the client id).
	Audience string `yaml:"audience"`
	// JWKSURL overrides jwks_uri from the issuer metadata (then the metadata
	// is not fetched).
	JWKSURL string `yaml:"jwks_url"`
	// Algorithms the issuer signs with; default DefaultAlgorithms.
	Algorithms []string `yaml:"algorithms"`
	// RequireTypATJWT demands typ at+jwt (RFC 9068). Default true. When false,
	// typ JWT or no typ is accepted too, with extra checks against ID tokens.
	RequireTypATJWT *bool `yaml:"require_typ_at_jwt"`
	// UsernameClaim is the claim that names the user; default sub.
	UsernameClaim string `yaml:"username_claim"`
	// ScopeClaim names the claim that carries the scopes. Default: scope, then
	// scp (a space-separated string or an array).
	ScopeClaim string `yaml:"scope_claim"`
	// EmailsVerified says the issuer only puts e-mail addresses it has verified
	// in the email claim, so they may be trusted without email_verified: true.
	EmailsVerified bool `yaml:"emails_verified"`
	// Introspection enables RFC 7662 for opaque (non-JWT) tokens.
	Introspection *Introspection `yaml:"introspection"`
}

// Introspection configures RFC 7662 token introspection for one issuer.
type Introspection struct {
	// Endpoint overrides introspection_endpoint from the issuer metadata.
	Endpoint string `yaml:"endpoint"`
	ClientID string `yaml:"client_id"`
	// ClientSecretEnv names the environment variable that holds the client
	// secret (never the secret itself).
	ClientSecretEnv string `yaml:"client_secret_env"`
	// TokenPrefix selects this issuer for opaque tokens that start with it. It is
	// required for every introspecting issuer when more than one introspects: a
	// token is only ever sent to one issuer.
	TokenPrefix string `yaml:"token_prefix"`
}

// NeedTypATJWT reports whether typ at+jwt is required.
func (t TrustedIssuer) NeedTypATJWT() bool { return t.RequireTypATJWT == nil || *t.RequireTypATJWT }

// AlgorithmList is Algorithms or the default.
func (t TrustedIssuer) AlgorithmList() []string {
	if len(t.Algorithms) == 0 {
		return DefaultAlgorithms
	}
	return t.Algorithms
}

// Name is the issuer's alias.
func (t TrustedIssuer) Name() string {
	if t.Alias != "" {
		return t.Alias
	}
	if t.Kind == KindMCPHub {
		return "mcphub"
	}
	return ""
}

// MCPScopes names the OAuth scopes that Rackbook checks. A nil pointer means
// the default; an empty string means "no scope needed".
type MCPScopes struct {
	Read  *string `yaml:"read"`  // default: no scope needed
	Write *string `yaml:"write"` // default: DefaultWriteScope
}

// DefaultWriteScope is required for MCPHub tokens to write unless
// auth.mcp.scopes.write says otherwise.
const DefaultWriteScope = "rackbook:write"

// ReadScope is the scope a token needs to read ("" = none).
func (s MCPScopes) ReadScope() string {
	if s.Read == nil {
		return ""
	}
	return strings.TrimSpace(*s.Read)
}

// WriteScope is the scope a token needs to write ("" = none).
func (s MCPScopes) WriteScope() string {
	if s.Write == nil {
		return DefaultWriteScope
	}
	return strings.TrimSpace(*s.Write)
}

// DirectPush allows create and update to the tracked branch for the listed
// users or roles, on the listed collections ("*" = all).
type DirectPush struct {
	Users       []string `yaml:"users"`
	Roles       []string `yaml:"roles"`
	Collections []string `yaml:"collections"`
}

// Audience returns the audience required of tokens from t.
func (m AuthMCP) Audience(t TrustedIssuer) string {
	if t.Audience != "" {
		return t.Audience
	}
	return m.Resource
}

// Enabled reports whether /mcp accepts MCPHub tokens.
func (m AuthMCP) Enabled() bool { return len(m.TrustedIssuers) > 0 }

// ValidURL checks an issuer, resource or JWKS URL: absolute, https (http only
// for localhost, 127.0.0.1 and [::1]), no credentials, query or fragment.
func ValidURL(raw string, allowQuery bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	if u.User != nil || u.Fragment != "" || (!allowQuery && u.RawQuery != "") {
		return fmt.Errorf("%q must not carry credentials, a fragment or a query", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return fmt.Errorf("%q: http is only allowed for localhost, use https", raw)
		}
	default:
		return fmt.Errorf("%q: the scheme must be https", raw)
	}
	return nil
}

var aliasRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func (m AuthMCP) validate() error {
	if m.Resource != "" {
		if err := ValidURL(m.Resource, false); err != nil {
			return fmt.Errorf("auth.mcp.resource: %w", err)
		}
	}
	if len(m.TrustedIssuers) > 0 && m.Resource == "" {
		return errors.New("auth.mcp.resource is required with trusted_issuers (the public URL of /mcp)")
	}
	seen := map[string]bool{}
	aliases := map[string]bool{}
	introspecting, prefixes := 0, map[string]bool{}
	for _, t := range m.TrustedIssuers {
		if t.Introspection != nil {
			introspecting++
		}
	}
	for i, t := range m.TrustedIssuers {
		if err := ValidURL(t.Issuer, false); err != nil {
			return fmt.Errorf("auth.mcp.trusted_issuers[%d].issuer: %w", i, err)
		}
		if seen[t.Issuer] {
			return fmt.Errorf("auth.mcp.trusted_issuers: %q listed twice", t.Issuer)
		}
		seen[t.Issuer] = true
		at := fmt.Sprintf("auth.mcp.trusted_issuers[%d]", i)
		switch t.Kind {
		case "", KindOAuth, KindMCPHub:
		default:
			return fmt.Errorf("%s.kind must be oauth or mcphub, got %q", at, t.Kind)
		}
		name := t.Name()
		if name == "" || !aliasRe.MatchString(name) {
			return fmt.Errorf("%s.alias is required (1-32 characters of a-z 0-9 . _ -), it names the issuer in role entries oauth:<alias>:<user>", at)
		}
		if aliases[name] {
			return fmt.Errorf("%s.alias %q is used twice", at, name)
		}
		aliases[name] = true
		for _, a := range t.Algorithms {
			if !AllowedAlgorithms[a] {
				return fmt.Errorf("%s.algorithms: %q is not allowed (use ES*, RS*, PS* or EdDSA; HS* and none are never accepted)", at, a)
			}
		}
		if in := t.Introspection; in != nil {
			if in.Endpoint != "" {
				if err := ValidURL(in.Endpoint, false); err != nil {
					return fmt.Errorf("%s.introspection.endpoint: %w", at, err)
				}
			}
			if p := in.TokenPrefix; p != "" {
				if prefixes[p] {
					return fmt.Errorf("%s.introspection.token_prefix %q is used twice", at, p)
				}
				prefixes[p] = true
			} else if introspecting > 1 {
				return fmt.Errorf("%s.introspection.token_prefix is required when several issuers introspect: an opaque token is only sent to the issuer whose prefix it carries", at)
			}
			if in.ClientID == "" || in.ClientSecretEnv == "" {
				return fmt.Errorf("%s.introspection needs client_id and client_secret_env (the name of the environment variable that holds the secret)", at)
			}
		}
		if t.Audience == "" && m.Resource == "" {
			return fmt.Errorf("%s needs an audience or auth.mcp.resource", at)
		}
		if t.JWKSURL != "" {
			if err := ValidURL(t.JWKSURL, true); err != nil {
				return fmt.Errorf("auth.mcp.trusted_issuers[%d].jwks_url: %w", i, err)
			}
		}
	}
	for i, d := range m.DirectPush {
		if len(d.Users) == 0 && len(d.Roles) == 0 {
			return fmt.Errorf("auth.mcp.direct_push[%d]: list users or roles", i)
		}
		if len(d.Collections) == 0 {
			return fmt.Errorf("auth.mcp.direct_push[%d]: list collections (or \"*\")", i)
		}
		for _, u := range d.Users {
			u = roles.FoldASCII(strings.TrimSpace(u))
			switch {
			case strings.HasPrefix(u, "mcphub:") && len(u) > len("mcphub:"):
			case strings.HasPrefix(u, "oauth:") && strings.Count(u, ":") >= 2:
			case strings.Contains(u, "@") && m.MatchEmail:
			default:
				return fmt.Errorf("auth.mcp.direct_push[%d]: user %q must be mcphub:<user>, oauth:<alias>:<user>, or an e-mail address with auth.mcp.match_email", i, u)
			}
		}
		for _, r := range d.Roles {
			if r != "admin" && r != "editor" {
				return fmt.Errorf("auth.mcp.direct_push[%d]: role %q must be admin or editor", i, r)
			}
		}
	}
	return nil
}

// IsStatePath reports whether a config-relative path is inside StateDir.
func IsStatePath(rel string) bool {
	p := filepath.ToSlash(filepath.Clean(rel))
	return p == StateDir || strings.HasPrefix(p, StateDir+"/")
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
	if filepath.IsAbs(rel) || (runtime.GOOS == "windows" && windowsNonRelative(rel)) {
		return "", fmt.Errorf("path %q must be relative to the config directory", rel)
	}
	abs := filepath.Join(c.Dir, rel)
	if !within(c.Dir, abs) {
		return "", fmt.Errorf("path %q escapes the config directory", rel)
	}
	if r, err := filepath.Rel(c.Dir, abs); err == nil && strings.EqualFold(strings.SplitN(filepath.ToSlash(r), "/", 2)[0], StateDir) {
		return "", fmt.Errorf("path %q is inside %s/, which belongs to Rackbook (passkeys, tokens) and is not part of the ledger", rel, StateDir)
	}
	if r, err := filepath.Rel(c.Dir, abs); err == nil && strings.EqualFold(strings.SplitN(filepath.ToSlash(r), "/", 2)[0], ".git") {
		return "", fmt.Errorf("path %q is inside .git/, which is not part of the ledger", rel)
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

// windowsNonRelative reports whether rel is, on Windows, anything but a plain
// relative path: a drive ("C:\x", "C:x"), a UNC or device path ("\\host\share",
// "\\?\C:\x"), a path rooted on the current drive ("\x", "/x"), or a name with
// a colon (an NTFS alternate data stream, "a.yml:stream"). filepath.IsAbs misses
// the rooted and drive-relative forms, and filepath.Join would glue them onto
// the config directory. It is plain string logic so it can be tested anywhere.
func windowsNonRelative(rel string) bool {
	return strings.HasPrefix(rel, `\`) || strings.HasPrefix(rel, "/") || strings.Contains(rel, ":")
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
	if err := c.Auth.Login.check(); err != nil {
		return err
	}
	if err := c.Auth.MCP.validate(); err != nil {
		return err
	}
	sc, err := secretscan.New(c.SecretScan)
	if err != nil {
		return err
	}
	c.scanner = sc
	if c.Types.DataDir == "" {
		c.Types.DataDir = "docs/ledger"
	}
	if c.Types.SchemaDir == "" {
		c.Types.SchemaDir = "schemas"
	}
	for _, d := range []string{c.Types.DataDir, c.Types.SchemaDir} {
		if _, err := c.Resolve(d); err != nil {
			return fmt.Errorf("types: %w", err)
		}
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
			abs, err := c.Resolve(p)
			if err != nil {
				return fmt.Errorf("collection %q: %w", col.Name, err)
			}
			if c.Path != "" && strings.EqualFold(filepath.Clean(abs), filepath.Clean(c.Path)) {
				return fmt.Errorf("collection %q: %s is the config file itself, not a data or schema file", col.Name, p)
			}
			if IsStatePath(p) {
				return fmt.Errorf("collection %q: %s is Rackbook's own state (.rackbook/), not a data file", col.Name, p)
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
	return c.checkModules()
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
