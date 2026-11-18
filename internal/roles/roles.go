// Package roles maps an identity to one of three roles (admin, editor,
// viewer) from the auth.roles block of rackbook.yml.
//
//	auth:
//	  roles:
//	    admin:  [owner@example.com]
//	    editor: ["*@example.com", "mcphub:alice"]
//	    viewer: ["*"]
//
// Entries are matched case-insensitively, folding ASCII letters only: a
// look-alike such as the Kelvin sign (U+212A) is not a "k".
//
//	user@example.com   exact identity (or e-mail)
//	*@example.com      any identity or e-mail in that domain
//	mcphub:<username>  an MCPHub user (only for Method "mcphub")
//	mcphub:*           any MCPHub user
//	oauth:<alias>:<user>  a user of the OAuth issuer auth.mcp.trusted_issuers[].alias
//	oauth:<alias>:*    any user of that issuer
//	group:<id>         a group the identity carries (Subject.Groups)
//	*                  anyone authenticated
//
// Which entries can match depends on how the identity was authenticated.
// Identities from oidc, passkey, cloudflare-access, none and cli match every
// kind except mcphub:. MCPHub identities match only mcphub: entries, and the
// exact and *@domain entries as well when the MCPHub username is an e-mail
// address and Options.MCPMatchEmail (auth.mcp.match_email) is on. Identities
// from another OAuth issuer (method "oauth") match only oauth:<alias>:<user>
// entries, and the same e-mail entries under the same option. Token
// identities match nothing: they take their creator's role.
//
// The highest matching role wins. Without a roles block every identity is an
// editor (v0.1 behaviour); the v0.1 auth.editors list then makes the listed
// identities editors and everyone else a viewer. With a roles block, an
// identity that matches nothing has RoleNone and is refused.
package roles

import (
	"fmt"
	"strings"
)

// Role is a permission level. The zero value grants nothing.
type Role int

// Roles in increasing order of power.
const (
	None Role = iota
	Viewer
	Editor
	Admin
)

func (r Role) String() string {
	switch r {
	case Viewer:
		return "viewer"
	case Editor:
		return "editor"
	case Admin:
		return "admin"
	}
	return "none"
}

// Action is something a caller wants to do.
type Action string

// Actions. Read covers every GET; Write is create and update; Delete removes
// records; Admin is for data types, accepting a rewritten remote and similar.
const (
	Read   Action = "read"
	Write  Action = "write"
	Delete Action = "delete"
	Manage Action = "admin"
)

// Allows reports whether the role may perform a.
func (r Role) Allows(a Action) bool {
	switch a {
	case Read:
		return r >= Viewer
	case Write, Delete:
		return r >= Editor
	case Manage:
		return r >= Admin
	}
	return false
}

// Lower returns the smaller of two roles.
func Lower(a, b Role) Role {
	if b < a {
		return b
	}
	return a
}

// Spec is the auth.roles block of rackbook.yml.
type Spec struct {
	Admin  []string `yaml:"admin"`
	Editor []string `yaml:"editor"`
	Viewer []string `yaml:"viewer"`
}

// FoldASCII lower-cases ASCII letters and leaves every other byte alone. Use
// it, not strings.ToLower, for identities and role entries, so that Unicode
// look-alikes never fold onto ASCII names.
func FoldASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
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

// Options tunes how entries match.
type Options struct {
	// MCPMatchEmail lets exact and *@domain entries match MCPHub identities
	// whose username is an e-mail address (auth.mcp.match_email).
	MCPMatchEmail bool
}

// Subject is what roles are evaluated for.
type Subject struct {
	ID     string // identity string folded with FoldASCII (e-mail, username, ...)
	Email  string
	Method string // how the identity was authenticated; see the package comment
	Issuer string // method oauth: the alias of the trusted issuer
	Groups []string
}

type entry struct {
	kind  int
	value string // exact: the identity; domain: "@example.com"; group/mcphub: the id
	alias string // oauth: the issuer alias
}

const (
	kExact = iota
	kDomain
	kMCPHub
	kOAuth
	kGroup
	kAny
)

func parseEntry(s string) (entry, error) {
	s = FoldASCII(strings.TrimSpace(s))
	switch {
	case s == "":
		return entry{}, fmt.Errorf("empty entry")
	case s == "*":
		return entry{kind: kAny}, nil
	case strings.HasPrefix(s, "group:"):
		if v := strings.TrimSpace(s[len("group:"):]); v != "" {
			return entry{kind: kGroup, value: v}, nil
		}
		return entry{}, fmt.Errorf("%q: group id is empty", s)
	case strings.HasPrefix(s, "oauth:"):
		alias, user, ok := strings.Cut(s[len("oauth:"):], ":")
		alias, user = strings.TrimSpace(alias), strings.TrimSpace(user)
		if !ok || alias == "" || user == "" {
			return entry{}, fmt.Errorf("%q: want oauth:<issuer-alias>:<user>", s)
		}
		return entry{kind: kOAuth, alias: alias, value: user}, nil
	case s == "mcphub:*":
		return entry{kind: kMCPHub, value: "*"}, nil
	case strings.HasPrefix(s, "mcphub:"):
		if v := strings.TrimSpace(s[len("mcphub:"):]); v != "" {
			return entry{kind: kMCPHub, value: v}, nil
		}
		return entry{}, fmt.Errorf("%q: MCPHub username is empty", s)
	case strings.HasPrefix(s, "*@"):
		if d := s[2:]; d != "" && !strings.ContainsAny(d, "*@ ") {
			return entry{kind: kDomain, value: "@" + d}, nil
		}
		return entry{}, fmt.Errorf("%q: want *@domain", s)
	case strings.Contains(s, "*"):
		return entry{}, fmt.Errorf("%q: wildcards are only supported as * and *@domain", s)
	}
	return entry{kind: kExact, value: s}, nil
}

func parseList(name string, in []string) ([]entry, error) {
	out := make([]entry, 0, len(in))
	for _, s := range in {
		e, err := parseEntry(s)
		if err != nil {
			return nil, fmt.Errorf("auth.roles.%s: %w", name, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// plainMethods are the authentication methods whose identities match exact,
// domain, group and * entries.
var plainMethods = map[string]bool{"oidc": true, "passkey": true, "cloudflare-access": true, "none": true, "cli": true}

func (e entry) matches(s Subject, opt Options) bool {
	if s.Method == "mcphub" {
		switch e.kind {
		case kMCPHub:
			return e.value == "*" || s.ID == e.value
		case kExact:
			return opt.MCPMatchEmail && strings.Contains(s.ID, "@") && s.ID == e.value
		case kDomain:
			return opt.MCPMatchEmail && strings.Contains(s.ID, "@") && strings.HasSuffix(s.ID, e.value)
		}
		return false
	}
	if s.Method == "oauth" {
		switch e.kind {
		case kOAuth:
			return e.alias == FoldASCII(s.Issuer) && (e.value == "*" || s.ID == e.value)
		case kExact:
			return opt.MCPMatchEmail && strings.Contains(s.ID, "@") && s.ID == e.value
		case kDomain:
			return opt.MCPMatchEmail && strings.Contains(s.ID, "@") && strings.HasSuffix(s.ID, e.value)
		}
		return false
	}
	if !plainMethods[s.Method] { // tokens, unknown methods: no direct role
		return false
	}
	switch e.kind {
	case kAny:
		return true
	case kGroup:
		for _, g := range s.Groups {
			if FoldASCII(strings.TrimSpace(g)) == e.value {
				return true
			}
		}
	case kDomain:
		return strings.HasSuffix(s.ID, e.value) || strings.HasSuffix(FoldASCII(s.Email), e.value)
	case kExact:
		return s.ID == e.value || FoldASCII(s.Email) == e.value
	}
	return false
}

// Policy is a compiled auth.roles block. It is immutable and safe for
// concurrent use.
type Policy struct {
	opt                 Options
	explicit            bool // a roles block exists
	admin, editor, view []entry
	editorsOnly         bool // no roles block, but an editors list: others are viewers
}

// Compile validates spec (nil = no roles block) and adds legacy to the editor
// entries (v0.1 auth.editors and --editors).
func Compile(spec *Spec, opt Options, legacyEditors ...string) (*Policy, error) {
	p := &Policy{explicit: spec != nil, opt: opt}
	if spec != nil {
		var err error
		if p.admin, err = parseList("admin", spec.Admin); err != nil {
			return nil, err
		}
		if p.editor, err = parseList("editor", spec.Editor); err != nil {
			return nil, err
		}
		if p.view, err = parseList("viewer", spec.Viewer); err != nil {
			return nil, err
		}
	}
	for _, s := range legacyEditors {
		if strings.TrimSpace(s) == "" {
			continue
		}
		e, err := parseEntry(s)
		if err != nil {
			return nil, fmt.Errorf("auth.editors: %w", err)
		}
		p.editor = append(p.editor, e)
		if spec == nil {
			p.editorsOnly = true
		}
	}
	return p, nil
}

// Explicit reports whether the policy has a roles block.
func (p *Policy) Explicit() bool { return p.explicit }

// Evaluate returns the highest role s has. s.ID must already be lowercased.
func (p *Policy) Evaluate(s Subject) Role {
	s.ID = FoldASCII(s.ID)
	for _, c := range []struct {
		r Role
		l []entry
	}{{Admin, p.admin}, {Editor, p.editor}, {Viewer, p.view}} {
		for _, e := range c.l {
			if e.matches(s, p.opt) {
				return c.r
			}
		}
	}
	switch {
	case p.explicit:
		return None
	case p.editorsOnly:
		return Viewer
	}
	return Editor
}
