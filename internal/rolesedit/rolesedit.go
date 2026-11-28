// Package rolesedit changes the role lists of rackbook.yml (auth.roles.admin,
// auth.roles.editor, auth.roles.viewer and auth.auditors) for the console's role
// editor. It plans a change (the new text of the file, its unified diff, what
// each entry is, what the person who edits would be afterwards), refuses the
// changes that would lock somebody out, and writes the file with yamledit so
// comments, key order and layout stay as they are.
//
// The rules of a save, in the order they are checked:
//
//  1. the version the editor read must still be the version of the lists
//     (conflict);
//  2. every entry must pass the parser that rackbook check uses, plus the
//     editor's own limits (invalid_entries);
//  3. at least one admin entry must remain, and one that somebody can sign in
//     through: a local: entry counts only while local accounts are available and
//     the account (or, for local:*, some account) is not disabled or removed
//     (last_admin);
//  4. the person saving must still be an admin afterwards, evaluated on their
//     own session (self_lockout), and an admin through an entry that names them
//     (an identity, *@domain, oidc: or *), not only through a group or an app
//     role (self_lockout_claims): a token of theirs and a session past
//     auth.session.claims_absolute are evaluated by identity entries alone.
package rolesedit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/types"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// KindRoles is the edit.Result kind of a role-list change.
const KindRoles edit.Kind = "roles"

// The four lists, as named in the API and the console.
const (
	ListAdmin    = "admin"
	ListEditor   = "editor"
	ListViewer   = "viewer"
	ListAuditors = "auditors"
)

// Lists is the content of the four lists.
type Lists struct {
	Admin    []string `json:"admin"`
	Editor   []string `json:"editor"`
	Viewer   []string `json:"viewer"`
	Auditors []string `json:"auditors"`
}

// Names of the lists in the order the editor shows them.
var Names = []string{ListAdmin, ListEditor, ListViewer, ListAuditors}

// yamlPath is where each list lives in rackbook.yml.
var yamlPath = map[string]string{
	ListAdmin: "auth.roles.admin", ListEditor: "auth.roles.editor", ListViewer: "auth.roles.viewer", ListAuditors: "auth.auditors",
}

// Get returns the list called name.
func (l Lists) Get(name string) []string {
	switch name {
	case ListAdmin:
		return l.Admin
	case ListEditor:
		return l.Editor
	case ListViewer:
		return l.Viewer
	case ListAuditors:
		return l.Auditors
	}
	return nil
}

func (l *Lists) set(name string, v []string) {
	switch name {
	case ListAdmin:
		l.Admin = v
	case ListEditor:
		l.Editor = v
	case ListViewer:
		l.Viewer = v
	case ListAuditors:
		l.Auditors = v
	}
}

// Spec is the lists as an auth.roles block, and the auditors beside it.
func (l Lists) Spec() (*roles.Spec, []string) {
	return &roles.Spec{Admin: l.Admin, Editor: l.Editor, Viewer: l.Viewer}, l.Auditors
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Normalized has no nil list.
func (l Lists) Normalized() Lists {
	return Lists{nonNil(l.Admin), nonNil(l.Editor), nonNil(l.Viewer), nonNil(l.Auditors)}
}

// Current returns the lists of cfg. explicit is false when rackbook.yml has no
// auth.roles block: every signed-in person may then edit and nobody is an
// admin, so there is nothing for the editor to do.
func Current(cfg *config.Config) (l Lists, explicit bool) {
	if r := cfg.Auth.Roles; r != nil {
		l = Lists{Admin: r.Admin, Editor: r.Editor, Viewer: r.Viewer}
		explicit = true
	}
	l.Auditors = cfg.Auth.Auditors
	return l.Normalized(), explicit
}

// Version identifies the content of the four lists. A change that leaves them as
// they were (a comment, another key of rackbook.yml) does not change it, so an
// edit of something else never makes an editor's draft stale.
func Version(l Lists) string {
	b, _ := json.Marshal(l.Normalized())
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// Note levels.
const (
	LevelError   = "error"   // the entry cannot be saved
	LevelWarning = "warning" // it can, but check it
)

// Note codes. The console words each one in the three languages; Message is the
// English text.
const (
	NoteEmpty          = "empty"
	NoteTooLong        = "too_long"
	NoteControl        = "control_chars"
	NoteFormat         = "format_chars"
	NoteInvalid        = "invalid"
	NoteWildcardAdmin  = "wildcard_admin"
	NoteWildcardEdit   = "wildcard_editor"
	NoteNoSSO          = "no_sso"
	NoteUnknownIssuer  = "unknown_issuer"
	NoteNoMCPHub       = "no_mcphub"
	NoteLocal          = "local_unavailable"
	NoteLocalNoAccount = "local_no_account"
	NoteLocalInactive  = "local_inactive"
	NoteAlsoIn         = "also_in"
	NoteDuplicate      = "duplicate"
	NoteNeverSeen      = "never_seen"
)

// Note is something to know about one entry.
type Note struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// Also names the other list of an also_in note.
	Also string `json:"also,omitempty"`
}

// Entry is one entry of a list with what it is and what to know about it.
type Entry struct {
	Value string `json:"value"`
	// Kind is roles.KindIdentity and the others; "" for an entry that does not parse.
	Kind  string `json:"kind"`
	Notes []Note `json:"notes"`
}

// Annotated is the four lists with each entry described.
type Annotated struct {
	Admin    []Entry `json:"admin"`
	Editor   []Entry `json:"editor"`
	Viewer   []Entry `json:"viewer"`
	Auditors []Entry `json:"auditors"`
}

func (a *Annotated) set(name string, v []Entry) {
	switch name {
	case ListAdmin:
		a.Admin = v
	case ListEditor:
		a.Editor = v
	case ListViewer:
		a.Viewer = v
	case ListAuditors:
		a.Auditors = v
	}
}

// Get returns the entries of the list called name.
func (a Annotated) Get(name string) []Entry {
	switch name {
	case ListAdmin:
		return a.Admin
	case ListEditor:
		return a.Editor
	case ListViewer:
		return a.Viewer
	case ListAuditors:
		return a.Auditors
	}
	return nil
}

// HasError reports whether any entry has a note of level error.
func (a Annotated) HasError() bool {
	for _, n := range Names {
		for _, e := range a.Get(n) {
			for _, nt := range e.Notes {
				if nt.Level == LevelError {
					return true
				}
			}
		}
	}
	return false
}

// invisibleRune is a character an entry must not hold: Unicode format characters
// (zero-width, bidi overrides and isolates, BOM), line and paragraph separators,
// and the C1 controls (including U+0085). They make two entries that look alike differ.
func invisibleRune(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || (r >= 0x80 && r <= 0x9f)
}

const (
	maxEntryBytes = 256
	maxListLen    = 1000
)

// The states of an account the editor tells apart (the same strings as internal/accounts, which a test holds
// together; this package does not import it, so that nothing HTTP-facing depends on the account store).
const (
	stateDisabled = "disabled"
	stateRemoved  = "removed"
)

// Local says what the deployment has of local accounts (docs/design-local-accounts.md, 7). The zero
// value is "none": local: entries then match nobody.
type Local struct {
	// Available is true when the state key is loaded and the account store is open.
	Available bool
	// States is the state of every account by username (active, restricted, passkey_only, invited, reset_pending, disabled, removed), removed ones included.
	States map[string]string
}

// usable says an account can sign in now or once its setup is done: it exists and is not disabled
// or removed.
func (l Local) usable(state string) bool {
	return state != "" && state != stateDisabled && state != stateRemoved
}

// canSignIn says the entry, which parsed as info, can match somebody who can sign in here. Entries
// of every kind but local: are taken to; a local: entry needs local accounts and an account.
func (l Local) canSignIn(info roles.EntryInfo) bool {
	if info.Kind != roles.KindLocal {
		return true
	}
	if !l.Available {
		return false
	}
	if info.Value == "*" {
		for _, st := range l.States {
			if l.usable(st) {
				return true
			}
		}
		return false
	}
	return l.usable(l.States[info.Value])
}

// Annotate describes every entry of l against cfg (what the deployment can
// match at all). Entries are taken as written; use Clean first for input. Local accounts are
// taken to be unavailable; AnnotateLocal says otherwise.
func Annotate(cfg *config.Config, l Lists) Annotated { return AnnotateLocal(cfg, l, Local{}) }

// AnnotateLocal is Annotate for a deployment that has local as its local accounts.
func AnnotateLocal(cfg *config.Config, l Lists, local Local) Annotated {
	var out Annotated
	// where each entry (by its key) is listed, to say "also in editor"
	where := map[string][]string{}
	for _, n := range Names[:3] {
		for _, s := range l.Get(n) {
			if info, err := roles.Describe(s); err == nil {
				where[info.Key] = append(where[info.Key], n)
			}
		}
	}
	for _, n := range Names {
		seen := map[string]bool{}
		var es []Entry
		for _, s := range l.Get(n) {
			e := Entry{Value: s, Notes: []Note{}}
			info, err := roles.Describe(s)
			switch {
			case strings.TrimSpace(s) == "":
				e.Notes = append(e.Notes, Note{Level: LevelError, Code: NoteEmpty, Message: "the entry is empty"})
			case len(s) > maxEntryBytes:
				e.Notes = append(e.Notes, Note{Level: LevelError, Code: NoteTooLong, Message: fmt.Sprintf("an entry is at most %d bytes", maxEntryBytes)})
			case strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
				e.Notes = append(e.Notes, Note{Level: LevelError, Code: NoteControl, Message: "an entry has no control characters"})
			case strings.ContainsFunc(s, invisibleRune):
				e.Notes = append(e.Notes, Note{Level: LevelError, Code: NoteFormat, Message: "an entry has no invisible or direction-changing characters (zero-width, bidi, line and paragraph separators)"})
			case err != nil:
				e.Notes = append(e.Notes, Note{Level: LevelError, Code: NoteInvalid, Message: err.Error()})
			default:
				e.Kind = info.Kind
				e.Notes = append(e.Notes, kindNotes(cfg, n, info, local)...)
				if seen[info.Key] {
					e.Notes = append(e.Notes, Note{Level: LevelWarning, Code: NoteDuplicate, Message: "listed twice in this list"})
				}
				seen[info.Key] = true
				if n != ListAuditors {
					for _, other := range where[info.Key] {
						if other != n {
							e.Notes = append(e.Notes, Note{Level: LevelWarning, Code: NoteAlsoIn, Also: other,
								Message: "also in " + other + "; the highest role the person matches wins"})
							break
						}
					}
				}
			}
			es = append(es, e)
		}
		out.set(n, nonNilEntries(es))
	}
	return out
}

func nonNilEntries(e []Entry) []Entry {
	if e == nil {
		return []Entry{}
	}
	return e
}

// kindNotes are the warnings that depend on the kind of entry and on what the
// deployment has: an entry that can match nobody here, or too many people.
func kindNotes(cfg *config.Config, list string, info roles.EntryInfo, local Local) []Note {
	var out []Note
	w := func(code, msg string) { out = append(out, Note{Level: LevelWarning, Code: code, Message: msg}) }
	// an entry that matches a whole class of people: *, *@domain, mcphub:* and oauth:<alias>:*
	wide := info.Kind == roles.KindAny || info.Kind == roles.KindDomain || (info.Kind == roles.KindLocal && info.Value == "*") ||
		(info.Kind == roles.KindMCPHub && info.Value == "*") || (info.Kind == roles.KindOAuth && strings.HasSuffix(info.Value, ":*"))
	switch {
	case wide && list == ListAdmin:
		w(NoteWildcardAdmin, "everyone this entry matches is an administrator")
	case wide && list == ListEditor:
		w(NoteWildcardEdit, "everyone this entry matches can edit records")
	}
	switch info.Kind {
	case roles.KindGroup, roles.KindAppRole, roles.KindOIDC:
		if cfg.Auth.Mode != "oidc" {
			w(NoteNoSSO, "sign-in is not through single sign-on here, so this entry matches nobody")
		}
	case roles.KindMCPHub:
		if !hasIssuerKind(cfg, config.KindMCPHub) {
			w(NoteNoMCPHub, "no MCPHub issuer is configured (auth.mcp.trusted_issuers), so this entry matches nobody")
		}
	case roles.KindOAuth:
		alias, _, _ := strings.Cut(info.Value, ":")
		if !hasAlias(cfg, alias) {
			w(NoteUnknownIssuer, fmt.Sprintf("no trusted OAuth issuer has the alias %q (auth.mcp.trusted_issuers)", alias))
		}
	case roles.KindLocal:
		switch st, has := local.States[info.Value]; {
		case !local.Available:
			w(NoteLocal, "local accounts are not available, so this entry matches nobody")
		case info.Value == "*":
		case !has:
			w(NoteLocalNoAccount, "no local account has this name, so this entry matches nobody yet")
		case st == stateRemoved:
			w(NoteLocalInactive, "this account was removed and its name cannot be used again, so this entry matches nobody")
		case st == stateDisabled:
			w(NoteLocalInactive, "this account is disabled, so this entry matches nobody until it is enabled")
		}
	}
	return out
}

func hasIssuerKind(cfg *config.Config, kind string) bool {
	for _, t := range cfg.Auth.MCP.TrustedIssuers {
		if t.Kind == kind {
			return true
		}
	}
	return false
}

func hasAlias(cfg *config.Config, alias string) bool {
	if alias == config.BuiltinIssuerAlias && cfg.Auth.MCP.BuiltinIssuer.Enabled {
		return true
	}
	for _, t := range cfg.Auth.MCP.TrustedIssuers {
		if t.Kind != config.KindMCPHub && strings.EqualFold(t.Name(), alias) {
			return true
		}
	}
	return false
}

// Clean trims the entries of input and drops nothing: an empty entry stays so
// that it is reported.
func Clean(l Lists) Lists {
	out := Lists{}
	for _, n := range Names {
		var v []string
		for _, s := range l.Get(n) {
			v = append(v, strings.TrimSpace(s))
		}
		out.set(n, v)
	}
	return out.Normalized()
}

// Cap is what one person has under a set of lists.
type Cap struct {
	Role        string   `json:"role"`
	Auditor     bool     `json:"auditor"`
	RoleFrom    []string `json:"roleFrom"`
	AuditorFrom []string `json:"auditorFrom"`
	// ByIdentity is the role the person keeps when only entries that name them
	// count; AuditorByIdentity the same for the auditor capability.
	ByIdentity        string `json:"byIdentity"`
	AuditorByIdentity bool   `json:"auditorByIdentity"`
}

// Evaluator evaluates the person who is editing, on their own session (identity
// and claims), under the given lists, everything else being as cfg has it. A nil
// Evaluator skips the caller's checks (the command line has no session). It is
// called while the store is locked for the write, so it must not read the store.
type Evaluator func(cfg *config.Config, spec *roles.Spec, auditors []string) (Cap, error)

// Refusal codes.
const (
	CodeInvalidEntries    = "invalid_entries"
	CodeLastAdmin         = "last_admin"
	CodeSelfLockout       = "self_lockout"
	CodeSelfLockoutClaims = "self_lockout_claims"
	CodeSecret            = "secret_detected"
)

// Refusal is a change that is not allowed, with the code the API answers by.
type Refusal struct {
	Code    string
	Message string
	// Entries describes the lists when the refusal is about their entries.
	Entries *Annotated
}

func (r *Refusal) Error() string { return r.Message }

// Errors of Plan and Apply other than a Refusal.
var (
	// ErrNoRolesBlock: rackbook.yml has no auth.roles block.
	ErrNoRolesBlock = errors.New("rackbook.yml has no auth.roles block: add one by hand first (every signed-in person can edit while it is missing, and nobody is an administrator)")
	// ErrNoVersion: the request did not say which version it started from.
	ErrNoVersion = errors.New("version is required: send the version you read (GET /api/admin/roles)")
)

// VersionError means the lists changed since the version the editor read.
type VersionError struct {
	Current Annotated
	Lists   Lists
	Version string
}

func (e *VersionError) Error() string {
	return "the roles changed since you opened them; reload and make your change again"
}

// Request is a change: the complete new lists, built from the version that was read.
type Request struct {
	Version string
	Lists   Lists
	// Message replaces the default commit subject when it is not empty.
	Message string
	// Evaluate evaluates the caller; see Evaluator.
	Evaluate Evaluator
	// Local says what the deployment has of local accounts (the zero value: none).
	Local Local
	// Identities are the identities that signed in (audit/identities.json), folded
	// to lower case, for a warning on an added entry that matches nobody of them.
	// Nil when there is no record to look at.
	Identities []string
}

// Warning is a note about an entry that the change adds.
type Warning struct {
	List  string `json:"list"`
	Entry string `json:"entry"`
	Note  Note   `json:"note"`
}

// Plan is what a change would do.
type Plan struct {
	Version string
	Before  Lists
	After   Lists
	Entries Annotated // the new lists, described
	Changed bool
	File    string // config-relative path of rackbook.yml
	Out     []byte // the new text of the file (nil when Changed is false or the lists do not pass)
	Diff    string
	Subject string
	// Now and After are the caller's capabilities before and after (nil without an Evaluator).
	Now, AfterCap *Cap
	Warnings      []Warning
	// Refusal is set when a save would be refused: the plan still holds everything
	// that could be worked out, so a preview can show it.
	Refusal *Refusal
	// Source is the file text the plan was made from.
	Source []byte
}

// Build plans req against cfg without writing anything. The error is a
// *VersionError, ErrNoRolesBlock, ErrNoVersion, or what yamledit says when the
// layout of the file cannot be edited (yamledit.ErrUnsupported); a change that is
// not allowed is a Plan with Refusal set.
func Build(cfg *config.Config, req Request) (*Plan, error) {
	cur, explicit := Current(cfg)
	if !explicit {
		return nil, ErrNoRolesBlock
	}
	if req.Version == "" {
		return nil, ErrNoVersion
	}
	ver := Version(cur)
	if req.Version != ver {
		return nil, &VersionError{Current: Annotate(cfg, cur), Lists: cur, Version: ver}
	}
	next := Clean(req.Lists)
	p := &Plan{Version: ver, Before: cur, After: next, Entries: AnnotateLocal(cfg, next, req.Local), File: relConfig(cfg)}
	p.Changed = !sameLists(cur, next)
	if req.Evaluate != nil {
		spec, aud := cur.Spec()
		if c, err := req.Evaluate(cfg, spec, aud); err == nil {
			p.Now = &c
		}
	}
	// 2. entries
	total := 0
	for _, n := range Names {
		total += len(next.Get(n))
	}
	if total > maxListLen {
		p.Refusal = &Refusal{Code: CodeInvalidEntries, Message: fmt.Sprintf("there are %d entries; the editor handles at most %d", total, maxListLen), Entries: &p.Entries}
		return p, nil
	}
	if p.Entries.HasError() {
		p.Refusal = &Refusal{Code: CodeInvalidEntries, Message: "some entries are not valid: " + firstError(p.Entries), Entries: &p.Entries}
		return p, nil
	}
	p.Warnings = addedWarnings(cur, next, p.Entries, req.Identities)
	// 3. the last admin. Nothing is refused when nothing changes: there is nothing to save. The rule counts
	// admin entries through which somebody can sign in: a local: entry counts only with local accounts and an
	// account that is not disabled or removed. A list that has none of those already is not refused for an
	// edit that leaves it so (a change to the editors, say), only one that takes the last one away.
	if p.Changed {
		switch {
		case len(next.Admin) == 0:
			p.Refusal = &Refusal{Code: CodeLastAdmin, Message: "at least one admin entry must remain: without one nobody could edit the roles again"}
		case signable(next.Admin, req.Local) == 0 && signable(cur.Admin, req.Local) > 0:
			p.Refusal = &Refusal{Code: CodeLastAdmin, Message: "no admin entry would be left that anyone can sign in through (a local: entry needs an account that is not disabled or removed): without one nobody could edit the roles again"}
		}
	}
	// 4. the person who saves
	if req.Evaluate != nil {
		spec, aud := next.Spec()
		c, err := req.Evaluate(cfg, spec, aud)
		if err != nil {
			return nil, err
		}
		p.AfterCap = &c
		if p.Refusal == nil && p.Changed {
			switch {
			case c.Role != roles.Admin.String():
				p.Refusal = &Refusal{Code: CodeSelfLockout, Message: "you would no longer be an administrator after this change: keep an admin entry that matches you, or ask another administrator to make it"}
			case c.ByIdentity != roles.Admin.String():
				p.Refusal = &Refusal{Code: CodeSelfLockoutClaims, Message: "you would be an administrator only through a group or an app role. An API token of yours and a session past auth.session.claims_absolute are decided by entries that name you alone, so you would lose the role there: keep an admin entry that names you (an identity, *@domain or oidc:)"}
			}
		}
	}
	if !p.Changed {
		return p, nil
	}
	// the new text of the file
	src, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, err
	}
	p.Source = src
	out := src
	for _, n := range Names {
		if sameSet(cur.Get(n), next.Get(n)) {
			continue
		}
		if out, err = yamledit.SetStringList(out, yamlPath[n], next.Get(n)); err != nil {
			return nil, fmt.Errorf("%w: the console cannot edit %s in this form (%v); change it in rackbook.yml by hand", yamledit.ErrUnsupported, yamlPath[n], err)
		}
	}
	// the result must load and say what was asked, whatever the file looked like
	chk, err := config.Parse(out, cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: the new rackbook.yml would not load: %v", yamledit.ErrUnsupported, err)
	}
	if got, _ := Current(chk); !sameLists(got, next) {
		return nil, fmt.Errorf("%w: the edit would not give the lists you asked for; change them in rackbook.yml by hand", yamledit.ErrUnsupported)
	}
	p.Out = out
	p.Diff = types.UnifiedDiff(p.File, string(src), string(out))
	p.Subject = subject(cur, next, req.Message)
	// the scan every write runs, so that a preview shows a refusal before Save does
	if p.Refusal == nil {
		sc := cfg.SecretScanner()
		if bad, _ := secretscan.Split(secretscan.Introduced(sc.ScanYAML(p.File, src), sc.ScanYAML(p.File, out))); len(bad) > 0 {
			p.Refusal = &Refusal{Code: CodeSecret, Message: (&secretscan.Error{Findings: bad}).Error()}
		}
	}
	return p, nil
}

// signable counts the entries of an admin list through which somebody can sign in.
func signable(list []string, local Local) int {
	n := 0
	for _, s := range list {
		if info, err := roles.Describe(s); err == nil && local.canSignIn(info) {
			n++
		}
	}
	return n
}

func firstError(a Annotated) string {
	for _, n := range Names {
		for _, e := range a.Get(n) {
			for _, nt := range e.Notes {
				if nt.Level == LevelError {
					if strings.TrimSpace(e.Value) == "" {
						return n + ": " + nt.Message
					}
					return n + ": " + fmt.Sprintf("%q: %s", e.Value, nt.Message)
				}
			}
		}
	}
	return ""
}

// sameSet reports whether a and b hold the same strings, as a multiset. The
// order of a list carries no meaning.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func sameLists(a, b Lists) bool {
	for _, n := range Names {
		if !sameSet(a.Get(n), b.Get(n)) {
			return false
		}
	}
	return true
}

// diffs returns the entries added to and removed from one list.
func diffs(before, after []string) (added, removed []string) {
	left := map[string]int{}
	for _, s := range before {
		left[s]++
	}
	for _, s := range after {
		if left[s] > 0 {
			left[s]--
		} else {
			added = append(added, s)
		}
	}
	right := map[string]int{}
	for _, s := range after {
		right[s]++
	}
	for _, s := range before {
		if right[s] > 0 {
			right[s]--
		} else {
			removed = append(removed, s)
		}
	}
	return added, removed
}

// addedWarnings are the warnings of the entries the change adds, with the check
// against the identities that signed in.
func addedWarnings(cur, next Lists, ann Annotated, ids []string) []Warning {
	var out []Warning
	for _, n := range Names {
		added, _ := diffs(cur.Get(n), next.Get(n))
		for _, s := range added {
			for _, e := range ann.Get(n) {
				if e.Value != s {
					continue
				}
				for _, nt := range e.Notes {
					if nt.Level == LevelWarning && nt.Code != NoteDuplicate {
						out = append(out, Warning{List: n, Entry: s, Note: nt})
					}
				}
				if nt, ok := neverSeen(e, ids); ok {
					out = append(out, Warning{List: n, Entry: s, Note: nt})
				}
				break
			}
		}
	}
	return out
}

// neverSeen warns about an identity or *@domain entry that none of the identities
// that signed in matches. Group and app role entries cannot be checked: the claims
// of a sign-in are not kept.
func neverSeen(e Entry, ids []string) (Note, bool) {
	if len(ids) == 0 {
		return Note{}, false
	}
	info, err := roles.Describe(e.Value)
	if err != nil {
		return Note{}, false
	}
	var match func(string) bool
	switch info.Kind {
	case roles.KindIdentity:
		match = func(id string) bool { return id == info.Key }
	case roles.KindDomain:
		suffix := info.Key[1:] // "@example.com"
		match = func(id string) bool { return strings.HasSuffix(id, suffix) }
	case roles.KindOIDC:
		match = func(id string) bool { return id == info.Key }
	default:
		return Note{}, false
	}
	for _, id := range ids {
		if match(id) {
			return Note{}, false
		}
	}
	return Note{Level: LevelWarning, Code: NoteNeverSeen, Message: "nobody who has signed in matches this entry; check the spelling"}, true
}

// subject is the commit subject: the editor's own message, or a short summary.
func subject(before, after Lists, message string) string {
	if m := oneLine(message, 200); m != "" {
		return m
	}
	var parts []string
	for _, n := range Names {
		added, removed := diffs(before.Get(n), after.Get(n))
		var ch []string
		for _, s := range added {
			ch = append(ch, fmt.Sprintf("+%s", s))
		}
		for _, s := range removed {
			ch = append(ch, fmt.Sprintf("-%s", s))
		}
		if len(ch) > 0 {
			parts = append(parts, n+" "+strings.Join(ch, " "))
		}
	}
	return oneLine("roles: "+strings.Join(parts, "; "), 120)
}

// oneLine puts s on one line, without control characters, at most max runes.
func oneLine(s string, max int) string {
	s = strings.Join(strings.FieldsFunc(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s), func(r rune) bool { return r == ' ' }), " ")
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max]) + "…"
	}
	return s
}

func relConfig(cfg *config.Config) string {
	rel, err := filepath.Rel(cfg.Dir, cfg.Path)
	if err != nil {
		return filepath.Base(cfg.Path)
	}
	return filepath.ToSlash(rel)
}

// Apply plans the change against cfg and, when it is allowed and changes
// something, writes rackbook.yml. The result names the file so the caller commits
// it. A change that is not allowed is the plan's *Refusal.
func Apply(cfg *config.Config, req Request) (*edit.Result, error) {
	p, err := Build(cfg, req)
	if err != nil {
		return nil, err
	}
	if p.Refusal != nil {
		return nil, p.Refusal
	}
	res := &edit.Result{Kind: KindRoles, Collection: "auth", ID: "roles"}
	if !p.Changed {
		return res, nil
	}
	sc := cfg.SecretScanner()
	if bad, _ := secretscan.Split(secretscan.Introduced(sc.ScanYAML(p.File, p.Source), sc.ScanYAML(p.File, p.Out))); len(bad) > 0 {
		return nil, &secretscan.Error{Findings: bad}
	}
	if err := edit.WriteFile(cfg.Path, p.Out); err != nil {
		return nil, err
	}
	res.Files = []string{p.File}
	res.SubjectText = p.Subject
	return res, nil
}
