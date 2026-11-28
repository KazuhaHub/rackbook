package auth

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/roles"
)

// InfraAdmins is the list of people who may use /infra. It is deliberately
// separate from auth.roles: it comes from a command-line flag, never from the
// data repository the console itself writes to, so nobody can grant it by
// editing the ledger. It admits a person only when they hold a browser login
// session of the built-in OIDC sign-in; API tokens, MCP clients, OAuth access
// tokens, passkey and Cloudflare Access identities never match, whatever
// their role.
//
// The identity provider that signed them in is pinned too (Pin): the login
// settings in the ledger's rackbook.yml (auth.oidc) can be edited by anyone who
// edits the ledger, so /infra never trusts them. A session counts only when it
// was issued under exactly the pinned issuer and client ID, which come from
// command-line flags.
//
// Beside exact identities the list may hold at most one claim entry, group:<id>
// or app-role:<value>, the syntax of auth.roles. It admits a person whose
// OIDC session carries that group or app role (as the cookie keeps it,
// capped), under the same pins, and only for claims_absolute after the
// sign-in (see Via). It is never read from the ledger either.
type InfraAdmins struct {
	flag     string // the flag this list came from, for messages
	ids      map[string]bool
	issuer   string
	clientID string
	claim    string // the claim the identity is taken from
	tenant   string // the tid of the sign-in (lower case; "" = none)
	maxAge   time.Duration

	claimKind  string // roles.KindGroup or roles.KindAppRole; "" = no claim entry
	claimValue string // the group id (lower case) or the app role value (as written)
	// claimsAbsolute is how long after the sign-in the claim entry counts: the
	// auth.session.claims_absolute the login runs with (0 = DefaultClaimsAbsolute).
	claimsAbsolute time.Duration
}

// How an infra capability was granted, as Via reports it and the audit log records it
// (infra_via).
const (
	InfraViaIdentity = "identity"
	InfraViaGroup    = "group"
	InfraViaAppRole  = "app_role"
)

// DefaultClaimsAbsolute is how long a claim entry counts after the sign-in when no
// configuration says otherwise (the default of auth.session.claims_absolute).
const DefaultClaimsAbsolute = 24 * time.Hour

// DefaultInfraWriteAge is how recent the sign-in must be for a write.
const DefaultInfraWriteAge = 12 * time.Hour

var guidRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// Pin sets what a session must carry: the issuer, the client ID, the claim the
// identity came from (empty = preferred_username) and the tenant (tid). It also
// sets how recent the sign-in must be for a write (0 = DefaultInfraWriteAge).
// The issuer and client ID are required. For an Entra issuer the tenant is
// required too, and a tenant GUID in the issuer URL must equal it. Nothing here
// comes from the ledger's rackbook.yml, which others can edit.
func (a *InfraAdmins) Pin(issuer, clientID, claim, tenant string, writeAge time.Duration) error {
	issuer, clientID, claim, tenant = strings.TrimSpace(issuer), strings.TrimSpace(clientID), strings.TrimSpace(claim), roles.FoldASCII(strings.TrimSpace(tenant))
	if issuer == "" || clientID == "" {
		return fmt.Errorf("the infra pages need --infra-oidc-issuer and --infra-oidc-client-id (the identity provider is not taken from the ledger's rackbook.yml)")
	}
	if a.claimKind != "" && tenant == "" {
		return fmt.Errorf("%s: a %s: entry needs --infra-oidc-issuer, --infra-oidc-client-id and --infra-oidc-tenant all set (the group or role is only believed from the pinned provider and tenant)", a.flagName(), a.claimKind)
	}
	if claim == "" {
		claim = "preferred_username"
	}
	if writeAge < 0 {
		return fmt.Errorf("--infra-write-max-age must not be negative")
	}
	if writeAge == 0 {
		writeAge = DefaultInfraWriteAge
	}
	if u, err := url.Parse(issuer); err == nil {
		entra := u.Host == "login.microsoftonline.com" || u.Host == "sts.windows.net" || strings.HasSuffix(u.Host, ".b2clogin.com")
		if entra && tenant == "" {
			return fmt.Errorf("--infra-oidc-tenant is required for an Entra issuer (the tid of the sign-in)")
		}
		if g := guidRe.FindString(u.Path); g != "" && tenant != "" && roles.FoldASCII(g) != tenant {
			return fmt.Errorf("--infra-oidc-tenant %s is not the tenant in --infra-oidc-issuer (%s)", tenant, roles.FoldASCII(g))
		}
	}
	a.issuer, a.clientID, a.claim, a.tenant, a.maxAge = issuer, clientID, claim, tenant, writeAge
	return nil
}

// WriteAge is how recent a sign-in must be for a write.
func (a *InfraAdmins) WriteAge() time.Duration {
	if a == nil || a.maxAge <= 0 {
		return DefaultInfraWriteAge
	}
	return a.maxAge
}

// NewInfraAdmins parses the entries of --infra-admins: exact identities (e-mail
// or UPN, matched like auth.roles: case-insensitively, folding ASCII letters
// only), and at most one claim entry, group:<id> or app-role:<value>, in the
// syntax and with the parser of auth.roles. Every other kind of entry is
// refused: this list names people one by one, or one group or app role.
func NewInfraAdmins(entries []string) (*InfraAdmins, error) {
	return newInfraList("--infra-admins", entries)
}

// NewInfraAuditors is NewInfraAdmins for --infra-auditors: the same kind of
// list with the same rules (its own single claim entry, independent of the
// administrators'), and it must be pinned (Pin) to the same issuer, client,
// claim and tenant. The people on it may read /infra but not the secrets, and
// may not change anything. The type is shared, so every rule that protects the
// administrators' list (OIDC sessions only, never tokens, the pinned provider)
// holds for it too.
func NewInfraAuditors(entries []string) (*InfraAdmins, error) {
	return newInfraList("--infra-auditors", entries)
}

func (a *InfraAdmins) flagName() string {
	if a.flag == "" {
		return "--infra-admins"
	}
	return a.flag
}

func newInfraList(flag string, entries []string) (*InfraAdmins, error) {
	a := &InfraAdmins{flag: flag, ids: map[string]bool{}}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		info, err := roles.Describe(e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", flag, err)
		}
		switch info.Kind {
		case roles.KindGroup, roles.KindAppRole:
			if a.claimKind != "" {
				return nil, fmt.Errorf("%s: at most one group: or app-role: entry (%q and %q); give the group or app role you want, and name the rest one by one", flag, a.claimKind+":"+a.claimValue, e)
			}
			a.claimKind, a.claimValue = info.Kind, info.Value
		case roles.KindIdentity, roles.KindOIDC:
			if strings.ContainsAny(e, "*? \t") {
				return nil, fmt.Errorf("%s: %q is not one exact identity (no wildcards)", flag, e)
			}
			a.ids[roles.FoldASCII(e)] = true
		default:
			return nil, fmt.Errorf("%s: %q is not allowed: no wildcards (* or *@domain) and no oauth:, mcphub: or local: entries, only exact identities and at most one group: or app-role: entry", flag, e)
		}
	}
	if len(a.ids) == 0 && a.claimKind == "" {
		return nil, fmt.Errorf("%s names nobody", flag)
	}
	return a, nil
}

// SetClaimsAbsolute tells the list how long, after a sign-in, its claim entry
// counts: the auth.session.claims_absolute the login runs with, read once at start
// like the login's own, so editing rackbook.yml cannot lengthen it. Without it the
// default of that setting applies.
func (a *InfraAdmins) SetClaimsAbsolute(d time.Duration) {
	if a != nil {
		a.claimsAbsolute = d
	}
}

// ClaimsAbsolute is how long after a sign-in the claim entry counts.
func (a *InfraAdmins) ClaimsAbsolute() time.Duration {
	if a != nil && a.claimsAbsolute > 0 {
		return a.claimsAbsolute
	}
	return DefaultClaimsAbsolute
}

// ClaimEntry is the claim entry in the syntax of auth.roles ("group:<id>" or
// "app-role:<value>"), or "" when the list has none.
func (a *InfraAdmins) ClaimEntry() string {
	if a == nil || a.claimKind == "" {
		return ""
	}
	return a.claimKind + ":" + a.claimValue
}

// Allows reports whether id is on the list now (see Via).
func (a *InfraAdmins) Allows(id *Identity) bool { return a.Via(id, time.Now()) != "" }

// Via says how id is on the list at the time now: InfraViaIdentity for a listed
// identity, InfraViaGroup or InfraViaAppRole for the claim entry, "" for not at
// all. A nil list allows nobody.
//
// Either way the person must hold a browser login session of the OIDC sign-in
// (never an API token, an OAuth or MCP grant, MCPHub, a passkey or a local
// account), issued under the pinned issuer, client, claim and tenant.
//
// The claim entry counts only if the group or app role is in the session's
// capped lists, so a claim that was dropped or cut (an overage) matches
// nothing, and only for claims_absolute after the sign-in. Both are decided
// here, on every request, from the signed cookie's values: nothing is stored
// that an old cookie could replay. A listed identity wins and has no such limit.
// A login named by its subject (identity claim sub) matches the claim entry
// never, as in auth.roles.
func (a *InfraAdmins) Via(id *Identity, now time.Time) string {
	if a == nil || id == nil || id.Method != MethodOIDC || id.Token != "" || id.ID == "" {
		return ""
	}
	// Signed in under the pinned provider and client only; a session issued
	// under any other (for example after auth.oidc was edited in the ledger)
	// is refused. Unpinned = nobody.
	if a.issuer == "" || id.OIDCIssuer != a.issuer || id.OIDCClient != a.clientID || id.OIDCClaim != a.claim || id.OIDCTenant != a.tenant {
		return ""
	}
	// The identity the login derived from the IdP's identity claim, not the
	// separate e-mail field.
	if a.ids[roles.FoldASCII(id.ID)] {
		return InfraViaIdentity
	}
	if a.claimKind == "" || strings.HasPrefix(id.ID, "oidc:") || id.OIDCAt.IsZero() {
		return ""
	}
	if age := now.Sub(id.OIDCAt); age < -time.Minute || age >= a.ClaimsAbsolute() {
		return ""
	}
	switch a.claimKind {
	case roles.KindGroup:
		for _, g := range id.Groups {
			if roles.FoldASCII(strings.TrimSpace(g)) == a.claimValue {
				return InfraViaGroup
			}
		}
	case roles.KindAppRole:
		if slices.Contains(id.AppRoles, a.claimValue) {
			return InfraViaAppRole
		}
	}
	return ""
}

// ClaimEnds is when the claim entry stops counting for id's session: the sign-in
// plus claims_absolute. Zero when the list has no claim entry or id has no sign-in time.
func (a *InfraAdmins) ClaimEnds(id *Identity) time.Time {
	if a == nil || a.claimKind == "" || id == nil || id.OIDCAt.IsZero() {
		return time.Time{}
	}
	return id.OIDCAt.Add(a.ClaimsAbsolute())
}

// Fresh reports whether id signed in recently enough for a write.
func (a *InfraAdmins) Fresh(id *Identity, now time.Time) bool {
	if id == nil || id.OIDCAt.IsZero() {
		return false
	}
	age := now.Sub(id.OIDCAt)
	return age >= -time.Minute && age < a.WriteAge()
}

// Len is the number of people on the list (0 for a nil list).
func (a *InfraAdmins) Len() int {
	if a == nil {
		return 0
	}
	return len(a.ids)
}

// InfraAccess is the pair of lists, for the parts that look at both: the
// sign-in event, the account page and the audit trail. Nil lists allow nobody.
type InfraAccess struct {
	Admins, Auditors *InfraAdmins
}

// Via is how id is an infra administrator and how an infra auditor ("" = not).
func (c *InfraAccess) Via(id *Identity, now time.Time) (admin, auditor string) {
	if c == nil {
		return "", ""
	}
	return c.Admins.Via(id, now), c.Auditors.Via(id, now)
}

// Overage says which claim a sign-in could not use for a claim entry that is set:
// "groups", "app_roles" or both joined by a comma, or "" when nothing was lost that
// mattered. cutGroups and cutRoles say that the list was dropped or cut at the
// sign-in. It names only a list that a configured, unmatched claim entry needs, so
// a person who was matched anyway (or who needs no claim) records nothing.
func (c *InfraAccess) Overage(id *Identity, now time.Time, cutGroups, cutRoles bool) string {
	if c == nil || (!cutGroups && !cutRoles) {
		return ""
	}
	var g, r bool
	for _, l := range []*InfraAdmins{c.Admins, c.Auditors} {
		if l == nil || l.claimKind == "" || l.Via(id, now) != "" {
			continue
		}
		g = g || (cutGroups && l.claimKind == roles.KindGroup)
		r = r || (cutRoles && l.claimKind == roles.KindAppRole)
	}
	switch {
	case g && r:
		return "groups,app_roles"
	case g:
		return "groups"
	case r:
		return "app_roles"
	}
	return ""
}
