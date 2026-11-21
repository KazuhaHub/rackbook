package auth

import (
	"fmt"
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
type InfraAdmins struct {
	ids      map[string]bool
	issuer   string
	clientID string
	maxAge   time.Duration
}

// DefaultInfraWriteAge is how recent the sign-in must be for a write.
const DefaultInfraWriteAge = 12 * time.Hour

// Pin sets the issuer and client ID a session must carry, and how recent the
// sign-in must be for a write (0 = DefaultInfraWriteAge). Both pins are required.
func (a *InfraAdmins) Pin(issuer, clientID string, writeAge time.Duration) error {
	issuer, clientID = strings.TrimSpace(issuer), strings.TrimSpace(clientID)
	if issuer == "" || clientID == "" {
		return fmt.Errorf("the infra pages need --infra-oidc-issuer and --infra-oidc-client-id (the identity provider is not taken from the ledger's rackbook.yml)")
	}
	if writeAge < 0 {
		return fmt.Errorf("--infra-write-max-age must not be negative")
	}
	if writeAge == 0 {
		writeAge = DefaultInfraWriteAge
	}
	a.issuer, a.clientID, a.maxAge = issuer, clientID, writeAge
	return nil
}

// WriteAge is how recent a sign-in must be for a write.
func (a *InfraAdmins) WriteAge() time.Duration {
	if a == nil || a.maxAge <= 0 {
		return DefaultInfraWriteAge
	}
	return a.maxAge
}

// NewInfraAdmins parses the exact identities (e-mail or UPN, matched like
// auth.roles: case-insensitively, folding ASCII letters only). Wildcards and
// prefixed entries are refused: this list names people one by one.
func NewInfraAdmins(entries []string) (*InfraAdmins, error) {
	a := &InfraAdmins{ids: map[string]bool{}}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.ContainsAny(e, "*? \t") {
			return nil, fmt.Errorf("--infra-admins: %q is not one exact identity (no wildcards)", e)
		}
		a.ids[roles.FoldASCII(e)] = true
	}
	if len(a.ids) == 0 {
		return nil, fmt.Errorf("--infra-admins names nobody")
	}
	return a, nil
}

// Allows reports whether id is a listed person signed in through the OIDC
// login. A nil InfraAdmins allows nobody.
func (a *InfraAdmins) Allows(id *Identity) bool {
	if a == nil || id == nil || id.Method != MethodOIDC || id.Token != "" || id.ID == "" {
		return false
	}
	// Signed in under the pinned provider and client only; a session issued
	// under any other (for example after auth.oidc was edited in the ledger)
	// is refused. Unpinned = nobody.
	if a.issuer == "" || id.OIDCIssuer != a.issuer || id.OIDCClient != a.clientID {
		return false
	}
	// The identity the login derived from the IdP's identity claim, not the
	// separate e-mail field.
	return a.ids[roles.FoldASCII(id.ID)]
}

// Fresh reports whether id signed in recently enough for a write.
func (a *InfraAdmins) Fresh(id *Identity, now time.Time) bool {
	if id == nil || id.OIDCAt.IsZero() {
		return false
	}
	age := now.Sub(id.OIDCAt)
	return age >= -time.Minute && age < a.WriteAge()
}
