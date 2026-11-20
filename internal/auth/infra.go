package auth

import (
	"fmt"
	"strings"

	"github.com/kazuhahub/rackbook/internal/roles"
)

// InfraAdmins is the list of people who may use /infra. It is deliberately
// separate from auth.roles: it comes from a command-line flag, never from the
// data repository the console itself writes to, so nobody can grant it by
// editing the ledger. It admits a person only when they hold a browser login
// session of the built-in OIDC sign-in; API tokens, MCP clients, OAuth access
// tokens, passkey and Cloudflare Access identities never match, whatever
// their role.
type InfraAdmins struct {
	ids map[string]bool
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
	// The identity the login derived from the IdP's identity claim, not the
	// separate e-mail field.
	return a.ids[roles.FoldASCII(id.ID)]
}
