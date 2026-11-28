// Package audit is the append-only, hash-chained audit log kept under
// <state-dir>/audit (docs/design-audit.md, section 3.1).
package audit

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
)

// Event is one line of the log. Only the fields that apply are set.
type Event struct {
	Seq      int64     `json:"seq"`
	Time     time.Time `json:"time"`
	Event    string    `json:"event"`
	Identity string    `json:"identity,omitempty"`
	Name     string    `json:"name,omitempty"`
	Method   string    `json:"method,omitempty"`
	Role     string    `json:"role,omitempty"`
	Addr     string    `json:"addr,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Code     string    `json:"code,omitempty"`
	Area     string    `json:"area,omitempty"`
	Repo     string    `json:"repo,omitempty"`
	Hash     string    `json:"hash,omitempty"`
	Record   string    `json:"record,omitempty"`
	Action   string    `json:"action,omitempty"`
	Outcome  string    `json:"outcome,omitempty"`
	Host     string    `json:"host,omitempty"`
	Key      string    `json:"key,omitempty"`
	Files    []string  `json:"files,omitempty"`
	Detail   []string  `json:"detail,omitempty"`
	// Groups and AppRoles are "overage" on a login whose groups or roles claim was
	// cut off: the identity provider sent no groups at all (Entra, past 200 groups),
	// or more than the session keeps. The sign-in succeeded without the lost values.
	Groups   string `json:"groups,omitempty"`
	AppRoles string `json:"app_roles,omitempty"`
	// InfraVia is how the person was an infra administrator when the event happened:
	// identity (a listed identity), group or app_role (the claim entry of
	// --infra-admins). InfraAuditorVia is the same for --infra-auditors, on a login. InfraOverage
	// is on a login whose claim entry was not matched because the list it needs was cut
	// off or dropped: groups, app_roles or both.
	InfraVia        string `json:"infra_via,omitempty"`
	InfraAuditorVia string `json:"infra_auditor_via,omitempty"`
	InfraOverage    string `json:"infra_overage,omitempty"`
	// role_changed: the effective role and auditor capability before and after, and
	// why the difference was seen (CauseSignIn or CauseConfig).
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	AuditorFrom *bool  `json:"auditor_from,omitempty"`
	AuditorTo   *bool  `json:"auditor_to,omitempty"`
	Cause       string `json:"cause,omitempty"`
	// Prev is "sha256:<hex>" of the previous line, "" for the first line ever.
	Prev string `json:"prev"`
}

// By fills the identity fields from who. A request made with an API token
// carries the token's name in Detail, as the commit trailer does.
func (e *Event) By(who *auth.Identity) {
	if who == nil {
		return
	}
	e.Identity, e.Name, e.Method = who.ID, who.Name, who.Method
	e.InfraVia = who.InfraVia
	if who.Token != "" {
		e.Detail = append(e.Detail, "token:"+who.Token)
	}
}

// AddrMode says how much of a client address is kept.
type AddrMode string

const (
	AddrFull     AddrMode = "full"
	AddrTruncate AddrMode = "truncate" // IPv4 without the last octet, IPv6 first 48 bits
	AddrNone     AddrMode = "none"
)

// ParseAddrMode validates the --audit-addr value ("" is the default, truncate).
func ParseAddrMode(s string) (AddrMode, error) {
	switch m := AddrMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return AddrTruncate, nil
	case AddrFull, AddrTruncate, AddrNone:
		return m, nil
	}
	return "", fmt.Errorf("--audit-addr must be full, truncate or none, got %q", s)
}

// applyAddr returns addr as it is stored under mode. internal/clientip names
// an IPv6 client by its /64 ("2001:db8:1:2::/64"); that form is accepted too.
func applyAddr(addr string, mode AddrMode) string {
	switch mode {
	case AddrNone:
		return ""
	case AddrFull:
		return addr
	}
	if addr == "" {
		return ""
	}
	var a netip.Addr
	if p, err := netip.ParsePrefix(addr); err == nil {
		a = p.Addr()
	} else if a, err = netip.ParseAddr(addr); err != nil {
		return ""
	}
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	return netip.PrefixFrom(a, bits).Masked().Addr().String()
}
