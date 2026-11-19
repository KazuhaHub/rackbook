package modules

import (
	"sort"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/modsettings"
)

// Effects of a settings change on a record.
const (
	// EffectFrozen: the sync no longer touches the record. An excluded app's
	// credentials are skipped, not retired (cmd/rackbook-entra, liveCredentials:
	// they count as "protected"), so the record keeps its last values.
	EffectFrozen = "frozen"
	// EffectMaybeRevoked: with service principals off, the sync no longer reads
	// them, and a record whose credential is found nowhere else is marked
	// revoked. The ledger does not say which side a record came from, so this
	// lists every active record the module keeps; rackbook-entra --dry-run says
	// exactly which.
	EffectMaybeRevoked = "maybe_revoked"
)

// Affected is a record a settings change touches.
type Affected struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Expires string `json:"expires,omitempty"`
	Effect  string `json:"effect"`
}

// Impact lists what a change does to the records the module keeps.
type Impact struct {
	Records []Affected `json:"records"`
	// Risky says the change is of a kind that can retire or freeze records, so
	// the console asks first even when Records is empty.
	Risky bool `json:"risky"`
}

func spOn(e *modsettings.Entra) bool { return e.ServicePrincipals == nil || *e.ServicePrincipals }

// PreviewImpact computes what moving the module from its current settings to
// next does to its records, with the rules rackbook-entra applies in sync.go:
// credentials of an excluded app are left alone, credentials that are no longer
// read are marked revoked. Only entra modules have an impact.
func PreviewImpact(cfg *config.Config, name string, next modsettings.Settings) Impact {
	m := cfg.Modules[name]
	out := Impact{Records: []Affected{}}
	if m == nil || m.Type != modsettings.TypeEntra || m.ReadOnly() {
		return out
	}
	old, _ := m.ParsedSettings().(*modsettings.Entra)
	nw, _ := next.(*modsettings.Entra)
	if old == nil || nw == nil {
		return out
	}
	was := map[string]bool{}
	for _, id := range old.ExcludeAppIDs {
		was[strings.ToLower(id)] = true
	}
	added := map[string]bool{}
	for _, id := range nw.ExcludeAppIDs {
		if id = strings.ToLower(id); !was[id] {
			added[id] = true
		}
	}
	spOff := spOn(old) && !spOn(nw)
	out.Risky = len(added) > 0 || spOff
	if !out.Risky {
		return out
	}
	col := ledger.Load(cfg, nil).Collection(m.Collection)
	if col == nil {
		return out
	}
	excluded := map[string]bool{}
	for _, id := range nw.ExcludeAppIDs {
		excluded[strings.ToLower(id)] = true
	}
	for _, r := range col.Records {
		if str(r.Data, "source") != name {
			continue
		}
		if v := r.Data["revoked"]; v != nil && v != "" {
			continue // already retired
		}
		a := Affected{ID: r.ID, Label: label(r), Expires: str(r.Data, "expires")}
		switch {
		case appExcluded(r.Data, excluded):
			if appExcluded(r.Data, added) {
				a.Effect = EffectFrozen
			} else {
				continue // excluded before this change: nothing new
			}
		case spOff:
			a.Effect = EffectMaybeRevoked
		default:
			continue
		}
		out.Records = append(out.Records, a)
	}
	sort.Slice(out.Records, func(i, j int) bool { return out.Records[i].ID < out.Records[j].ID })
	return out
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func label(r *ledger.Record) string {
	if n := str(r.Data, "name"); n != "" {
		return n
	}
	return r.ID
}

// appExcluded reports whether the record's ids name one of the apps
// (entra_app_id=<uuid>, as rackbook-entra writes it).
func appExcluded(data map[string]any, apps map[string]bool) bool {
	if len(apps) == 0 {
		return false
	}
	ids, _ := data["ids"].([]any)
	for _, v := range ids {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if k, val, found := strings.Cut(s, "="); found && strings.EqualFold(k, "entra_app_id") && apps[strings.ToLower(strings.TrimSpace(val))] {
			return true
		}
	}
	return false
}
