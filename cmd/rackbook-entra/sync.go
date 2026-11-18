package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/modules/rbclient"
)

const dateLayout = "2006-01-02"

var (
	nonSlugRe = regexp.MustCompile(`[^a-z0-9]+`)
	tagRe     = regexp.MustCompile(`\s*\[[^\]]*\]\s*$`)
)

func slug(s string) string {
	s = strings.Trim(nonSlugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		return "app"
	}
	return s
}

func family(displayName string) string {
	return strings.TrimSpace(tagRe.ReplaceAllString(displayName, ""))
}

func shortKey(keyID string) string {
	k := strings.ToLower(keyID)
	if len(k) > 8 {
		k = k[:8]
	}
	return k
}

type dedupKey struct{ app, key string }

func rank(c credential) int {
	r := 0
	if c.OwnerKind != "application" {
		r += 2
	}
	if c.Type != "certificate" {
		r++
	}
	return r
}

// liveCredentials applies the exclusion list, the end-date rule, the
// de-duplication and the rotation rule. protected holds key ids the module
// must not mark revoked although they are not live (excluded or undated).
func liveCredentials(cfg *Config, now time.Time, creds []credential, log *slog.Logger) (live []credential, protected map[string]bool) {
	protected = map[string]bool{}
	excl := map[string]bool{}
	for _, e := range cfg.Entra.ExcludeAppIDs {
		excl[strings.ToLower(strings.TrimSpace(e))] = true
	}
	best := map[dedupKey]credential{}
	for _, c := range creds {
		kid := strings.ToLower(c.KeyID)
		if excl[strings.ToLower(c.AppID)] || excl[strings.ToLower(c.OwnerID)] {
			protected[kid] = true
			continue
		}
		if c.End == nil {
			log.Warn("skipping credential without end date", "app", c.AppName, "app_id", c.AppID, "key_id", c.KeyID, "type", c.Type)
			protected[kid] = true
			continue
		}
		k := dedupKey{strings.ToLower(c.AppID), kid}
		if old, ok := best[k]; !ok || rank(c) < rank(old) {
			best[k] = c
		}
	}
	all := make([]credential, 0, len(best))
	for _, c := range best {
		all = append(all, c)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].AppID != all[j].AppID {
			return all[i].AppID < all[j].AppID
		}
		return all[i].KeyID < all[j].KeyID
	})

	type famKey struct{ app, typ, fam string }
	unexpired := map[famKey]bool{}
	for _, c := range all {
		if c.End.After(now) {
			unexpired[famKey{strings.ToLower(c.AppID), c.Type, family(c.DisplayName)}] = true
		}
	}
	for _, c := range all {
		if !c.End.After(now) && unexpired[famKey{strings.ToLower(c.AppID), c.Type, family(c.DisplayName)}] {
			log.Info("credential superseded by a newer one", "app", c.AppName, "key_id", c.KeyID, "type", c.Type)
			continue
		}
		live = append(live, c)
	}
	return live, protected
}

func (cfg *Config) recordName(c credential) string {
	return cfg.prefix() + slug(c.AppName) + "-" + shortKey(c.KeyID)
}

func (cfg *Config) typeFields(c credential) map[string]any {
	if c.Type == "certificate" {
		return cfg.Record.Certificate
	}
	return cfg.Record.Password
}

// ownedFields are the fields the module maintains for a credential.
func (cfg *Config) ownedFields(c credential) map[string]any {
	f := map[string]any{}
	maps.Copy(f, cfg.typeFields(c))
	label := cfg.Record.TypeLabels[c.Type]
	f["purpose"] = strings.NewReplacer(
		"{app}", c.AppName, "{name}", c.DisplayName, "{type}", label,
		"{owner}", c.OwnerKind, "{app_id}", strings.ToLower(c.AppID),
	).Replace(cfg.Record.Purpose)
	f["expires"] = c.End.UTC().Format(dateLayout)
	if c.Start != nil {
		f["not_before"] = c.Start.UTC().Format(dateLayout)
	}
	f["kid"] = strings.ToLower(c.KeyID)
	f["ids"] = []string{
		"entra_app_id=" + strings.ToLower(c.AppID),
		"entra_tenant_id=" + strings.ToLower(cfg.Entra.TenantID),
	}
	f["source"] = cfg.Rackbook.Source
	return f
}

func (cfg *Config) newRecord(c credential) map[string]any {
	d := map[string]any{}
	maps.Copy(d, cfg.Record.Defaults)
	d["name"] = cfg.recordName(c)
	maps.Copy(d, cfg.ownedFields(c))
	return d
}

func (cfg *Config) updatedRecord(c credential, old map[string]any) map[string]any {
	d := map[string]any{}
	maps.Copy(d, old)
	delete(d, "not_before")
	delete(d, "revoked")
	maps.Copy(d, cfg.ownedFields(c))
	return d
}

func norm(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}

func changedFields(old, nw map[string]any) []string {
	var out []string
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range nw {
		keys[k] = true
	}
	for k := range keys {
		ov, oka := old[k]
		nv, okb := nw[k]
		if oka != okb || !reflect.DeepEqual(norm(ov), norm(nv)) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func hasID(m map[string]any, want string) bool {
	ids, _ := m["ids"].([]any)
	for _, v := range ids {
		if s, ok := v.(string); ok && strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// action is one planned write.
type action struct {
	Kind    string // create | update | revoke
	Name    string
	ID      string
	Hash    string
	Data    map[string]any
	Changed []string
}

type planStats struct {
	Live, Covered, Unchanged int
}

func buildPlan(cfg *Config, now time.Time, creds []credential, records []rbclient.Record, log *slog.Logger) ([]action, planStats) {
	var st planStats
	live, protected := liveCredentials(cfg, now, creds, log)
	source := cfg.Rackbook.Source

	own := map[string]rbclient.Record{}
	var manual []rbclient.Record
	for _, r := range records {
		if str(r.Data, "source") == source {
			kid := strings.ToLower(str(r.Data, "kid"))
			if kid == "" {
				continue
			}
			if _, dup := own[kid]; dup {
				log.Warn("two records carry the same kid, using the first", "kid", kid)
				continue
			}
			own[kid] = r
		} else {
			manual = append(manual, r)
		}
	}
	covered := func(c credential) bool {
		kid := strings.ToLower(c.KeyID)
		want := "entra_app_id=" + strings.ToLower(c.AppID)
		exp := c.End.UTC().Format(dateLayout)
		for _, r := range manual {
			if strings.EqualFold(str(r.Data, "kid"), kid) {
				return true
			}
			if hasID(r.Data, want) && str(r.Data, "expires") == exp {
				return true
			}
		}
		return false
	}

	var plan []action
	liveKids := map[string]bool{}
	for _, c := range live {
		kid := strings.ToLower(c.KeyID)
		liveKids[kid] = true
		st.Live++
		rec, ok := own[kid]
		if !ok {
			if covered(c) {
				st.Covered++
				log.Info("covered by a manual record, leaving alone", "app", c.AppName, "key_id", c.KeyID)
				continue
			}
			d := cfg.newRecord(c)
			plan = append(plan, action{Kind: "create", Name: str(d, "name"), Data: d})
			continue
		}
		nd := cfg.updatedRecord(c, rec.Data)
		ch := changedFields(rec.Data, nd)
		if len(ch) == 0 {
			st.Unchanged++
			continue
		}
		plan = append(plan, action{Kind: "update", Name: recName(rec), ID: rec.ID, Hash: rec.Hash, Data: nd, Changed: ch})
	}

	today := now.UTC().Format(dateLayout)
	kids := make([]string, 0, len(own))
	for k := range own {
		kids = append(kids, k)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		rec := own[kid]
		if liveKids[kid] || protected[kid] {
			continue
		}
		if v := rec.Data["revoked"]; v != nil && v != "" {
			continue
		}
		nd := map[string]any{}
		maps.Copy(nd, rec.Data)
		nd["revoked"] = today
		plan = append(plan, action{Kind: "revoke", Name: recName(rec), ID: rec.ID, Hash: rec.Hash, Data: nd, Changed: []string{"revoked"}})
	}
	return plan, st
}

func recName(r rbclient.Record) string {
	if n := str(r.Data, "name"); n != "" {
		return n
	}
	return r.ID
}

// result summarises one run.
type result struct {
	Created, Updated, Revoked, Conflicts, Denied, Failed int
}

func (r result) writes() int { return r.Created + r.Updated + r.Revoked }

// app holds everything one sync needs.
type app struct {
	cfg   *Config
	graph *graphClient
	rb    *rbclient.Client
	out   io.Writer
	now   func() time.Time
	log   *slog.Logger
}

func (a *app) syncOnce(ctx context.Context, dry bool) (result, error) {
	var res result
	creds, err := a.graph.fetchCredentials(ctx, a.cfg.serviceFlag())
	if err != nil {
		return res, err
	}
	records, err := a.rb.List(ctx, a.cfg.Rackbook.Collection)
	if err != nil {
		return res, fmt.Errorf("list %s: %w", a.cfg.Rackbook.Collection, err)
	}
	plan, st := buildPlan(a.cfg, a.now(), creds, records, a.log)
	a.log.Info("plan", "credentials", len(creds), "live", st.Live, "covered_by_manual", st.Covered, "unchanged", st.Unchanged, "actions", len(plan), "dry_run", dry)

	col := a.cfg.Rackbook.Collection
	for _, p := range plan {
		if dry {
			fmt.Fprintln(a.out, describe(p))
			continue
		}
		var err error
		if p.Kind == "create" {
			_, err = a.rb.Create(ctx, col, p.Data)
		} else {
			_, err = a.rb.Update(ctx, col, p.ID, p.Hash, p.Data)
		}
		var re *rbclient.Error
		switch {
		case err == nil:
			a.log.Info(p.Kind, "record", p.Name, "fields", p.Changed)
			switch p.Kind {
			case "create":
				res.Created++
			case "update":
				res.Updated++
			default:
				res.Revoked++
			}
		case rbclient.IsConflict(err):
			res.Conflicts++
			a.log.Warn("conflict, will retry on the next run", "action", p.Kind, "record", p.Name)
		case errors.As(err, &re) && re.Status == http.StatusForbidden:
			res.Denied++
			a.log.Error("write refused by Rackbook", "action", p.Kind, "record", p.Name, "message", re.Message)
		default:
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			res.Failed++
			a.log.Error("write failed", "action", p.Kind, "record", p.Name, "err", err)
		}
	}
	a.log.Info("sync done", "created", res.Created, "updated", res.Updated, "revoked", res.Revoked, "conflicts", res.Conflicts, "denied", res.Denied, "failed", res.Failed)
	return res, nil
}

func describe(p action) string {
	switch p.Kind {
	case "create":
		return fmt.Sprintf("create %s (expires %s)", p.Name, str(p.Data, "expires"))
	case "revoke":
		return fmt.Sprintf("revoke %s (revoked %s)", p.Name, str(p.Data, "revoked"))
	}
	return fmt.Sprintf("update %s: %s", p.Name, strings.Join(p.Changed, ", "))
}
