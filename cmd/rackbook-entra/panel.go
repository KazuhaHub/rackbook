package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/modsettings"
	"github.com/kazuhahub/rackbook/modules/rbclient"
)

// withPanel returns a copy of the local config with the settings an
// administrator set in the console. A setting from the console wins over the
// same field in the local file (and a warning says so, so the local line can
// be deleted); a field the console leaves unset keeps its local value. The one
// exception is exclude_app_ids: the two lists are added together (union), so
// the console can only exclude more apps.
func (c *Config) withPanel(s *modsettings.Entra, log *slog.Logger) *Config {
	eff := *c
	eff.Entra.ExcludeAppIDs = append([]string(nil), c.Entra.ExcludeAppIDs...)
	rec := c.Record
	rec.Defaults = maps.Clone(c.Record.Defaults)
	eff.Record = rec

	warn := func(field string, local, panel any) {
		if !reflect.DeepEqual(local, panel) {
			log.Warn("a setting from the Rackbook console overrides the local config; delete it from the local file", "field", field)
		}
	}
	if len(s.ExcludeAppIDs) > 0 {
		// the two lists add up: the console can only exclude more apps, so a
		// console edit never un-freezes an app the local file excludes
		eff.Entra.ExcludeAppIDs = unionIDs(c.Entra.ExcludeAppIDs, s.ExcludeAppIDs)
	}
	if s.ServicePrincipals != nil {
		if c.setServicePrincipals {
			warn("entra.service_principals", c.serviceFlag(), *s.ServicePrincipals)
		}
		v := *s.ServicePrincipals
		eff.Entra.ServicePrincipals = &v
	}
	if s.NamePrefix != nil {
		if c.setNamePrefix {
			warn("record.name_prefix", c.prefix(), *s.NamePrefix)
		}
		v := *s.NamePrefix
		eff.Record.NamePrefix = &v
	}
	if s.Purpose != "" {
		if c.setPurpose {
			warn("record.purpose", c.Record.Purpose, s.Purpose)
		}
		eff.Record.Purpose = s.Purpose
	}
	if len(s.Defaults) > 0 {
		if len(c.Record.Defaults) > 0 {
			warn("record.defaults", norm(c.Record.Defaults), norm(s.Defaults))
		}
		eff.Record.Defaults = maps.Clone(s.Defaults)
	}
	return &eff
}

// unionIDs joins two id lists, ignoring case and keeping the first spelling.
func unionIDs(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if k := strings.ToLower(strings.TrimSpace(s)); k != "" && !seen[k] {
				seen[k] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func lowerSorted(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	sort.Strings(out)
	return out
}

// options are the command line switches that change what one cycle does.
type options struct {
	dry   bool // plan only: ignore the schedule, report nothing
	force bool // run now, ignoring the schedule and a pause
}

// cycle is one start of the program (what the hourly timer does): read the
// settings, decide, sync, report. It returns whether the run failed and
// whether the settings came from the server (the loop then checks hourly).
func (a *app) cycle(ctx context.Context, o options) (failed, panel bool) {
	name := a.base.Rackbook.Source
	chk := a.rb.CheckRun(ctx, name, modsettings.TypeEntra, a.now(), modsettings.DefaultSyncAt)
	a.cfg = a.base
	if chk.Err != nil {
		a.log.Warn("settings from the Rackbook console are not available; using the local config", "err", chk.Err)
	} else {
		a.cfg = a.base.withPanel(chk.Settings.(*modsettings.Entra), a.log)
	}
	d := chk.Decision
	switch {
	case o.dry || o.force:
		if d.Reason != "local" && d.Reason != modsettings.ReasonSlot && d.Reason != modsettings.ReasonRequested {
			a.log.Info("running although not due", "reason", d.Reason, "dry_run", o.dry)
		}
		d.Run = true
	case chk.Panel() && d.Reason == modsettings.ReasonPaused:
		a.log.Info("paused in the Rackbook console, nothing to do")
		now := a.now()
		a.report(ctx, modsettings.Run{Started: now, Finished: now, Status: modsettings.StatusSkipped, Error: "paused"})
		return false, true
	case !d.Run:
		a.log.Info("nothing to do: no sync time has passed since the last run", "reason", d.Reason)
		return false, chk.Panel()
	}
	started := a.now()
	res, err := a.syncOnce(ctx, o.dry)
	if ctx.Err() != nil {
		return false, chk.Panel()
	}
	run := modsettings.Run{Started: started, Finished: a.now(), Status: modsettings.StatusOK,
		Counts: modsettings.Counts{Created: res.Created, Updated: res.Updated, Revoked: res.Revoked}, RunRequest: d.RunRequest}
	if msg := failure(res, err); msg != "" {
		run.Status, run.Error = modsettings.StatusFailed, msg
		a.log.Error("sync failed", "err", msg)
	}
	if !o.dry && chk.Panel() {
		a.report(ctx, run)
	}
	return run.Status == modsettings.StatusFailed, chk.Panel()
}

// failure describes why a sync did not complete, or "". A write that lost a
// race (conflict) is not final, but the run is reported failed so the next
// hourly check tries again instead of waiting for the next sync time.
func failure(res result, err error) string {
	var parts []string
	if err != nil {
		parts = append(parts, err.Error())
	}
	if res.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d writes failed", res.Failed))
	}
	if res.Denied > 0 {
		parts = append(parts, fmt.Sprintf("%d writes refused by Rackbook", res.Denied))
	}
	if res.Conflicts > 0 {
		parts = append(parts, fmt.Sprintf("%d records changed meanwhile, trying again at the next check", res.Conflicts))
	}
	return strings.Join(parts, "; ")
}

func (a *app) report(ctx context.Context, run modsettings.Run) {
	// the run is over; a cancelled context must not lose its report
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := a.rb.ReportRun(rctx, a.base.Rackbook.Source, run); err != nil {
		var e *rbclient.Error
		if errors.As(err, &e) {
			a.log.Warn("run not reported", "status", e.Status, "err", err)
			return
		}
		a.log.Warn("run not reported", "err", err)
	}
}
