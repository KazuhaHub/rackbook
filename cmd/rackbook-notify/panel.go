package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/modsettings"
	"github.com/kazuhahub/rackbook/modules/rbclient"
)

// withPanel returns a copy of the local config with the settings an
// administrator set in the console. A setting from the console wins over the
// same field in the local file (a warning says so, so the local line can be
// deleted); a field the console leaves unset keeps its local value.
func (c *Config) withPanel(s *modsettings.Notify, log *slog.Logger) *Config {
	eff := *c
	warn := func(field string) {
		log.Warn("a setting from the Rackbook console overrides the local config; delete it from the local file", "field", field)
	}
	if len(s.Thresholds) > 0 {
		if c.setThresholds && !reflect.DeepEqual(c.Thresholds, s.Thresholds) {
			warn("thresholds")
		}
		eff.Thresholds = append([]int(nil), s.Thresholds...)
	}
	if s.Language != "" {
		if c.setLanguage && c.Language != s.Language {
			warn("language")
		}
		eff.Language = s.Language
	}
	if len(s.Collections) > 0 {
		if c.setCollections && !reflect.DeepEqual(c.Collections, s.Collections) {
			warn("collections")
		}
		eff.Collections = append([]string(nil), s.Collections...)
	}
	if len(s.Recipients) > 0 {
		switch {
		case c.SMTP == nil:
			log.Warn("recipients are set in the Rackbook console, but the local config has no smtp section; they are ignored")
		default:
			smtp := *c.SMTP
			if len(smtp.To) > 0 && !sameAddresses(smtp.To, s.Recipients) {
				warn("smtp.to")
			}
			smtp.To = append([]string(nil), s.Recipients...)
			eff.SMTP = &smtp
		}
	}
	return &eff
}

// sameAddresses compares two address lists as sets, ignoring case.
func sameAddresses(a, b []string) bool {
	return reflect.DeepEqual(foldSet(a), foldSet(b))
}

func foldSet(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(strings.TrimSpace(s))
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// options are the command line switches that change what one cycle does.
type options struct {
	dry   bool // print the digest, send and save nothing; ignores the schedule
	force bool // run now, ignoring the schedule and a pause
}

// cycle is one start of the program (what the hourly timer does): read the
// settings, announce a change of recipients, decide, send, report. It returns
// whether the run failed and whether the settings came from the server (the
// loop then checks hourly).
func (n *notifier) cycle(ctx context.Context, o options) (failed, panel bool) {
	name := n.base.Rackbook.Module
	chk := n.client.CheckRun(ctx, name, modsettings.TypeNotify, n.now(), modsettings.DefaultSendAt)
	n.cfg = n.base
	if chk.Err != nil {
		n.log.Warn("settings from the Rackbook console are not available; using the local config", "err", chk.Err)
		n.useRememberedRecipients()
	} else {
		n.cfg = n.base.withPanel(chk.Settings.(*modsettings.Notify), n.log)
	}
	d := chk.Decision
	switch {
	case o.dry || o.force:
		if d.Reason != "local" && d.Reason != modsettings.ReasonSlot && d.Reason != modsettings.ReasonRequested {
			n.log.Info("running although not due", "reason", d.Reason, "dry_run", o.dry)
		}
		d.Run = true
	case chk.Panel() && d.Reason == modsettings.ReasonPaused:
		n.log.Info("paused in the Rackbook console, nothing to do")
		now := n.now()
		n.report(ctx, modsettings.Run{Started: now, Finished: now, Status: modsettings.StatusSkipped, Error: "paused"})
		return false, true
	}
	// Only settings that really came from the console can change the
	// recipients; a failed fetch must not look like a change.
	if !o.dry && chk.Panel() {
		if err := n.announceRecipients(ctx); err != nil && ctx.Err() == nil {
			n.log.Warn("could not announce the change of recipients; the new list is in use and the notice is not retried", "err", err)
		}
	}
	if !d.Run {
		n.log.Info("nothing to do: no send time has passed since the last run", "reason", d.Reason)
		return false, chk.Panel()
	}
	started := n.now()
	n.sent = 0
	err := n.run(ctx)
	if ctx.Err() != nil {
		return false, chk.Panel()
	}
	run := modsettings.Run{Started: started, Finished: n.now(), Status: modsettings.StatusOK, Counts: modsettings.Counts{Sent: n.sent}, RunRequest: d.RunRequest}
	if err != nil {
		run.Status, run.Error = modsettings.StatusFailed, err.Error()
		n.log.Error("run failed", "error", err)
	}
	if !o.dry && chk.Panel() {
		n.report(ctx, run)
	}
	return err != nil, chk.Panel()
}

func (n *notifier) report(ctx context.Context, run modsettings.Run) {
	// the run is over; a cancelled context must not lose its report
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := n.client.ReportRun(rctx, n.base.Rackbook.Module, run); err != nil {
		n.log.Warn("run not reported", "err", err)
	}
}

// failures reads the last run of every module and returns the failed ones that
// no digest has reported yet (the module itself is left out), and the
// FailedSeen map to save once they are reported: every module that still has a
// failed last run. A server without the status endpoint (older than v0.5.0, or
// this token is not a notify module's) reports none and changes nothing.
func (n *notifier) failures(ctx context.Context, st *State) (fresh []modsettings.ModuleStatus, seen map[string]string) {
	mods, err := n.client.ModuleStatus(ctx)
	if err != nil {
		n.log.Debug("module status not available", "err", err)
		return nil, st.FailedSeen
	}
	seen = map[string]string{}
	for _, m := range mods {
		if m.Name == n.base.Rackbook.Module || m.LastRun == nil || m.LastRun.Status != modsettings.StatusFailed {
			continue
		}
		at := m.LastRun.Finished.UTC().Format(time.RFC3339)
		seen[m.Name] = at
		if st.FailedSeen[m.Name] != at {
			fresh = append(fresh, m)
		}
	}
	return fresh, seen
}

// useRememberedRecipients is the fallback when the console cannot be reached:
// the digest goes to the recipients the module last got while it could (not to
// a possibly older list in the local file). Without any, the local list stays.
func (n *notifier) useRememberedRecipients() {
	s := n.cfg.SMTP
	if s == nil {
		return
	}
	st, err := loadState(n.statePath)
	if err != nil || len(st.Recipients) == 0 {
		return
	}
	smtp := *s
	smtp.To = append([]string(nil), st.Recipients...)
	cfg := *n.cfg
	cfg.SMTP = &smtp
	n.cfg = &cfg
}

// announceRecipients sends one notice to the old and the new addresses when
// a successful settings fetch shows recipients that differ from the remembered
// ones. The new list is remembered first and the notice is not retried: each
// address is tried on its own, a rejected one is logged and the others still
// get the mail. The first time it only remembers the list.
func (n *notifier) announceRecipients(ctx context.Context) error {
	s := n.cfg.SMTP
	if s == nil || len(s.To) == 0 {
		return nil
	}
	st, err := loadState(n.statePath)
	if err != nil {
		return err
	}
	old := st.Recipients
	if len(old) > 0 && sameAddresses(old, s.To) {
		return nil
	}
	st.Recipients = append([]string(nil), s.To...)
	if err := saveState(n.statePath, st); err != nil {
		return err
	}
	if len(old) == 0 { // the first time: only remember them
		return nil
	}
	subject, body := recipientsNotice(n.cfg.Language, n.cfg.Rackbook.URL, old, s.To)
	var pw string
	if s.Username != "" {
		if pw, err = rbclient.ReadSecret(s.PasswordFile); err != nil {
			return err
		}
	}
	notice := *s
	notice.To = union(old, s.To)
	rejected, err := sendMailBestEffort(ctx, &notice, pw, subject, body)
	for _, e := range rejected {
		n.log.Warn("recipients changed: the notice was refused for an address", "err", e)
	}
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}
	n.log.Info("recipients changed, notice sent", "old", len(old), "new", len(s.To), "refused", len(rejected))
	return nil
}

func union(a, b []string) []string {
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

func recipientsNotice(lang, baseURL string, old, nw []string) (subject, body string) {
	list := func(l []string) string {
		if len(l) == 0 {
			return "-"
		}
		return strings.Join(l, ", ")
	}
	if lang == "zh" {
		return "Rackbook：收件人已变更", fmt.Sprintf("到期提醒的收件人已变更。\n\n原收件人：%s\n新收件人：%s\n\n如果这不是你预期的改动，请在 %s 的“模块”页面检查。\n", list(old), list(nw), strings.TrimRight(baseURL, "/")+"/modules")
	}
	return "Rackbook: recipients changed", fmt.Sprintf("The recipients of the expiry reminders changed.\n\nBefore: %s\nNow: %s\n\nIf you did not expect this, check the Modules page at %s.\n", list(old), list(nw), strings.TrimRight(baseURL, "/")+"/modules")
}

var errNoRecipients = errors.New("no recipients: set them in the Rackbook console (Modules) or in smtp.to")
