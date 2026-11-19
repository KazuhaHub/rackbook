package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/modsettings"
)

func (e *env) panel(settings map[string]any, lastOK time.Time, request string) {
	e.rb.mu.Lock()
	defer e.rb.mu.Unlock()
	e.rb.remote = &modsettings.Remote{Name: "entra", Type: "entra", Settings: settings, LastOK: lastOK, RunRequest: request, Now: testNow}
}

func (e *env) cycle(o options) (failed, panel bool, logs string) {
	e.t.Helper()
	var buf bytes.Buffer
	e.a.log = slog.New(slog.NewTextHandler(&buf, nil))
	failed, panel = e.a.cycle(context.Background(), o)
	return failed, panel, buf.String()
}

func (e *env) reported() []modsettings.Run {
	e.rb.mu.Lock()
	defer e.rb.mu.Unlock()
	return append([]modsettings.Run(nil), e.rb.runs...)
}

func TestCycleRunsWhenASlotHasPassedAndReports(t *testing.T) {
	e := newEnv(t)
	e.panel(map[string]any{"sync_at": []any{"03:00"}}, testNow.Add(-30*time.Hour), "")
	failed, panel, _ := e.cycle(options{})
	if failed || !panel {
		t.Fatalf("failed=%v panel=%v", failed, panel)
	}
	runs := e.reported()
	if len(runs) != 1 || runs[0].Status != "ok" || runs[0].Counts.Created != 4 || runs[0].RunRequest != "" {
		t.Fatalf("%+v", runs)
	}
	if len(e.rb.records) != 4 {
		t.Fatalf("records %d", len(e.rb.records))
	}
}

func TestCycleDoesNothingBetweenSlots(t *testing.T) {
	e := newEnv(t)
	e.panel(map[string]any{"sync_at": []any{"03:00"}}, testNow.Add(-time.Hour), "") // ran after today's 03:00 slot
	failed, panel, logs := e.cycle(options{})
	if failed || !panel || len(e.rb.records) != 0 || len(e.reported()) != 0 {
		t.Fatalf("it ran: records=%d runs=%v\n%s", len(e.rb.records), e.reported(), logs)
	}
	// a waiting request runs it anyway, and its id comes back with the run
	e.panel(map[string]any{"sync_at": []any{"03:00"}}, testNow.Add(-time.Hour), "req-1")
	e.cycle(options{})
	if runs := e.reported(); len(runs) != 1 || runs[0].RunRequest != "req-1" || len(e.rb.records) != 4 {
		t.Fatalf("%+v", runs)
	}
}

func TestCyclePausedReportsSkippedAndForceRunsAnyway(t *testing.T) {
	e := newEnv(t)
	e.panel(map[string]any{"paused": true}, time.Time{}, "req-9")
	if failed, panel, _ := e.cycle(options{}); failed || !panel {
		t.Fatalf("failed=%v panel=%v", failed, panel)
	}
	if runs := e.reported(); len(runs) != 1 || runs[0].Status != "skipped" || runs[0].Error != "paused" || len(e.rb.records) != 0 {
		t.Fatalf("%+v", runs)
	}
	e.cycle(options{force: true})
	if runs := e.reported(); len(runs) != 2 || runs[1].Status != "ok" || len(e.rb.records) != 4 {
		t.Fatalf("--force: %+v", runs)
	}
}

func TestCycleDryRunPlansWithoutReporting(t *testing.T) {
	e := newEnv(t)
	e.panel(map[string]any{"paused": true}, testNow.Add(-time.Minute), "")
	e.cycle(options{dry: true})
	if len(e.reported()) != 0 || len(e.rb.records) != 0 || !strings.Contains(e.out.String(), "create entra-") {
		t.Fatalf("dry run: runs=%v out=%q", e.reported(), e.out.String())
	}
}

func TestConsoleSettingsWinOverTheLocalConfigAndSayWhy(t *testing.T) {
	e := newEnv(t) // the local config excludes appB
	e.panel(map[string]any{"exclude_app_ids": []any{appB, appA}, "name_prefix": "ent-", "defaults": map[string]any{"owner": "sec"}}, time.Time{}, "")
	_, _, logs := e.cycle(options{})
	// appA is excluded by the console: its credentials get no record; the prefix and defaults are the console's
	if len(e.rb.records) != 2 {
		t.Fatalf("records: %v", e.rb.records)
	}
	for n, r := range e.rb.records {
		if !strings.HasPrefix(n, "ent-") || r["owner"] != "sec" {
			t.Errorf("%s: %v", n, r)
		}
	}
	for _, f := range []string{"record.defaults"} {
		if !strings.Contains(logs, "overrides the local config") || !strings.Contains(logs, f) {
			t.Errorf("no warning for %s in:\n%s", f, logs)
		}
	}
	if strings.Contains(logs, "record.name_prefix") {
		t.Error("the local file never set name_prefix, so there is nothing to warn about")
	}
	// the same list written the same way is not worth a warning
	e2 := newEnv(t)
	e2.panel(map[string]any{"exclude_app_ids": []any{strings.ToLower(appB)}}, time.Time{}, "")
	if _, _, logs := e2.cycle(options{}); strings.Contains(logs, "overrides the local config") {
		t.Errorf("a warning for an equal value:\n%s", logs)
	}
}

func TestConsoleExcludeListAddsToTheLocalOne(t *testing.T) {
	e := newEnv(t) // the local config excludes appB
	e.panel(map[string]any{"exclude_app_ids": []any{appA}}, time.Time{}, "")
	_, _, logs := e.cycle(options{})
	if strings.Contains(logs, "entra.exclude_app_ids") {
		t.Errorf("the lists add up; nothing is overridden:\n%s", logs)
	}
	base := newEnv(t)
	base.panel(map[string]any{"exclude_app_ids": []any{appA, appB}}, time.Time{}, "")
	base.cycle(options{})
	if len(e.rb.records) != len(base.rb.records) {
		t.Fatalf("appB must stay excluded: %d records, want %d", len(e.rb.records), len(base.rb.records))
	}
}

func TestFallsBackToTheLocalConfigWithoutAPanel(t *testing.T) {
	e := newEnv(t) // fakeRB answers 404 for /api/modules
	failed, panel, logs := e.cycle(options{})
	if failed || panel || len(e.rb.records) != 4 || !strings.Contains(logs, "using the local config") {
		t.Fatalf("failed=%v panel=%v records=%d\n%s", failed, panel, len(e.rb.records), logs)
	}
	if len(e.reported()) != 0 {
		t.Fatal("nothing to report to a server without a panel")
	}
}

func TestFailedAndConflictedRunsAreReportedFailed(t *testing.T) {
	e := newEnv(t)
	e.panel(map[string]any{}, time.Time{}, "")
	e.rb.denyAll = true
	failed, _, _ := e.cycle(options{})
	runs := e.reported()
	if !failed || len(runs) != 1 || runs[0].Status != "failed" || !strings.Contains(runs[0].Error, "refused by Rackbook") {
		t.Fatalf("%v %+v", failed, runs)
	}
	e = newEnv(t)
	e.panel(map[string]any{}, time.Time{}, "")
	e.rb.conflict = true
	failed, _, _ = e.cycle(options{})
	if runs := e.reported(); !failed || len(runs) != 1 || runs[0].Status != "failed" || !strings.Contains(runs[0].Error, "trying again") {
		t.Fatalf("%v %+v", failed, runs)
	}
	// a Graph failure aborts the run and is reported with its reason
	e = newEnv(t)
	e.panel(map[string]any{}, time.Time{}, "")
	e.graph.always = 403
	failed, _, _ = e.cycle(options{})
	if runs := e.reported(); !failed || len(runs) != 1 || runs[0].Status != "failed" || runs[0].Error == "" {
		t.Fatalf("%v %+v", failed, runs)
	}
}
