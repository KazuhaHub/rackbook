package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mime/quotedprintable"

	"github.com/kazuhahub/rackbook/modsettings"
)

var panelNow = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)

func (e *env) panel(settings map[string]any, lastOK time.Time, request string) {
	e.rb.mu.Lock()
	defer e.rb.mu.Unlock()
	e.rb.remote = &modsettings.Remote{Name: "notify", Type: "notify", Settings: settings, LastOK: lastOK, RunRequest: request, Now: panelNow}
}

func (e *env) cycle(t *testing.T, o options) (failed, panel bool, logs string) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	n, err := newNotifier(e.cfg, o.dry, &e.out, log)
	if err != nil {
		t.Fatal(err)
	}
	n.now = func() time.Time { return panelNow }
	failed, panel = n.cycle(context.Background(), o)
	return failed, panel, buf.String()
}

func (e *env) reported() []modsettings.Run {
	e.rb.mu.Lock()
	defer e.rb.mu.Unlock()
	return append([]modsettings.Run(nil), e.rb.runs...)
}

func webhookEnv(t *testing.T) (*env, *hook) {
	e := newEnv(t)
	h := &hook{code: 200}
	e.cfg.Webhook = &WebhookConfig{URL: h.server(t).URL}
	return e, h
}

func TestCycleSendsWhenASlotHasPassedAndReports(t *testing.T) {
	e, h := webhookEnv(t)
	e.rb.set(item("c", "a", "2026-11-20", 2), item("c", "b", "2026-11-19", 1))
	e.panel(map[string]any{"send_at": []any{"08:00"}}, panelNow.Add(-26*time.Hour), "")
	failed, panel, _ := e.cycle(t, options{})
	if failed || !panel || len(h.calls) != 1 {
		t.Fatalf("failed=%v panel=%v calls=%d", failed, panel, len(h.calls))
	}
	if runs := e.reported(); len(runs) != 1 || runs[0].Status != "ok" || runs[0].Counts.Sent != 2 {
		t.Fatalf("%+v", runs)
	}
	// the next hourly check, after the run, does nothing and reports nothing
	e.panel(map[string]any{"send_at": []any{"08:00"}}, panelNow.Add(-time.Minute), "")
	e.cycle(t, options{})
	if len(h.calls) != 1 || len(e.reported()) != 1 {
		t.Fatalf("calls=%d runs=%d", len(h.calls), len(e.reported()))
	}
}

func TestCycleRunNowAndPause(t *testing.T) {
	e, h := webhookEnv(t)
	e.rb.set(item("c", "a", "2026-11-20", 2))
	e.panel(map[string]any{"send_at": []any{"08:00"}}, panelNow.Add(-time.Minute), "req-7")
	e.cycle(t, options{})
	if runs := e.reported(); len(h.calls) != 1 || len(runs) != 1 || runs[0].RunRequest != "req-7" {
		t.Fatalf("calls=%d runs=%+v", len(h.calls), runs)
	}
	e.panel(map[string]any{"paused": true}, time.Time{}, "req-8")
	e.rb.set(item("c", "z", "2026-11-19", 1))
	e.cycle(t, options{})
	if runs := e.reported(); len(h.calls) != 1 || len(runs) != 2 || runs[1].Status != "skipped" || runs[1].Error != "paused" {
		t.Fatalf("paused: calls=%d runs=%+v", len(h.calls), runs)
	}
	e.cycle(t, options{force: true})
	if len(h.calls) != 2 {
		t.Fatalf("--force must send: %d", len(h.calls))
	}
	// --dry-run prints, sends nothing and reports nothing
	before := len(e.reported())
	e.rb.set(item("c", "fresh", "2026-11-19", 1))
	e.cycle(t, options{dry: true})
	if len(h.calls) != 2 || len(e.reported()) != before || !strings.Contains(e.out.String(), "Subject:") {
		t.Fatalf("dry run: calls=%d", len(h.calls))
	}
}

func TestConsoleSettingsOverrideTheLocalConfig(t *testing.T) {
	e, _ := webhookEnv(t)
	e.cfg.Thresholds, e.cfg.setThresholds = []int{30, 14, 7, 0}, true
	e.cfg.Language, e.cfg.setLanguage = "en", true
	e.rb.set()
	e.panel(map[string]any{"thresholds": []any{90, 60}, "collections": []any{"credentials"}, "language": "zh"}, time.Time{}, "")
	_, _, logs := e.cycle(t, options{})
	if !strings.Contains(e.rb.query, "days=90") || !strings.Contains(e.rb.query, "collection=credentials") {
		t.Fatalf("query %q", e.rb.query)
	}
	for _, f := range []string{"thresholds", "language"} {
		if !strings.Contains(logs, "overrides the local config") || !strings.Contains(logs, "field="+f) {
			t.Errorf("no warning for %s:\n%s", f, logs)
		}
	}
	if strings.Contains(logs, "field=collections") {
		t.Error("collections was not set locally; nothing to warn about")
	}
}

func TestFallsBackToTheLocalConfigWithoutAPanel(t *testing.T) {
	e, h := webhookEnv(t)
	e.rb.set(item("c", "a", "2026-11-20", 2))
	failed, panel, logs := e.cycle(t, options{})
	if failed || panel || len(h.calls) != 1 || !strings.Contains(logs, "using the local config") || len(e.reported()) != 0 {
		t.Fatalf("failed=%v panel=%v calls=%d\n%s", failed, panel, len(h.calls), logs)
	}
}

func smtpEnv(t *testing.T) (*env, *fakeSMTP) {
	f, pool := newFakeSMTP(t, true)
	smtpRootCAs = pool
	t.Cleanup(func() { smtpRootCAs = nil })
	e := newEnv(t)
	e.cfg.Language = "zh"
	e.cfg.SMTP = &SMTPConfig{Host: "127.0.0.1", Port: f.port(), From: "Rackbook <rb@example.org>", Helo: "notify.example.org"}
	return e, f
}

func (f *fakeSMTP) last() (rcpts []string, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, b, _ := strings.Cut(f.data, "\r\n\r\n")
	dec, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(b)))
	return append([]string(nil), f.rcpts...), string(dec)
}

func TestRecipientsFromTheConsoleAndTheChangeNotice(t *testing.T) {
	e, f := smtpEnv(t)
	e.rb.set()
	// no recipients anywhere: a clear error, not a silent skip
	e.rb.set(item("c", "a", "2026-11-20", 2))
	e.panel(map[string]any{}, time.Time{}, "")
	if failed, _, _ := e.cycle(t, options{}); !failed {
		t.Fatal("a run without recipients must fail")
	}
	if runs := e.reported(); len(runs) != 1 || runs[0].Status != "failed" || !strings.Contains(runs[0].Error, "no recipients") {
		t.Fatalf("%+v", runs)
	}
	// first recipients: sent to them, remembered, no notice
	e.panel(map[string]any{"recipients": []any{"a@example.org"}}, time.Time{}, "")
	e.cycle(t, options{})
	if rc, _ := f.last(); len(rc) != 1 || rc[0] != "<a@example.org>" {
		t.Fatalf("rcpts %v", rc)
	}
	if st, _ := loadState(e.stat); len(st.Recipients) != 1 || st.Recipients[0] != "a@example.org" {
		t.Fatalf("state %+v", st)
	}
	// the same list in another order and case: nothing is announced
	e.panel(map[string]any{"recipients": []any{"A@Example.org"}}, panelNow.Add(-time.Minute), "")
	e.cycle(t, options{})
	if rc, body := f.last(); len(rc) != 1 || strings.Contains(body, "收件人") {
		t.Fatalf("rcpts %v\n%s", rc, body)
	}
	// a changed list: one notice to the old and the new addresses, even though no run is due
	e.panel(map[string]any{"recipients": []any{"b@example.org", "c@example.org"}}, panelNow.Add(-time.Minute), "")
	e.cycle(t, options{})
	rc, body := f.last()
	if len(rc) != 3 || rc[0] != "<a@example.org>" || rc[1] != "<b@example.org>" || rc[2] != "<c@example.org>" {
		t.Fatalf("notice went to %v", rc)
	}
	for _, want := range []string{"收件人已变更", "a@example.org", "b@example.org, c@example.org", "/modules"} {
		if !strings.Contains(body, want) {
			t.Errorf("notice lacks %q:\n%s", want, body)
		}
	}
	// and only once
	if st, _ := loadState(e.stat); len(st.Recipients) != 2 || st.Recipients[0] != "b@example.org" {
		t.Fatalf("state %+v", st)
	}
	f.mu.Lock()
	f.data = ""
	f.mu.Unlock()
	e.cycle(t, options{})
	if _, body := f.last(); body != "" {
		t.Fatalf("a second notice was sent:\n%s", body)
	}
}

func TestDigestIncludesFailedModuleRunsOnce(t *testing.T) {
	e, h := webhookEnv(t)
	fin := time.Date(2026, 11, 18, 4, 0, 5, 0, time.UTC)
	e.rb.status = []modsettings.ModuleStatus{
		{Name: "entra", Type: "entra", LastRun: &modsettings.Run{Started: fin.Add(-5 * time.Second), Finished: fin, Status: "failed", Error: "graph: HTTP 403"}},
		{Name: "other", Type: "entra", LastRun: &modsettings.Run{Finished: fin, Status: "ok"}},
		{Name: "notify", Type: "notify", LastRun: &modsettings.Run{Finished: fin, Status: "failed", Error: "smtp down"}},
	}
	e.rb.set() // nothing expires
	e.panel(map[string]any{"language": "zh"}, time.Time{}, "")
	e.cycle(t, options{})
	if len(h.calls) != 1 {
		t.Fatalf("calls %d", len(h.calls))
	}
	text := h.calls[0]["text"].(string)
	for _, want := range []string{"1 个模块运行失败", "[失败] entra", "graph: HTTP 403", "/modules"} {
		if !strings.Contains(text, want) {
			t.Errorf("digest lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "smtp down") || strings.Contains(text, "other") {
		t.Errorf("only other modules' failures belong in the digest:\n%s", text)
	}
	// reported once: the next run has nothing to say
	e.panel(map[string]any{}, time.Time{}, "r2")
	e.cycle(t, options{})
	if len(h.calls) != 1 {
		t.Fatalf("the same failure was reported twice: %d calls", len(h.calls))
	}
	// a new failure of the same module is reported again
	e.rb.status[0].LastRun.Finished = fin.Add(24 * time.Hour)
	e.panel(map[string]any{}, time.Time{}, "r3")
	e.cycle(t, options{})
	if len(h.calls) != 2 {
		t.Fatalf("a new failure must be reported: %d calls", len(h.calls))
	}
	// recovered, then failing again with the same finish time as before is still reported (state forgot it)
	e.rb.status[0].LastRun = &modsettings.Run{Finished: fin.Add(48 * time.Hour), Status: "ok"}
	e.panel(map[string]any{}, time.Time{}, "r4")
	e.cycle(t, options{})
	st, _ := loadState(e.stat)
	if len(st.FailedSeen) != 0 {
		t.Fatalf("recovered modules must be forgotten: %v", st.FailedSeen)
	}
}

func TestStatePreservesPanelFieldsAcrossARun(t *testing.T) {
	e, _ := webhookEnv(t)
	st := newState()
	st.Recipients = []string{"a@example.org"}
	st.FailedSeen = map[string]string{"entra": "2026-11-18T04:00:05Z"}
	if err := saveState(e.stat, st); err != nil {
		t.Fatal(err)
	}
	e.rb.set(item("c", "a", "2026-11-20", 2))
	if err := e.run(t, false); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(e.stat)
	if err != nil || len(got.Recipients) != 1 || got.FailedSeen["entra"] == "" {
		t.Fatalf("%+v %v", got, err)
	}
	// an old state file (no panel fields) still loads
	old := filepath.Join(e.dir, "old.json")
	os.WriteFile(old, []byte(`{"version":1,"items":{}}`), 0o600)
	if _, err := loadState(old); err != nil {
		t.Fatal(err)
	}
}

func TestFailedSettingsFetchDoesNotAnnounceOrUseTheLocalList(t *testing.T) {
	e, f := smtpEnv(t)
	e.cfg.SMTP.To = []string{"local@example.org"}
	e.rb.set(item("c", "a", "2026-11-20", 2))
	e.panel(map[string]any{"recipients": []any{"console@example.org"}}, time.Time{}, "")
	e.cycle(t, options{})
	// the console becomes unreachable (404 from the fake); the local list differs
	e.rb.mu.Lock()
	e.rb.remote = nil
	e.rb.mu.Unlock()
	f.mu.Lock()
	f.data = ""
	f.mu.Unlock()
	e.rb.set(item("c", "b", "2026-11-20", 2))
	e.cycle(t, options{})
	rc, body := f.last()
	if strings.Contains(body, "收件人已变更") || strings.Contains(body, "Recipients changed") {
		t.Fatalf("a failed fetch must not announce a change:\n%s", body)
	}
	if len(rc) != 1 || rc[0] != "<console@example.org>" {
		t.Fatalf("the digest must go to the last recipients from the console, got %v", rc)
	}
	if st, _ := loadState(e.stat); len(st.Recipients) != 1 || st.Recipients[0] != "console@example.org" {
		t.Fatalf("state %+v", st)
	}
}

func TestChangeNoticeIsBestEffortAndNotRetried(t *testing.T) {
	e, f := smtpEnv(t)
	e.rb.set()
	e.panel(map[string]any{"recipients": []any{"gone@example.org", "a@example.org"}}, time.Time{}, "")
	e.cycle(t, options{})
	// one old address no longer exists; the change must still reach the others
	f.mu.Lock()
	f.reject = map[string]bool{"gone@example.org": true}
	f.mu.Unlock()
	e.panel(map[string]any{"recipients": []any{"b@example.org"}}, panelNow.Add(-time.Minute), "")
	_, _, logs := e.cycle(t, options{})
	rc, body := f.last()
	if len(rc) != 2 || rc[0] != "<a@example.org>" || rc[1] != "<b@example.org>" || !strings.Contains(body, "收件人已变更") {
		t.Fatalf("notice went to %v\n%s", rc, body)
	}
	if !strings.Contains(logs, "gone@example.org") {
		t.Errorf("the refused address is not logged:\n%s", logs)
	}
	// the new list is remembered at once; nothing else is carried over, so no retry
	st, _ := loadState(e.stat)
	if len(st.Recipients) != 1 || st.Recipients[0] != "b@example.org" {
		t.Fatalf("state %+v", st)
	}
	if b, _ := os.ReadFile(e.stat); strings.Contains(string(b), "notice") {
		t.Fatalf("state must hold no notice bookkeeping:\n%s", b)
	}
	f.mu.Lock()
	f.data = ""
	f.mu.Unlock()
	e.cycle(t, options{})
	if _, body := f.last(); body != "" {
		t.Fatalf("the notice was sent again:\n%s", body)
	}
}
