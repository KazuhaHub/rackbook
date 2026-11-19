package modules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/modsettings"
)

const (
	appA = "11111111-2222-3333-4444-555555555555"
	appB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// ---- state ------------------------------------------------------------------

func run(finished time.Time, status string) modsettings.Run {
	return modsettings.Run{Started: finished.Add(-time.Second), Finished: finished, Status: status}
}

func TestStateKeepsTheLastRunsAndSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modules.json")
	s := &State{Path: path}
	base := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	for i := 0; i < modsettings.MaxRuns+5; i++ {
		r := run(base.Add(time.Duration(i)*time.Hour), modsettings.StatusOK)
		r.Counts.Created = i
		if err := s.AddRun("entra", r); err != nil {
			t.Fatal(err)
		}
	}
	runs := s.Runs("entra")
	if len(runs) != modsettings.MaxRuns || runs[0].Counts.Created != modsettings.MaxRuns+4 || runs[len(runs)-1].Counts.Created != 5 {
		t.Fatalf("rotation: %d runs, newest %d oldest %d", len(runs), runs[0].Counts.Created, runs[len(runs)-1].Counts.Created)
	}
	// a new State on the same file sees the same history
	again := &State{Path: path}
	if got := again.Runs("entra"); len(got) != modsettings.MaxRuns || !got[0].Finished.Equal(runs[0].Finished) {
		t.Fatalf("after restart: %d runs", len(got))
	}
	if again.Runs("notify") != nil || again.LastRun("notify") != nil {
		t.Fatal("another module has no runs")
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Fatalf("state file mode: %v %v", st, err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".modules-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func isWindows() bool { return os.PathSeparator == '\\' }

func TestStateCollapsesRepeatedSkipsAndTracksLastOK(t *testing.T) {
	s := &State{}
	t0 := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	_ = s.AddRun("m", run(t0, modsettings.StatusOK))
	for i := 1; i <= 5; i++ {
		_ = s.AddRun("m", run(t0.Add(time.Duration(i)*time.Hour), modsettings.StatusSkipped))
	}
	if n := len(s.Runs("m")); n != 2 {
		t.Fatalf("skipped runs must collapse: %d runs", n)
	}
	_ = s.AddRun("m", run(t0.Add(7*time.Hour), modsettings.StatusFailed))
	if ok := s.LastOK("m"); !ok.Equal(t0) {
		t.Fatalf("a failed or skipped run is not a success: %v", ok)
	}
	if last := s.LastRun("m"); last.Status != modsettings.StatusFailed {
		t.Fatalf("%+v", last)
	}
}

func TestRunRequestIsKeptOnceAndClearedByItsRun(t *testing.T) {
	now := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	s := &State{Path: filepath.Join(t.TempDir(), "modules.json"), Now: func() time.Time { return now }}
	r1, err := s.Request("entra", "boss@example.com")
	if err != nil || r1.ID == "" || r1.By != "boss@example.com" || !r1.Requested.Equal(now) {
		t.Fatalf("%+v %v", r1, err)
	}
	if r2, _ := s.Request("entra", "other"); r2.ID != r1.ID {
		t.Fatal("a second request while one waits must return the same one")
	}
	if p := (&State{Path: s.Path}).Pending("entra"); p == nil || p.ID != r1.ID {
		t.Fatal("the request must survive a restart")
	}
	// a run that answers another id, and a skipped run, leave it
	wrong := run(now, modsettings.StatusOK)
	wrong.RunRequest = "nope"
	_ = s.AddRun("entra", wrong)
	skipped := run(now, modsettings.StatusSkipped)
	skipped.RunRequest = r1.ID
	_ = s.AddRun("entra", skipped)
	if s.Pending("entra") == nil {
		t.Fatal("the request was cleared too early")
	}
	ok := run(now.Add(time.Minute), modsettings.StatusFailed)
	ok.RunRequest = r1.ID
	_ = s.AddRun("entra", ok)
	if s.Pending("entra") != nil {
		t.Fatal("the run that names the request must clear it")
	}
}

func TestStateIsSafeForConcurrentUseAndSurvivesAJunkFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &State{Path: path}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.AddRun("m", run(time.Now(), modsettings.StatusOK))
		}()
	}
	wg.Wait()
	if n := len(s.Runs("m")); n != 20 {
		t.Fatalf("%d runs", n)
	}
}

// ---- edit -------------------------------------------------------------------

const baseYAML = `title: demo
collections:
  todo:
    title: todo
    file: todo.yml
    schema: todo.json
    key: [item]
  sites:
    title: sites
    file: sites.yml
    schema: sites.json
    key: [code]

# modules below
modules:
  entra:
    token: entra-sync
    collection: todo
    fields: [expires]
    direct_push: true
  notify:
    token: notify-read   # read only
`

func writeCfg(t *testing.T, y string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rackbook.yml")
	if err := os.WriteFile(p, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func apply(t *testing.T, cfg *config.Config, name string, settings map[string]any, confirm bool) (string, error) {
	t.Helper()
	_, ver := Current(cfg.Modules[name])
	res, err := Apply(cfg, Change{Name: name, Version: ver, Settings: settings, ConfirmImpact: confirm})
	if err != nil {
		return "", err
	}
	b, _ := os.ReadFile(cfg.Path)
	if !res.Changed() {
		return string(b), nil
	}
	return string(b) + "\n#subject: " + res.Subject(), nil
}

func TestApplyAddsChangesAndRemovesSettingsInPlace(t *testing.T) {
	cfg := writeCfg(t, baseYAML)
	got, err := apply(t, cfg, "notify", map[string]any{
		"thresholds": []any{30, 7}, "recipients": []any{"ops@example.org"}, "send_at": []any{"08:00"}, "timezone": "Asia/Shanghai",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"    token: notify-read   # read only\n    settings:\n      send_at: [\"08:00\"]",
		"      timezone: Asia/Shanghai\n",
		"      thresholds: [30, 7]\n",
		"      recipients: [ops@example.org]\n",
		"# modules below\n",
		"#subject: modules(notify): change recipients, send_at, thresholds, timezone",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	// the entra entry above is untouched, byte for byte
	if !strings.Contains(got, "  entra:\n    token: entra-sync\n    collection: todo\n    fields: [expires]\n    direct_push: true\n") {
		t.Fatalf("another module changed:\n%s", got)
	}
	cfg, err = config.Load(cfg.Path)
	if err != nil {
		t.Fatalf("the file must still load: %v", err)
	}
	// change one key, drop one: only those lines move
	got, err = apply(t, cfg, "notify", map[string]any{
		"thresholds": []any{14, 3}, "recipients": []any{"ops@example.org"}, "send_at": []any{"08:00"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "      thresholds: [14, 3]\n") || strings.Contains(got, "      timezone") || !strings.Contains(got, "#subject: modules(notify): change thresholds, timezone") {
		t.Fatalf("%s", got)
	}
	cfg, _ = config.Load(cfg.Path)
	// clearing everything removes the block
	got, err = apply(t, cfg, "notify", map[string]any{}, false)
	if err != nil || strings.Contains(got, "    settings:") || !strings.Contains(got, "token: notify-read   # read only\n") {
		t.Fatalf("%v\n%s", err, got)
	}
	cfg, _ = config.Load(cfg.Path)
	if cfg.Modules["notify"].ParsedSettings() == nil {
		t.Fatal("settings must parse as empty")
	}
	// no change, no write
	before, _ := os.ReadFile(cfg.Path)
	_, ver := Current(cfg.Modules["notify"])
	res, err := Apply(cfg, Change{Name: "notify", Version: ver, Settings: map[string]any{}})
	if err != nil || res.Changed() {
		t.Fatalf("%v %+v", err, res)
	}
	if after, _ := os.ReadFile(cfg.Path); string(after) != string(before) {
		t.Fatal("an empty change wrote")
	}
}

func TestApplyRefusals(t *testing.T) {
	cfg := writeCfg(t, baseYAML)
	_, ver := Current(cfg.Modules["notify"])
	before, _ := os.ReadFile(cfg.Path)
	check := func(name string, ch Change, target any) {
		t.Helper()
		_, err := Apply(cfg, ch)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if target != nil {
			switch target.(type) {
			case *VersionError:
				var e *VersionError
				if !errors.As(err, &e) {
					t.Fatalf("%s: %v", name, err)
				}
			case *InvalidError:
				var e *InvalidError
				if !errors.As(err, &e) {
					t.Fatalf("%s: %v", name, err)
				}
			}
		}
	}
	check("stale version", Change{Name: "notify", Version: "0000", Settings: map[string]any{"language": "zh"}}, &VersionError{})
	check("no version", Change{Name: "notify", Settings: map[string]any{"language": "zh"}}, &InvalidError{})
	check("unknown key", Change{Name: "notify", Version: ver, Settings: map[string]any{"smtp_password": "x"}}, &InvalidError{})
	check("bad value", Change{Name: "notify", Version: ver, Settings: map[string]any{"thresholds": []any{4000}}}, &InvalidError{})
	check("unknown collection", Change{Name: "notify", Version: ver, Settings: map[string]any{"collections": []any{"nope"}}}, &InvalidError{})
	if _, err := Apply(cfg, Change{Name: "ghost", Version: ver}); !errors.Is(err, ErrUnknownModule) {
		t.Fatal(err)
	}
	// a secret in a setting is refused by the scan
	_, err := Apply(cfg, Change{Name: "entra", Version: func() string { _, v := Current(cfg.Modules["entra"]); return v }(),
		Settings: map[string]any{"defaults": map[string]any{"note": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}}})
	var se *secretscan.Error
	if !errors.As(err, &se) {
		t.Fatalf("secret not refused: %v", err)
	}
	if after, _ := os.ReadFile(cfg.Path); string(after) != string(before) {
		t.Fatal("a refused change wrote")
	}
	// a module without a type has no settings
	c2 := writeCfg(t, strings.Replace(baseYAML, "  notify:\n    token: notify-read   # read only\n", "  other:\n    token: other-t\n", 1))
	if _, err := Apply(c2, Change{Name: "other", Version: "x"}); !errors.Is(err, ErrNoSettings) {
		t.Fatal(err)
	}
}

func TestApplyReportsAnEntryItCannotEdit(t *testing.T) {
	cfg := writeCfg(t, strings.Replace(baseYAML, "  notify:\n    token: notify-read   # read only\n", "  notify: {token: notify-read}\n", 1))
	_, ver := Current(cfg.Modules["notify"])
	_, err := Apply(cfg, Change{Name: "notify", Version: ver, Settings: map[string]any{"language": "zh"}})
	var e *InvalidError
	if !errors.As(err, &e) || !strings.Contains(e.Message, "by hand") {
		t.Fatalf("%v", err)
	}
}

// ---- preview ----------------------------------------------------------------

func previewCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := testutil.CopyExample(t)
	p := filepath.Join(dir, "rackbook.yml")
	b, _ := os.ReadFile(p)
	b = append(b, []byte("\nmodules:\n  entra:\n    token: entra-sync\n    collection: todo\n    fields: [status]\n    settings:\n      exclude_app_ids: ["+appB+"]\n")...)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	// records as rackbook-entra writes them (todo stands in for credentials: only the data matters)
	recs := `
- {item: rec-a1, source: entra, expires: "2027-01-01", ids: ["entra_app_id=` + appA + `", "entra_tenant_id=t"]}
- {item: rec-a2, source: entra, expires: "2027-02-01", ids: ["entra_app_id=` + strings.ToUpper(appA) + `"]}
- {item: rec-b1, source: entra, expires: "2027-03-01", ids: ["entra_app_id=` + appB + `"]}
- {item: rec-c1, source: entra, expires: "2027-04-01", ids: ["entra_app_id=cccccccc-0000-0000-0000-000000000000"]}
- {item: rec-gone, source: entra, revoked: "2026-10-01", ids: ["entra_app_id=` + appA + `"]}
- {item: manual-one, ids: ["entra_app_id=` + appA + `"]}
`
	f := filepath.Join(dir, "docs/ledger/todo.yml")
	old, _ := os.ReadFile(f)
	if err := os.WriteFile(f, append(old, []byte(recs)...), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func impactIDs(imp Impact) string {
	var out []string
	for _, a := range imp.Records {
		out = append(out, a.ID+":"+a.Effect)
	}
	return strings.Join(out, ",")
}

func entraSettings(t *testing.T, raw map[string]any) modsettings.Settings {
	t.Helper()
	s, err := modsettings.DecodeAndValidate(modsettings.TypeEntra, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// These expectations restate what cmd/rackbook-entra/sync.go does: credentials
// of an excluded app are "protected" (left alone, never revoked) and
// credentials that are no longer read are marked revoked.
func TestPreviewMatchesWhatTheSyncDoes(t *testing.T) {
	cfg := previewCfg(t)
	// excluding app A freezes its two active entra records; revoked and manual ones are not listed
	imp := PreviewImpact(cfg, "entra", entraSettings(t, map[string]any{"exclude_app_ids": []any{appA, appB}}))
	if !imp.Risky || impactIDs(imp) != "rec-a1:frozen,rec-a2:frozen" {
		t.Fatalf("exclude: %+v", imp)
	}
	// service principals off: every active entra record may be revoked, except
	// those of an app that is (already, or now) excluded
	imp = PreviewImpact(cfg, "entra", entraSettings(t, map[string]any{"exclude_app_ids": []any{appB}, "service_principals": false}))
	if !imp.Risky || impactIDs(imp) != "rec-a1:maybe_revoked,rec-a2:maybe_revoked,rec-c1:maybe_revoked" {
		t.Fatalf("sp off: %+v", imp)
	}
	// both at once
	imp = PreviewImpact(cfg, "entra", entraSettings(t, map[string]any{"exclude_app_ids": []any{appA, appB}, "service_principals": false}))
	if impactIDs(imp) != "rec-a1:frozen,rec-a2:frozen,rec-c1:maybe_revoked" {
		t.Fatalf("both: %+v", imp)
	}
	// harmless changes are not risky: removing an exclusion, a new time, SP on
	for _, raw := range []map[string]any{
		{}, {"exclude_app_ids": []any{appB}, "sync_at": []any{"04:00"}}, {"exclude_app_ids": []any{appB}, "service_principals": true},
	} {
		if imp := PreviewImpact(cfg, "entra", entraSettings(t, raw)); imp.Risky || len(imp.Records) != 0 {
			t.Fatalf("%v: %+v", raw, imp)
		}
	}
	// only entra modules have an impact
	if imp := PreviewImpact(cfg, "nobody", entraSettings(t, map[string]any{})); imp.Risky {
		t.Fatal("unknown module")
	}
}

func TestApplyAsksForConfirmationOnARiskyChange(t *testing.T) {
	cfg := previewCfg(t)
	settings := map[string]any{"exclude_app_ids": []any{appA, appB}}
	_, ver := Current(cfg.Modules["entra"])
	before, _ := os.ReadFile(cfg.Path)
	_, err := Apply(cfg, Change{Name: "entra", Version: ver, Settings: settings})
	var ie *ImpactError
	if !errors.As(err, &ie) || len(ie.Impact.Records) != 2 {
		t.Fatalf("%v", err)
	}
	if after, _ := os.ReadFile(cfg.Path); string(after) != string(before) {
		t.Fatal("an unconfirmed risky change wrote")
	}
	res, err := Apply(cfg, Change{Name: "entra", Version: ver, Settings: settings, ConfirmImpact: true})
	if err != nil || !res.Changed() {
		t.Fatalf("%v %+v", err, res)
	}
	b, _ := os.ReadFile(cfg.Path)
	if !strings.Contains(string(b), appA) || !strings.Contains(res.Subject(), "exclude_app_ids") {
		t.Fatalf("%s\n%s", b, res.Subject())
	}
	// a risky change that touches no record needs no confirmation
	cfg2, _ := config.Load(cfg.Path)
	_, ver2 := Current(cfg2.Modules["entra"])
	if _, err := Apply(cfg2, Change{Name: "entra", Version: ver2, Settings: map[string]any{"exclude_app_ids": []any{appA, appB, "dddddddd-0000-0000-0000-000000000000"}}}); err != nil {
		t.Fatal(err)
	}
}
