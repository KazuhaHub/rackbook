package modsettings

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeNormalizesAndKeepsOnlySetValues(t *testing.T) {
	s, err := DecodeAndValidate(TypeNotify, map[string]any{
		"thresholds": []any{7, 30, 7, 0}, "recipients": []any{" Ops@Example.org ", "ops@example.org", "b@example.org"},
		"send_at": []any{"13:00", "08:00", "08:00"}, "timezone": "Asia/Shanghai", "language": "zh",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := s.(*Notify)
	if len(n.Thresholds) != 3 || n.Thresholds[0] != 30 || n.Thresholds[2] != 0 {
		t.Errorf("thresholds %v", n.Thresholds)
	}
	if len(n.Recipients) != 2 || n.Recipients[0] != "Ops@Example.org" {
		t.Errorf("recipients %v", n.Recipients)
	}
	if len(n.SendAt) != 2 || n.SendAt[0] != "08:00" {
		t.Errorf("send_at %v", n.SendAt)
	}
	m := Map(s)
	if _, ok := m["paused"]; ok {
		t.Error("unset paused must not be in the map")
	}
	if _, ok := m["collections"]; ok {
		t.Error("unset collections must not be in the map")
	}
	if Version(m) != Version(Map(s)) || Version(m) == Version(map[string]any{}) {
		t.Error("version must follow the content")
	}
}

func TestDecodeRefusals(t *testing.T) {
	cases := []struct {
		typ  string
		raw  map[string]any
		want string
	}{
		{TypeNotify, map[string]any{"smtp_password": "x"}, `unknown setting "smtp_password"`},
		{TypeEntra, map[string]any{"send_at": []any{"08:00"}}, `unknown setting "send_at"`},
		{TypeNotify, map[string]any{"thresholds": "7"}, "settings:"},
		{"sms", map[string]any{}, "unknown module type"},
		{TypeNotify, map[string]any{"send_at": []any{"24:00"}}, "not a time of day"},
		{TypeNotify, map[string]any{"send_at": []any{"8:00"}}, "not a time of day"},
		{TypeNotify, map[string]any{"timezone": "Local"}, "timezone"},
		{TypeNotify, map[string]any{"thresholds": []any{-1}}, "between 0 and 3650"},
		{TypeNotify, map[string]any{"thresholds": []any{3651}}, "between 0 and 3650"},
		{TypeNotify, map[string]any{"recipients": []any{"nobody"}}, "not an e-mail address"},
		{TypeNotify, map[string]any{"recipients": []any{"A <a@example.org>"}}, "not an e-mail address"},
		{TypeNotify, map[string]any{"language": "fr"}, "language"},
		{TypeEntra, map[string]any{"exclude_app_ids": []any{"not-a-uuid"}}, "not an application id"},
		{TypeEntra, map[string]any{"name_prefix": "has space"}, "name_prefix"},
		{TypeEntra, map[string]any{"purpose": "{app} {secret}"}, "not a placeholder"},
		{TypeEntra, map[string]any{"defaults": map[string]any{"Bad Key": "x"}}, "not a field name"},
		{TypeEntra, map[string]any{"defaults": map[string]any{"owner": map[string]any{"a": 1}}}, "defaults.owner"},
	}
	for _, c := range cases {
		_, err := DecodeAndValidate(c.typ, c.raw, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: got %v, want %q", c.typ, c.raw, err, c.want)
		}
	}
	if _, err := DecodeAndValidate(TypeNotify, map[string]any{"collections": []any{"nope"}}, func(string) bool { return false }); err == nil {
		t.Error("an unknown collection must be refused")
	}
	if _, err := DecodeAndValidate(TypeEntra, map[string]any{"exclude_app_ids": []any{"11111111-2222-3333-4444-555555555555"}, "name_prefix": "", "defaults": map[string]any{"used_by": []any{"all"}, "owner": "ops"}}, nil); err != nil {
		t.Errorf("valid entra settings: %v", err)
	}
}

func TestChangedKeys(t *testing.T) {
	got := ChangedKeys(map[string]any{"a": 1.0, "b": []any{"x"}}, map[string]any{"a": 1.0, "b": []any{"y"}, "c": true})
	if strings.Join(got, ",") != "b,c" {
		t.Fatal(got)
	}
}

func TestRunFromAFastClockIsStoredAsReported(t *testing.T) {
	now := time.Now()
	start := now.Add(3 * time.Hour)
	r := Run{Started: start, Finished: start.Add(time.Minute), Status: StatusOK}
	want := r
	if err := r.Validate(now); err != nil {
		t.Fatalf("a fast module clock must not block reports: %v", err)
	}
	if !r.Started.Equal(want.Started) || !r.Finished.Equal(want.Finished) {
		t.Fatalf("times must not be rewritten: %+v", r)
	}
	// a clock a few minutes fast: the slot the module just ran stays done for it
	slot := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	modStart := slot.Add(time.Minute)
	fast := Run{Started: modStart, Finished: modStart.Add(5 * time.Second), Status: StatusOK}
	if err := fast.Validate(fast.Finished.Add(-3 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	d := Decide(Input{Now: time.Date(2026, 11, 18, 9, 2, 0, 0, time.UTC), Times: []string{"08:00"}, Timezone: "UTC", LastOK: fast.Started})
	if d.Run {
		t.Fatalf("ran twice for one slot: %+v", d)
	}
}

func TestRunValidation(t *testing.T) {
	now := time.Now()
	ok := Run{Started: now.Add(-time.Minute), Finished: now, Status: StatusOK, Counts: Counts{Created: 2}}
	if err := ok.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Run){
		"status":   func(r *Run) { r.Status = "done" },
		"order":    func(r *Run) { r.Finished = r.Started.Add(-time.Second) },
		"future":   func(r *Run) { r.Finished = now.Add(25 * time.Hour) },
		"negative": func(r *Run) { r.Counts.Sent = -1 },
		"zero":     func(r *Run) { r.Started = time.Time{} },
	} {
		r := ok
		mut(&r)
		if err := r.Validate(now); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	r := Run{Error: "line one\nline two\x00" + strings.Repeat("é", 400)}
	r.Clean()
	if strings.ContainsAny(r.Error, "\n\x00") || len([]rune(r.Error)) > MaxErrorLen+1 {
		t.Errorf("error not cleaned: %q", r.Error)
	}
}
