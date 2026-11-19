package rbclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/modsettings"
)

func panelServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	c, err := New(ts.URL, "rbk_test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCheckRunFollowsTheServer(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	answer := modsettings.Remote{Name: "notify", Type: "notify", Settings: map[string]any{"send_at": []any{"08:00"}}, LastOK: now.Add(-25 * time.Hour)}
	c := panelServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/modules/notify/settings" || r.Header.Get("Authorization") != "Bearer rbk_test" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(answer)
	})
	k := c.CheckRun(context.Background(), "notify", "notify", now, modsettings.DefaultSendAt)
	if !k.Panel() || !k.Decision.Run || k.Decision.Reason != modsettings.ReasonSlot {
		t.Fatalf("%+v", k)
	}
	answer.LastOK = now.Add(-time.Hour) // already ran after the slot
	if k = c.CheckRun(context.Background(), "notify", "notify", now, modsettings.DefaultSendAt); k.Decision.Run || k.Decision.Reason != modsettings.ReasonNotDue {
		t.Fatalf("%+v", k)
	}
	answer.RunRequest = "r1"
	if k = c.CheckRun(context.Background(), "notify", "notify", now, modsettings.DefaultSendAt); !k.Decision.Run || k.Decision.RunRequest != "r1" {
		t.Fatalf("%+v", k)
	}
	answer.Settings = map[string]any{"paused": true}
	if k = c.CheckRun(context.Background(), "notify", "notify", now, modsettings.DefaultSendAt); k.Decision.Run || k.Decision.Reason != modsettings.ReasonPaused {
		t.Fatalf("%+v", k)
	}
}

func TestCheckRunFallsBackToTheLocalConfig(t *testing.T) {
	now := time.Now()
	old := panelServer(t, http.NotFound) // a server older than v0.5.0
	k := old.CheckRun(context.Background(), "entra", "entra", now, modsettings.DefaultSyncAt)
	if k.Panel() || !errors.Is(k.Err, ErrNoPanel) || !k.Decision.Run {
		t.Fatalf("404: %+v", k)
	}
	broken := panelServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) })
	if k = broken.CheckRun(context.Background(), "entra", "entra", now, modsettings.DefaultSyncAt); k.Panel() || k.Err == nil || !k.Decision.Run {
		t.Fatalf("500: %+v", k)
	}
	ts := httptest.NewServer(http.NotFoundHandler())
	c, _ := New(ts.URL, "rbk_test")
	ts.Close() // unreachable
	if k = c.CheckRun(context.Background(), "entra", "entra", now, modsettings.DefaultSyncAt); k.Panel() || k.Err == nil || !k.Decision.Run {
		t.Fatalf("unreachable: %+v", k)
	}
	wrongType := panelServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(modsettings.Remote{Name: "entra", Type: "notify"})
	})
	if k = wrongType.CheckRun(context.Background(), "entra", "entra", now, modsettings.DefaultSyncAt); k.Panel() || k.Err == nil || !k.Decision.Run {
		t.Fatalf("type mismatch: %+v", k)
	}
	junk := panelServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(modsettings.Remote{Name: "entra", Type: "entra", Settings: map[string]any{"nope": 1}})
	})
	if k = junk.CheckRun(context.Background(), "entra", "entra", now, modsettings.DefaultSyncAt); k.Panel() || k.Err == nil {
		t.Fatalf("junk settings: %+v", k)
	}
}

func TestReportRunSendsTheRun(t *testing.T) {
	var got modsettings.Run
	c := panelServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/modules/entra/runs" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(201)
	})
	run := modsettings.Run{Started: time.Now().Add(-time.Second), Finished: time.Now(), Status: "ok", Counts: modsettings.Counts{Created: 3}, RunRequest: "r9"}
	if err := c.ReportRun(context.Background(), "entra", run); err != nil {
		t.Fatal(err)
	}
	if got.Status != "ok" || got.Counts.Created != 3 || got.RunRequest != "r9" {
		t.Fatalf("%+v", got)
	}
}
