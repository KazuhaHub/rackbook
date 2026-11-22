package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/kazuhahub/rackbook/internal/audit"
)

func auditState(t *testing.T, n int) (state, file string) {
	t.Helper()
	state = t.TempDir()
	l, err := audit.Open(filepath.Join(state, "audit"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		l.Record(audit.Event{Event: "login", Identity: "ann@example.com", Time: time.Date(2026, 11, 1+i, 9, 0, 0, 0, time.UTC)})
	}
	l.Close()
	return state, filepath.Join(state, "audit", "audit-2026-11.jsonl")
}

func exitCode(err error) int {
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if err != nil {
		return -1
	}
	return 0
}

func TestAuditVerifyExitCodes(t *testing.T) {
	state, file := auditState(t, 4)
	out, err := run(t, "audit", "verify", "--state-dir", state)
	if exitCode(err) != 0 || !strings.HasPrefix(out, "ok: 4 lines in 1 files") {
		t.Fatalf("%v %s", err, out)
	}

	// JSON report
	out, err = run(t, "audit", "verify", "--state-dir", state, "--json")
	var rep audit.Report
	if exitCode(err) != 0 || json.Unmarshal([]byte(out), &rep) != nil || !rep.OK || rep.Lines != 4 || !strings.Contains(out, `"problems": []`) {
		t.Fatalf("%v %s", err, out)
	}

	// A crash case is a warning: exit 0, and the file is not touched.
	f, _ := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":5,"time":"2026`)
	f.Close()
	before, _ := os.ReadFile(file)
	out, err = run(t, "audit", "verify", "--state-dir", state)
	if exitCode(err) != 0 || !strings.Contains(out, "truncated_tail") || !strings.Contains(out, "repairs them when it starts") {
		t.Fatalf("%v %s", err, out)
	}
	if after, _ := os.ReadFile(file); string(after) != string(before) {
		t.Fatal("verify must never change a file")
	}
	// the server repairs it at start
	l, err := audit.Open(filepath.Join(state, "audit"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if out, err = run(t, "audit", "verify", "--state-dir", state); exitCode(err) != 0 || !strings.HasPrefix(out, "ok:") {
		t.Fatalf("%v %s", err, out)
	}

	// Tampering exits 1 and names the first broken seq.
	b, _ := os.ReadFile(file)
	os.WriteFile(file, []byte(strings.Replace(string(b), "ann@example.com", "eve@example.com", 1)), 0o600)
	out, err = run(t, "audit", "verify", "--state-dir", state)
	if exitCode(err) != 1 || !strings.Contains(out, "edited at seq 1") {
		t.Fatalf("%v %s", err, out)
	}
	out, err = run(t, "audit", "verify", "--state-dir", state, "--json")
	if exitCode(err) != 1 || json.Unmarshal([]byte(out), &rep) != nil || rep.OK || rep.Problems[0].Kind != "edited" {
		t.Fatalf("%v %s", err, out)
	}

	// No directory or no flag: an error, exit 1.
	if _, err = run(t, "audit", "verify", "--state-dir", t.TempDir()); exitCode(err) == 0 {
		t.Fatal("no audit directory must fail")
	}
	if _, err = run(t, "audit", "verify"); err == nil {
		t.Fatal("--state-dir is required")
	}
}

func TestAuditFlagsAreChecked(t *testing.T) {
	cmd := newServe()
	for _, tc := range []struct {
		args    []string
		wantErr string
	}{
		{nil, ""},
		{[]string{"--audit-addr", "full", "--audit-retention-months", "12"}, ""},
		{[]string{"--audit-addr", "bogus"}, "--audit-addr"},
		{[]string{"--audit-retention-months", "-1"}, "--audit-retention-months"},
	} {
		cmd.Flags().VisitAll(func(f *pflag.Flag) { _ = f.Value.Set(f.DefValue) })
		if err := cmd.Flags().Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		_, _, err := auditFlags(cmd.Flags())
		if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%v: %v", tc.args, err)
		}
	}
}

func TestAuditFlagsWarnWithoutStateDir(t *testing.T) {
	var buf strings.Builder
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	warnAuditWithoutState(lg, audit.AddrTruncate, 0)
	if buf.Len() != 0 {
		t.Fatalf("defaults must not warn: %s", buf.String())
	}
	warnAuditWithoutState(lg, audit.AddrFull, 6)
	if !strings.Contains(buf.String(), "--audit-addr has no effect") || !strings.Contains(buf.String(), "--audit-retention-months has no effect") {
		t.Fatalf("%s", buf.String())
	}
}
