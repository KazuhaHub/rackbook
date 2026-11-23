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

func anchorRepo(t *testing.T, lines ...audit.Anchor) string {
	t.Helper()
	repo := t.TempDir()
	if len(lines) > 0 {
		var b []byte
		for _, a := range lines {
			b = append(b, a.Line()...)
		}
		if err := os.MkdirAll(filepath.Join(repo, ".rackbook"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, ".rackbook", "audit-anchors"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

func TestAuditVerifyChecksTheAnchorsOfAClone(t *testing.T) {
	state, _ := auditState(t, 5)
	l, err := audit.Open(filepath.Join(state, "audit"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	seq, hash := l.Head()
	l.Close()
	good := audit.Anchor{Day: "2026-11-02", Seq: seq, Hash: hash, At: "2026-11-02T03:00:00Z"}

	out, err := run(t, "audit", "verify", "--state-dir", state, "--repo", anchorRepo(t, good))
	if exitCode(err) != 0 || !strings.Contains(out, "ok: 5 lines") || !strings.Contains(out, "anchors: 1 checked") {
		t.Fatalf("%v %s", err, out)
	}
	// without --repo the anchors are not looked at, and nothing is said about them
	if out, err = run(t, "audit", "verify", "--state-dir", state); exitCode(err) != 0 || strings.Contains(out, "anchors") {
		t.Fatalf("%v %s", err, out)
	}
	// a clone with no anchor file has nothing to check
	if out, err = run(t, "audit", "verify", "--state-dir", state, "--repo", anchorRepo(t)); exitCode(err) != 0 || !strings.Contains(out, "anchors: 0 checked") {
		t.Fatalf("%v %s", err, out)
	}

	// an anchor whose hash is not the line's: exit 1, with the day and seq
	bad := good
	bad.Seq, bad.Hash = 3, good.Hash
	out, err = run(t, "audit", "verify", "--state-dir", state, "--repo", anchorRepo(t, bad))
	if exitCode(err) != 1 || !strings.Contains(out, "anchor_mismatch at seq 3") || !strings.Contains(out, "2026-11-02") {
		t.Fatalf("%v %s", err, out)
	}
	// an anchor past the end of the log
	ahead := good
	ahead.Seq, ahead.Day = seq+10, "2026-11-03"
	out, err = run(t, "audit", "verify", "--state-dir", state, "--repo", anchorRepo(t, good, ahead), "--json")
	var rep audit.Report
	if exitCode(err) != 1 || json.Unmarshal([]byte(out), &rep) != nil || rep.OK || len(rep.Problems) != 1 ||
		rep.Problems[0].Kind != audit.KindAnchorAhead || rep.Anchors == nil || rep.Anchors.Checked != 2 {
		t.Fatalf("%v %s", err, out)
	}
	// unknown lines are reported, and are not a failure
	repo := anchorRepo(t, good)
	f, _ := os.OpenFile(filepath.Join(repo, ".rackbook", "audit-anchors"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{\"future\":1}\n")
	f.Close()
	out, err = run(t, "audit", "verify", "--state-dir", state, "--repo", repo)
	if exitCode(err) != 0 || !strings.Contains(out, "lines [2] of .rackbook/audit-anchors are not anchors") {
		t.Fatalf("%v %s", err, out)
	}
	// the log is never changed by looking
	// a --repo that is not a directory, or an anchor file that is a link, is an error
	if _, err = run(t, "audit", "verify", "--state-dir", state, "--repo", filepath.Join(repo, "nope")); err == nil {
		t.Fatal("a missing --repo must fail")
	}
	// a symbolic link in place of .rackbook, even to a directory inside the clone, is refused too
	dirLink := anchorRepo(t)
	if err := os.MkdirAll(filepath.Join(dirLink, "elsewhere"), 0o755); err == nil {
		_ = os.WriteFile(filepath.Join(dirLink, "elsewhere", "audit-anchors"), good.Line(), 0o644)
		if err := os.Symlink("elsewhere", filepath.Join(dirLink, ".rackbook")); err == nil {
			if _, err = run(t, "audit", "verify", "--state-dir", state, "--repo", dirLink); err == nil {
				t.Fatal("a linked .rackbook directory must be refused")
			}
		}
	}
	link := anchorRepo(t)
	_ = os.MkdirAll(filepath.Join(link, ".rackbook"), 0o755)
	if err := os.Symlink(filepath.Join(repo, ".rackbook", "audit-anchors"), filepath.Join(link, ".rackbook", "audit-anchors")); err == nil {
		if _, err = run(t, "audit", "verify", "--state-dir", state, "--repo", link); err == nil {
			t.Fatal("a linked anchor file must be refused")
		}
	}
}

func TestAuditVerifyRetentionMonthsDecidesWhatMaySkip(t *testing.T) {
	state := t.TempDir()
	clk := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	l, err := audit.Open(filepath.Join(state, "audit"), audit.Options{Now: func() time.Time { return clk }})
	if err != nil {
		t.Fatal(err)
	}
	var as []audit.Anchor
	for _, m := range []time.Month{8, 9, 10, 11} {
		l.Record(audit.Event{Event: "login", Identity: "ann@example.com", Time: time.Date(2026, m, 3, 9, 0, 0, 0, time.UTC)})
		seq, hash := l.Head()
		as = append(as, audit.Anchor{Day: time.Date(2026, m, 3, 0, 0, 0, 0, time.UTC).Format("2006-01-02"), Seq: seq, Hash: hash, At: "2026-01-01T00:00:00Z"})
	}
	l.Close()
	if err := os.Remove(filepath.Join(state, "audit", "audit-2026-08.jsonl")); err != nil {
		t.Fatal(err)
	}
	repo := anchorRepo(t, as...)
	// by default nothing is skipped: the anchor of the August line, which is gone, is a problem
	out, err := run(t, "audit", "verify", "--state-dir", state, "--repo", repo)
	if exitCode(err) != 1 || !strings.Contains(out, "anchor_mismatch at seq 1") {
		t.Fatalf("%v %s", err, out)
	}
	// with the retention of the server (a gap in the chain aside) that anchor may be skipped
	out, _ = run(t, "audit", "verify", "--state-dir", state, "--repo", repo, "--retention-months", "3")
	if !strings.Contains(out, "anchors: 3 checked, 1 before the first kept line skipped") || strings.Contains(out, "anchor_mismatch") {
		t.Fatalf("%s", out)
	}
	if _, err := run(t, "audit", "verify", "--state-dir", state, "--repo", repo, "--retention-months", "-1"); err == nil {
		t.Fatal("a negative retention must be refused")
	}
}
