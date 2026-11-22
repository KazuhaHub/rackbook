package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/fsutil"
)

// auditFlags reads and checks --audit-addr and --audit-retention-months.
func auditFlags(f *pflag.FlagSet) (audit.AddrMode, int, error) {
	s, _ := f.GetString("audit-addr")
	mode, err := audit.ParseAddrMode(s)
	if err != nil {
		return "", 0, err
	}
	n, _ := f.GetInt("audit-retention-months")
	if n < 0 {
		return "", 0, errors.New("--audit-retention-months must be 0 (keep everything) or more")
	}
	return mode, n, nil
}

// warnAuditWithoutState says the audit flags do nothing without --state-dir.
func warnAuditWithoutState(logger *slog.Logger, mode audit.AddrMode, retention int) {
	if mode != audit.AddrTruncate {
		logger.Warn("--audit-addr has no effect without --state-dir: there is no audit file")
	}
	if retention > 0 {
		logger.Warn("--audit-retention-months has no effect without --state-dir: there is no audit file")
	}
}

// prepareStateDir checks and creates --state-dir and takes its lock: one
// server at a time owns it, because the grant file and the others are read
// once and rewritten whole. The result releases the lock.
func prepareStateDir(cfg *config.Config, dir string, strict bool, logger *slog.Logger) (func(), error) {
	// a file inside the clone would make it dirty and stop every write
	abs, _ := filepath.Abs(dir)
	if rel, err := filepath.Rel(cfg.Dir, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("--state-dir %s is inside the data repository; put it beside the clone", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("--state-dir: %w", err)
	}
	if err := secureStateDir(dir, strict, logger); err != nil {
		return nil, err
	}
	unlock, err := fsutil.Lock(filepath.Join(dir, "rackbook.lock"))
	if err != nil {
		if errors.Is(err, fsutil.ErrLocked) {
			return nil, fmt.Errorf("another rackbook serve is already using --state-dir %s (%w)", dir, err)
		}
		return nil, fmt.Errorf("--state-dir: %w", err)
	}
	return unlock, nil
}

// commitHook records the commits of the data repository (area ledger) once
// Rackbook's own push succeeded. A nil log gives no hook.
func commitHook(l *audit.Log, area, repo string) func(string, *auth.Identity, string) {
	if l == nil {
		return nil
	}
	return func(hash string, who *auth.Identity, record string) {
		e := audit.Event{Event: "commit", Area: area, Repo: repo, Hash: hash, Record: record}
		e.By(who)
		l.Record(e)
	}
}

// infraCommitHook records a commit of the infra repository.
func infraCommitHook(l *audit.Log, repo, hash string, who *auth.Identity, scope string) {
	if h := commitHook(l, "infra", repo); h != nil {
		h(hash, who, scope)
	}
}

func newAudit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Check the audit log kept in --state-dir",
	}
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Check that the audit log chain is intact",
		Long: `Walk the audit log in <state-dir>/audit and check that every line chains to the
one before it and that the last line matches head.json. It reads only; it never
changes a file.

It is safe to run while the server is running: it reads the month files first and head.json
last, and looks again before it reports a mismatch.

Exit status 0: the chain is intact. A line cut short by a crash, or a head.json one
line behind, are warnings only (the server repairs both at start) and also exit 0.
Exit status 1: anything else, with the first broken seq.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, _ := cmd.Flags().GetString("state-dir")
			if dir == "" {
				return errors.New("--state-dir is required")
			}
			rep, err := audit.Verify(filepath.Join(dir, "audit"))
			if err != nil {
				return err
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if rep.Problems == nil {
					rep.Problems = []audit.Problem{}
				}
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				printReport(out, rep)
			}
			if !rep.OK && !rep.Repairable() {
				return exitError{1}
			}
			return nil
		},
	}
	verify.Flags().String("state-dir", "", "the server's --state-dir (the log is in its audit directory)")
	verify.Flags().Bool("json", false, "print the report as JSON")
	cmd.AddCommand(verify)
	return cmd
}

func printReport(out io.Writer, rep audit.Report) {
	if rep.OK {
		fmt.Fprintf(out, "ok: %d lines in %d files, the chain is intact\n", rep.Lines, rep.Files)
		return
	}
	state := "PROBLEMS"
	if rep.Repairable() {
		state = "warnings"
	}
	fmt.Fprintf(out, "%s: %d lines in %d files, %d found\n", state, rep.Lines, rep.Files, len(rep.Problems))
	for _, p := range rep.Problems {
		fmt.Fprintln(out, "  "+p.Describe())
	}
	if rep.Repairable() {
		fmt.Fprintln(out, "these are not tampering: the server repairs them when it starts")
	}
}
