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

	"github.com/kazuhahub/rackbook/internal/anchor"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/internal/gitstore"
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
Exit status 1: anything else, with the first broken seq.

A problem the server wrote down at start and an administrator acknowledged on the
Activity page is still listed, marked "acknowledged at seq N", and still counts:
acknowledging stops it from blocking retention and from showing as a banner, it does
not make the chain intact.

With --repo (the server's clone of the data repository, or any current clone of it)
the daily anchors in .rackbook/audit-anchors are checked too: each anchor that is
still inside the kept log must name the hash of the line at its seq. An anchor that
does not match, or that is beyond the end of the log, is a problem (anchor_mismatch,
anchor_ahead), and so is an anchor that cannot be one (anchor_invalid: dated after
tomorrow, or not after the previous anchor that matched). The file is read as it is
checked out: pull the clone first. If the clone is a Git repository, the history of the
file is checked as well, as the server does: for every commit that touches it and each of
that commit's parents (so every side of every merge), the file must be the parent's with
lines appended, else the commit is an anchor_rewritten problem.

If the history cannot be checked (a git failure, an answer that does not fit what was asked), or
the anchor file cannot be read, that is a failure: exit status 1 (anchor_unreadable, or an error),
never a pass. That includes a directory that is no Git repository (anchor_unreadable,
not_repository): give --no-history to say that only the file is wanted; it is then checked, and
a note says the history was not. A version of the file above 4 MiB, or that is not a regular
file, is a problem too.

By default no anchor is skipped. If the server runs with --audit-retention-months, pass the
same number as --retention-months: only then an anchor that is below the first kept line,
dated on or before the first day of the cutoff month (now minus that many months), and older
in the file than the newest anchor that matched, is skipped (and counted). This works whether
or not audit.anchor is on. Without --repo the anchors are not checked.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, _ := cmd.Flags().GetString("state-dir")
			if dir == "" {
				return errors.New("--state-dir is required")
			}
			var rep audit.Report
			var err error
			if repo, _ := cmd.Flags().GetString("repo"); repo != "" {
				var anchors []byte
				if anchors, err = readAnchorFile(repo); err != nil {
					return err
				}
				months, _ := cmd.Flags().GetInt("retention-months")
				if months < 0 {
					return errors.New("--retention-months must be 0 (the log keeps everything) or more")
				}
				var extra []audit.Problem
				var note string
				if noHistory, _ := cmd.Flags().GetBool("no-history"); noHistory {
					note = "the history of " + audit.AnchorsPath + " was not checked (--no-history)"
				} else {
					switch chk, herr := gitstore.CheckStateFileInClone(cmd.Context(), repo, audit.AnchorsPath); {
					case herr != nil:
						// a check that cannot be done is a failure, not a pass: that includes a directory
						// that is no Git repository, unless --no-history says the history is not wanted
						reason := "history_error"
						switch {
						case errors.Is(herr, gitstore.ErrNotRepository):
							reason = "not_repository"
						case errors.Is(herr, gitstore.ErrStateDesync):
							reason = "history_desync"
						}
						tip := ""
						if chk != nil {
							tip = chk.Tip
						}
						extra = append(extra, audit.UnreadableAnchors(reason, tip, herr.Error()))
					default:
						extra = anchor.ProblemsOf(chk)
					}
				}
				rep, err = audit.VerifyWithAnchors(filepath.Join(dir, "audit"), anchors, audit.AnchorOptions{RetentionMonths: months}, extra...)
				if err == nil && note != "" && rep.Anchors != nil {
					rep.Anchors.Note = note
				}
			} else {
				rep, err = audit.Verify(filepath.Join(dir, "audit"))
			}
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
	verify.Flags().String("repo", "", "a clone of the data repository: also check the daily anchors in its .rackbook/audit-anchors (as checked out)")
	verify.Flags().Bool("no-history", false, "with --repo: check only the anchor file as checked out, not the history of the file in Git (needed for a directory that is not a Git repository)")
	verify.Flags().Int("retention-months", 0, "with --repo: the server's --audit-retention-months. 0 (the default) means no anchor is skipped; with more, only an anchor that retention could have removed is (see the long help)")
	verify.Flags().Bool("json", false, "print the report as JSON")
	cmd.AddCommand(verify)
	return cmd
}

// readAnchorFile reads .rackbook/audit-anchors of a clone; nil when it has none. The clone may
// be somebody else's: nothing is followed out of it, and neither .rackbook nor the file may be a
// symbolic link. The file is opened through os.Root, then checked to be the regular file the
// directory entry names, so what is read is what was checked.
func readAnchorFile(repo string) ([]byte, error) {
	root, err := os.OpenRoot(repo)
	if err != nil {
		return nil, fmt.Errorf("--repo: %w", err)
	}
	defer root.Close()
	dirName := strings.SplitN(audit.AnchorsPath, "/", 2)[0]
	fileName := strings.SplitN(audit.AnchorsPath, "/", 2)[1]
	st, err := root.Lstat(dirName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s/%s is not a directory (a symbolic link is refused)", repo, dirName)
	}
	sub, err := root.OpenRoot(dirName)
	if err != nil {
		return nil, err
	}
	defer sub.Close()
	l, err := sub.Lstat(fileName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !l.Mode().IsRegular() {
		return nil, fmt.Errorf("%s/%s is not a regular file (a symbolic link is refused)", repo, audit.AnchorsPath)
	}
	f, err := sub.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !os.SameFile(fi, l) {
		return nil, fmt.Errorf("%s changed while it was opened", audit.AnchorsPath)
	}
	return io.ReadAll(io.LimitReader(f, 64<<20))
}

// printAnchors says what the anchors were compared with; malformed lines are a
// warning (nothing about the chain is wrong), not a failure.
func printAnchors(out io.Writer, a *audit.AnchorSummary) {
	if a == nil {
		return
	}
	fmt.Fprintf(out, "anchors: %d checked", a.Checked)
	if a.Skipped > 0 {
		fmt.Fprintf(out, ", %d before the first kept line skipped", a.Skipped)
	}
	fmt.Fprintln(out)
	if a.Note != "" {
		fmt.Fprintln(out, "note: "+a.Note)
	}
	if len(a.Malformed) > 0 {
		fmt.Fprintf(out, "warning: lines %v of .rackbook/audit-anchors are not anchors (left as they are)\n", a.Malformed)
	}
}

func printReport(out io.Writer, rep audit.Report) {
	defer printAnchors(out, rep.Anchors)
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
