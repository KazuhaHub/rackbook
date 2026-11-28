package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/login"
	"github.com/kazuhahub/rackbook/internal/statekey"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

// The offline commands of local accounts (docs/design-local-accounts.md, 11.2). They work on the files in
// --state-dir directly, with the state key, and they need the server stopped: they take the state
// directory's lock. They are not reachable from HTTP.

func newAccounts() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "Offline commands for the local account store in --state-dir (sign-in is not built yet)",
		Long: `Local accounts cannot sign in yet: serve --auth login with the state key opens the account store and
evaluates local: role entries, but the sign-in pages and the online commands come later. These commands prepare
and repair the encrypted files under --state-dir:

  accounts/accounts.enc   the account store (encrypted under the state key)
  secrets.enc             provider secrets set in the console (encrypted under the state key)
  accounts/usernames      every username ever used (MACed under the state key)

The state key is 32 or more random bytes (openssl rand -base64 32), in RACKBOOK_STATE_KEY (base64) or
--state-key-file. Keep it outside the state directory, and back it up separately from it. It must
differ from the session key.

rekey, accept-restore and discard-store need the server stopped. list only reads.`,
	}
	f := cmd.PersistentFlags()
	f.String("state-dir", "", "the directory of the audit log and the account files")
	f.String("state-key-file", "", "file with the base64 state key (alternative to RACKBOOK_STATE_KEY)")
	f.String("session-key-file", "", "file with the base64 session key, only to check that the state key differs from it (or RACKBOOK_SESSION_KEY)")
	f.String("operator", "", "who runs the command, written into the audit event as operator:<text> (default: the operating system user)")

	list := &cobra.Command{
		Use:   "list",
		Short: "Show usernames, state, factors, counters, locks, pending links and revocations, evidence files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, key, err := stateAndKey(cmd)
			if err != nil {
				return err
			}
			return accounts.List(cmd.OutOrStdout(), dir, key, time.Now())
		},
	}

	rekey := &cobra.Command{
		Use:   "rekey",
		Short: "Re-encrypt the account files under a new state key (offline)",
		Long: `Re-encrypt accounts.enc and secrets.enc and MAC usernames again under a new key, recorded as
account_store_rekeyed. The current key comes from RACKBOOK_STATE_KEY or --state-key-file; the new one from
--new-key-file, or --generate makes a new random key and writes it there (mode 0600, never printed).
Afterwards use only the new key; the old one opens nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			off, done, err := offlineSession(cmd)
			if err != nil {
				return err
			}
			defer done()
			newKey, err := loadNewKey(cmd, off.StateDir)
			if err != nil {
				return err
			}
			defer newKey.Zero()
			if err := checkSessionKey(cmd, newKey); err != nil {
				return err
			}
			_, err = accounts.Rekey(off, newKey)
			return err
		},
	}
	rekey.Flags().String("new-key-file", "", "file with the new base64 state key")
	rekey.Flags().Bool("generate", false, "make a new random key and write it to --new-key-file (which must not exist)")

	restore := &cobra.Command{
		Use:   "accept-restore",
		Short: "Accept a restored or rolled-back store after the server refused to start (offline)",
		Long: `When the account store is older than the audit log (a gap), the server stops. This command prints every
change event after the store's, re-applies the restrictive ones (disable, remove, sessions ended,
factors removed, resets, invite revocations and the revocations they list), puts every account named by
such an event into reset_pending with scope all, renews every session secret, clears every known
network, and records account_store_restored.

It also handles a rolled-back or truncated audit log (--accept-audit-truncation) and a store month
that retention deleted (--reset-all-accounts); both put every account into reset_pending.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			off, done, err := offlineSession(cmd)
			if err != nil {
				return err
			}
			defer done()
			ro := accounts.RestoreOptions{}
			ro.AcceptAuditTruncation, _ = cmd.Flags().GetBool("accept-audit-truncation")
			ro.ResetAllAccounts, _ = cmd.Flags().GetBool("reset-all-accounts")
			if yes, _ := cmd.Flags().GetBool("yes"); !yes {
				ro.Confirm = func() (bool, error) { return confirm(cmd, "Type yes to apply this: ") }
			}
			if repo, _ := cmd.Flags().GetString("repo"); repo != "" {
				var commit string
				if off.TokenNames, commit, err = listTokenNames(cmd.Context(), repo); err != nil {
					return err
				}
				off.TokensListed = true
				fmt.Fprintf(cmd.OutOrStdout(), "API tokens listed from %s at commit %s (%d). Pull the clone first; tokens created since that commit are not listed.\n", repo, commit, len(off.TokenNames))
			}
			_, err = accounts.AcceptRestore(off, ro)
			return err
		},
	}
	restore.Flags().Bool("accept-audit-truncation", false, "accept that the audit log was rolled back or truncated")
	restore.Flags().Bool("reset-all-accounts", false, "accept that the store's audit month was deleted by retention")
	restore.Flags().Bool("yes", false, "do not ask for confirmation")
	restore.Flags().String("repo", "", "a clone of the data repository: its API token names are listed as pending revocations when the audit log cannot be trusted")

	discard := &cobra.Command{
		Use:   "discard-store",
		Short: "Start over after the state key was lost (offline)",
		Long: `For a lost key. The account store and secrets.enc, which no key opens, are moved aside (kept, not deleted); the
list of usernames ever used is shown and, once you confirm it, MACed again under the key you have now, so
no name comes back; new empty stores are written, recorded as account_store_problem (discarded). Invite
everyone again under new usernames and enter the provider secrets again in the console.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			off, done, err := offlineSession(cmd)
			if err != nil {
				return err
			}
			defer done()
			var ask func([]string) (bool, error)
			if yes, _ := cmd.Flags().GetBool("yes"); !yes {
				ask = func([]string) (bool, error) {
					return confirm(cmd, "Type yes to keep these names used and discard the stores: ")
				}
			}
			force, _ := cmd.Flags().GetBool("key-is-lost")
			_, err = accounts.DiscardStore(off, ask, force)
			return err
		},
	}
	discard.Flags().Bool("yes", false, "do not ask for confirmation")
	discard.Flags().Bool("key-is-lost", false, "confirm that the key the store was encrypted under (its id is shown) is lost, and that the loaded key is a new one")

	cmd.AddCommand(list, rekey, restore, discard)
	return cmd
}

func confirm(cmd *cobra.Command, prompt string) (bool, error) {
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "yes"), nil
}

// stateAndKey reads --state-dir (which must exist: a typo must not make a new state directory) and loads the state key.
func stateAndKey(cmd *cobra.Command) (string, *statekey.Key, error) {
	dir, _ := cmd.Flags().GetString("state-dir")
	if dir == "" {
		return "", nil, errors.New("--state-dir is required")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return "", nil, fmt.Errorf("--state-dir %s is not a directory", dir)
	}
	file, _ := cmd.Flags().GetString("state-key-file")
	if file != "" {
		if err := outsideStateDir(dir, file); err != nil {
			return "", nil, err
		}
	}
	key, err := statekey.LoadKey("RACKBOOK_STATE_KEY", os.Getenv("RACKBOOK_STATE_KEY"), file)
	if err != nil {
		return "", nil, err
	}
	if err := checkSessionKey(cmd, key); err != nil {
		return "", nil, err
	}
	return dir, key, nil
}

// outsideStateDir refuses a key file kept inside the directory it protects.
func outsideStateDir(dir, file string) error {
	d, err1 := filepath.Abs(dir)
	f, err2 := filepath.Abs(file)
	if err1 != nil || err2 != nil {
		return nil
	}
	if r, err := filepath.EvalSymlinks(d); err == nil {
		d = r
	}
	// the file itself may be a symlink into the state directory; one that does not exist yet (a key to be
	// generated) is resolved by its directory
	if r, err := filepath.EvalSymlinks(f); err == nil {
		f = r
	} else if r, err := filepath.EvalSymlinks(filepath.Dir(f)); err == nil {
		f = filepath.Join(r, filepath.Base(f))
	}
	if rel, err := filepath.Rel(d, f); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("the key file %s is inside --state-dir; keep the key outside the directory it protects", file)
	}
	return nil
}

// checkSessionKey refuses a state key equal to the session key, when the session key is given.
func checkSessionKey(cmd *cobra.Command, key *statekey.Key) error {
	file, _ := cmd.Flags().GetString("session-key-file")
	env := os.Getenv("RACKBOOK_SESSION_KEY")
	if file == "" && env == "" {
		return nil
	}
	if file != "" && env != "" {
		file = "" // the usual precedence is not ours to enforce here
	}
	sk, err := login.LoadSessionKey(env, file)
	if err != nil {
		return err
	}
	return key.DistinctFrom(sk)
}

func loadNewKey(cmd *cobra.Command, stateDir string) (*statekey.Key, error) {
	file, _ := cmd.Flags().GetString("new-key-file")
	if file == "" {
		return nil, errors.New("--new-key-file is required")
	}
	if err := outsideStateDir(stateDir, file); err != nil {
		return nil, err
	}
	if gen, _ := cmd.Flags().GetBool("generate"); gen {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		// the new key is on disk, file and directory entry both, before anything is encrypted under it: a key
		// that is lost after the store was re-encrypted loses the store
		if err := writeKeyFileDurably(file, base64.StdEncoding.EncodeToString(b)+"\n"); err != nil {
			return nil, fmt.Errorf("--new-key-file: the new key could not be written durably, nothing was re-encrypted: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "wrote a new state key to %s (mode 0600)\n", file)
	}
	return statekey.LoadKey("RACKBOOK_NEW_KEY", "", file)
}

// test seams for writeKeyFileDurably
var (
	syncKeyFile = func(f *os.File) error { return f.Sync() }
	syncKeyDir  = func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
)

// writeKeyFileDurably writes content to path, which must not exist, with mode 0600: a temporary file in the same
// directory is written and fsynced, then linked to its name (a link never replaces a file), and the directory is fsynced.
// On any failure nothing is left behind.
func writeKeyFileDurably(path, content string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".newkey-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return err
	}
	_, werr := f.WriteString(content)
	if werr == nil {
		werr = syncKeyFile(f)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	if err := syncKeyDir(dir); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// offlineSession prepares an offline command: the state key, the lock of the state directory (so a
// running server, or another command, stops it) and the audit log without retention.
func offlineSession(cmd *cobra.Command) (accounts.Offline, func(), error) {
	dir, key, err := stateAndKey(cmd)
	if err != nil {
		return accounts.Offline{}, nil, err
	}
	unlock, err := fsutil.Lock(filepath.Join(dir, "rackbook.lock"))
	if err != nil {
		if errors.Is(err, fsutil.ErrLocked) {
			return accounts.Offline{}, nil, fmt.Errorf("--state-dir %s is in use by a running rackbook (or another offline command): stop it first, these commands work on the files directly", dir)
		}
		return accounts.Offline{}, nil, err
	}
	logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	l, err := audit.Open(filepath.Join(dir, "audit"), audit.Options{Logger: logger})
	if err != nil {
		unlock()
		return accounts.Offline{}, nil, err
	}
	op, _ := cmd.Flags().GetString("operator")
	if strings.TrimSpace(op) == "" {
		if u, err := user.Current(); err == nil {
			op = u.Username
		}
	}
	if strings.TrimSpace(op) == "" {
		op = "unknown"
	}
	off := accounts.Offline{StateDir: dir, Key: key, Log: l, Operator: op, Out: cmd.OutOrStdout(), Logger: logger}
	return off, func() { l.Close(); unlock(); key.Zero() }, nil
}

// listTokenNames reads the names of every API token of a clone of the data repository, and the commit the clone is at
// (asked of Git through the repository's own runner). Names only. It is an error, never an empty list, when the
// directory is missing, is not a Git checkout or has no tokens file: an empty list would hide the warning to revoke the
// tokens by hand.
func listTokenNames(ctx context.Context, repo string) (names []string, commit string, err error) {
	const byHand = "pass a clone of the data repository, or leave --repo out and revoke the API tokens by hand"
	if st, err := os.Stat(repo); err != nil || !st.IsDir() {
		return nil, "", fmt.Errorf("--repo %s is not a directory: %s", repo, byHand)
	}
	r := &gitstore.Repo{Dir: repo, IgnoreUserConfig: true}
	if !r.IsRepo(ctx) {
		return nil, "", fmt.Errorf("--repo %s is not a Git checkout: %s", repo, byHand)
	}
	if commit, err = r.Head(ctx); err != nil || commit == "" {
		return nil, "", fmt.Errorf("--repo %s has no commit: %s", repo, byHand)
	}
	b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(tokens.File)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("--repo %s has no %s at commit %s: it is not the data repository, or its checkout is out of date; pull it, or leave --repo out and revoke the API tokens by hand", repo, tokens.File, commit)
	}
	if err != nil {
		return nil, "", err
	}
	ts, err := tokens.Parse(b)
	if err != nil {
		return nil, "", fmt.Errorf("%s does not parse: %w", tokens.File, err)
	}
	for _, t := range ts {
		names = append(names, t.Name)
	}
	return names, commit, nil
}
