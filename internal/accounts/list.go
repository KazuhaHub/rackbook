package accounts

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kazuhahub/rackbook/internal/statekey"
)

// List prints the account store as an operator reads it: usernames, state, factors (present or not,
// never their material), counters, locks, pending links and revocations, evidence files. It reads
// the files without recovering anything or taking a lock, so it works while the server runs. No hash,
// secret, token or key is printed.
func List(w io.Writer, stateDir string, key *statekey.Key, now time.Time) error {
	st, evidence, leftover, err := Inspect(stateDir, key)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "account store: change %s, audit seq %d, audit month %s\n", st.Change, st.AuditSeq, orDash(st.AuditMonth))
	if len(leftover) > 0 {
		fmt.Fprintf(w, "left over from a write that did not finish (the next start recovers or refuses): %s\n", strings.Join(leftover, ", "))
	}
	if len(evidence) > 0 {
		fmt.Fprintf(w, "evidence files (set aside by a start; kept until accept-restore): %s\n", strings.Join(evidence, ", "))
	}
	secrets, secErr := inspectSecrets(stateDir, key)
	switch {
	case secErr == nil:
		fmt.Fprintf(w, "secrets: has_captcha_secret=%v has_oidc_client_secret=%v\n", secrets.Secrets[SecretCaptcha] != nil, secrets.Secrets[SecretOIDCClient] != nil)
	default:
		fmt.Fprintf(w, "secrets: %v\n", secErr)
	}
	if len(st.Usernames) > 0 {
		fmt.Fprintf(w, "usernames ever used: %d\n", len(st.Usernames))
	}
	fmt.Fprintln(w)
	if len(st.Accounts) == 0 {
		fmt.Fprintln(w, "no accounts")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tSTATE\tPASSWORD\tTOTP\tPASSKEYS\tFAILS pw/totp/passkey/reauth\tLOCKS\tLAST SIGN-IN")
	for _, n := range st.Names() {
		a := st.Accounts[n]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", a.Username, a.State, yesNo(a.Password != ""), yesNo(a.TOTP != nil), len(a.Passkeys),
			failures(a), locks(a, now), lastLogin(a))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, n := range st.Names() {
		a := st.Accounts[n]
		var notes []string
		if a.Pending != nil {
			p := a.Pending
			s := fmt.Sprintf("pending %s", p.Kind)
			if p.Scope != "" {
				s += " (" + p.Scope + ")"
			}
			switch {
			case len(p.TokenHash) == 0:
				s += ", no link issued yet"
			case !p.Expires.IsZero() && p.Expires.Before(now):
				s += ", link expired " + p.Expires.UTC().Format(time.RFC3339)
			default:
				s += ", link expires " + p.Expires.UTC().Format(time.RFC3339)
			}
			if !p.HeldUntil.IsZero() && p.HeldUntil.After(now) {
				s += ", held until " + p.HeldUntil.UTC().Format(time.RFC3339)
			}
			notes = append(notes, s)
		}
		if !a.PendingRevocations.Empty() {
			notes = append(notes, fmt.Sprintf("revocations pending: tokens [%s] grants [%s]", strings.Join(a.PendingRevocations.Tokens, ", "), strings.Join(a.PendingRevocations.Grants, ", ")))
		}
		if len(a.GoodBuckets) > 0 {
			notes = append(notes, fmt.Sprintf("%d known network(s)", len(a.GoodBuckets)))
		}
		if len(a.Notices) > 0 {
			notes = append(notes, fmt.Sprintf("%d notice(s) not yet shown to the holder", len(a.Notices)))
		}
		if len(notes) > 0 {
			fmt.Fprintf(w, "  %s: %s\n", n, strings.Join(notes, "; "))
		}
	}
	return nil
}

func inspectSecrets(stateDir string, key *statekey.Key) (*SecretsState, error) {
	eng := newEngine(engineConfig[*SecretsState]{Dir: stateDir, Base: secretsFile, Purpose: statekey.PurposeSecrets, Key: key, New: newSecretsState})
	d, err := eng.readDoc(filepath.Join(stateDir, secretsFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return newSecretsState(), nil
		}
		return nil, keyErr(err, secretsFile)
	}
	return d, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func failures(a *Account) string {
	return fmt.Sprintf("%d/%d/%d/%d", a.ConsecutiveFailures, a.TOTPFailures, a.PasskeyPathFailures, a.ReauthFailures)
}

func locks(a *Account, now time.Time) string {
	var out []string
	for _, l := range a.Locks {
		if l.Until.After(now) {
			out = append(out, l.Scope+" until "+l.Until.UTC().Format("2006-01-02T15:04Z"))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ", ")
}

func lastLogin(a *Account) string {
	if a.LastLogin == nil {
		return "never"
	}
	s := a.LastLogin.Time.UTC().Format("2006-01-02T15:04Z")
	if a.LastLogin.Addr != "" {
		s += " from " + a.LastLogin.Addr
	}
	return s
}
