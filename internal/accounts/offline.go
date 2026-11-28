package accounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Offline is what the offline commands (11.2) work with: the state directory with its lock taken by the
// caller, the state key, and the audit log opened without retention.
type Offline struct {
	StateDir string
	Key      *statekey.Key
	Log      *audit.Log
	// Operator is the text of operator:<text> in the events these commands write (method cli).
	Operator string
	// TokenNames are the names of every API token of the data repository (.rackbook/tokens.yml), when the caller could
	// list them; accept-restore writes them as pending revocations when the audit log cannot be trusted. Names only.
	TokenNames   []string
	TokensListed bool
	Out          io.Writer
	Now          func() time.Time
	Logger       *slog.Logger

	hook func(step string) error // tests: crash points of rekey and discard
}

func (o *Offline) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *Offline) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return io.Discard
}

func (o *Offline) printf(format string, a ...any) { fmt.Fprintf(o.out(), format, a...) }

func (o *Offline) event(name, code string, detail ...string) audit.Event {
	return audit.Event{Event: name, Method: "cli", Code: code, Detail: append([]string{"operator:" + o.Operator}, detail...)}
}

func (o *Offline) options() Options {
	return Options{StateDir: o.StateDir, Key: o.Key, Log: o.Log, Now: o.Now, Logger: o.Logger, hook: o.hook}
}

func (o *Offline) hookStep(step string) error {
	if o.hook == nil {
		return nil
	}
	return o.hook(step)
}

func (o *Offline) check() error {
	if o.Key == nil || o.Log == nil || o.StateDir == "" {
		return errors.New("an offline command needs the state directory, the state key and the audit log")
	}
	if strings.TrimSpace(o.Operator) == "" {
		return errors.New("an operator name is needed for the audit event (--operator)")
	}
	return nil
}

// ---- accept-restore (4.4)

// RestoreOptions are the flags of accept-restore.
type RestoreOptions struct {
	// AcceptAuditTruncation accepts that the audit log was rolled back or truncated.
	AcceptAuditTruncation bool
	// ResetAllAccounts accepts that the store's audit month was deleted by retention.
	ResetAllAccounts bool
	// Confirm, when set, is asked after the plan is printed and before anything is written.
	Confirm func() (bool, error)
}

// RestoreReport says what accept-restore did.
type RestoreReport struct {
	// Nothing is set when both stores agree with the audit log.
	Nothing     bool
	Accounts    string // "", "gap", "audit_truncated" or "month_pruned"
	Secrets     string
	ResetNames  []string
	ClearedKeys []string
	// GrantsRevoked is how many OAuth grants were removed from oauth-grants.json when the log could not be trusted.
	GrantsRevoked int
}

// AcceptRestore resolves what the start sequence refuses with a gap, a rolled-back or truncated audit
// log, or a pruned month. A gap is never replayed (that would need secrets in the log): the
// restrictive changes are re-applied, every account named by a change after the store is put into
// reset_pending with scope all, every session secret is renewed and every good bucket cleared. The
// stores are rewritten through the single writer, so a crash is recovered at the next start.
func AcceptRestore(o Offline, ro RestoreOptions) (*RestoreReport, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	s, err := newStore(o.options())
	if err != nil {
		return nil, err
	}
	sec, err := newSecrets(o.options())
	if err != nil {
		return nil, err
	}
	accErr, secErr := s.eng.start(), sec.eng.start()
	rep := &RestoreReport{}
	plan := func(se *StartError, what string) (string, error) {
		if se == nil {
			return "", nil
		}
		switch se.Code {
		case CodeGap:
			return "gap", nil
		case CodeAuditTruncated:
			if !ro.AcceptAuditTruncation {
				return "", fmt.Errorf("%s: %s\nThis needs --accept-audit-truncation: every account is then put into reset_pending and every session secret is renewed", what, se.Msg)
			}
			return "audit_truncated", nil
		case CodeMonthPruned:
			if !ro.ResetAllAccounts {
				return "", fmt.Errorf("%s: %s\nThis needs --reset-all-accounts: every account is then put into reset_pending and every session secret is renewed", what, se.Msg)
			}
			return "month_pruned", nil
		}
		return "", fmt.Errorf("%s: accept-restore cannot fix this: %w", what, se)
	}
	var e1, e2 error
	rep.Accounts, e1 = plan(accErr, accountsFile)
	rep.Secrets, e2 = plan(secErr, secretsFile)
	if err := errors.Join(e1, e2); err != nil {
		return nil, err
	}
	if rep.Accounts == "" && rep.Secrets == "" {
		rep.Nothing = true
		o.printf("The stores agree with the audit log. Nothing to accept.\n")
		return rep, nil
	}

	var accPlan *accountsPlan
	if accErr != nil {
		events := gapEvents(accErr)
		if rep.Accounts != "gap" {
			// the log is not trusted, but what is still readable after the store's seq is not ignored either
			chs, err := s.eng.changesFrom("", accErr.Doc.(*State).AuditSeq+1)
			if err != nil {
				return nil, fmt.Errorf("audit log: %w", err)
			}
			for _, c := range chs {
				events = append(events, c.ev)
			}
		}
		accPlan = planAccounts(accErr, rep.Accounts, events)
		o.printf("%s\n", accPlan.describe(accErr, &o))
	}
	var secNames []string
	if secErr != nil {
		cause, globalSince, gerr := globalResetAfter(o.Log, secErr.Doc.(*SecretsState).AuditSeq)
		if gerr != nil {
			return nil, fmt.Errorf("audit log: %w", gerr)
		}
		secNames = secretNames(secErr, rep.Secrets, globalSince)
		switch {
		case rep.Secrets != "gap":
			o.printf("  every secret is cleared because the audit log cannot be trusted (%s)\n", rep.Secrets)
		case globalSince:
			o.printf("  every secret is cleared because of %s\n", cause)
		}
		o.printf("%s: %s\n", secretsFile, secErr.Msg)
		for _, ev := range gapEvents(secErr) {
			o.printf("  seq %d  %s  %s\n", ev.Seq, ev.Time.Format(time.RFC3339), ev.Event)
		}
		if len(secNames) > 0 {
			o.printf("  these secrets are cleared and must be entered again in the console: %s\n", strings.Join(secNames, ", "))
		}
	}
	if ro.Confirm != nil {
		ok, err := ro.Confirm()
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("not confirmed; nothing was changed")
		}
	}

	if accErr != nil {
		if err := s.applyRestore(o, accErr, accPlan, rep); err != nil {
			return nil, err
		}
	}
	if secErr != nil {
		if err := sec.applyRestore(o, secErr, rep.Secrets, secNames); err != nil {
			return nil, err
		}
		rep.ClearedKeys = secNames
	}
	// evidence files are archived, not deleted
	if err := archiveEvidence(o, filepath.Join(o.StateDir, accountsDir), accountsFile, o.StateDir, secretsFile); err != nil {
		o.printf("could not archive the evidence files: %v\n", err)
	}
	return rep, nil
}

func gapEvents(se *StartError) []audit.Event {
	if se.Gap == nil {
		return nil
	}
	return se.Gap.Events
}

// accountsPlan is what accept-restore will do to the account store.
type accountsPlan struct {
	kind   string
	events []audit.Event
	seqs   [2]int64
	named  map[string]bool
	// global: an earlier global reset or restore lies between the backup and now, so every account is reset.
	global bool
	// untrusted: the audit log cannot be relied on (it was rolled back, truncated or pruned, or a global
	// reset is among the events): every account is reset, every OAuth grant revoked, every API token listed.
	untrusted bool
}

// isGlobalReset says an event reset every account: a restore, or a problem that did.
func isGlobalReset(ev audit.Event) bool {
	switch ev.Event {
	case "account_store_restored":
		return true
	case "account_store_problem":
		return ev.Code == "audit_truncated" || ev.Code == "month_pruned" || ev.Code == "discarded"
	}
	return false
}

// planAccounts reads the plan. events are the change events after the store's own seq: for a gap those the
// start found, otherwise those still readable in the log, which is not trusted but is not ignored.
func planAccounts(se *StartError, kind string, events []audit.Event) *accountsPlan {
	p := &accountsPlan{kind: kind, events: events, named: map[string]bool{}}
	st := se.Doc.(*State)
	p.seqs = [2]int64{st.AuditSeq, st.AuditSeq}
	for _, ev := range p.events {
		p.seqs[1] = ev.Seq
		if isGlobalReset(ev) {
			p.global = true
		}
		if n := accountOf(ev); n != "" {
			p.named[n] = true
		}
	}
	p.untrusted = kind != "gap" || p.global
	return p
}

func (p *accountsPlan) describe(se *StartError, o *Offline) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", accountsFile, se.Msg)
	fmt.Fprintf(&b, "  change events still readable after the store's last change (seq %d), re-applied in this order:\n", p.seqs[0])
	if len(p.events) == 0 {
		b.WriteString("    none\n")
	}
	for _, ev := range p.events {
		fmt.Fprintf(&b, "    seq %d  %s  %s", ev.Seq, ev.Time.Format(time.RFC3339), ev.Event)
		if ev.Target != "" {
			fmt.Fprintf(&b, "  target=%s", ev.Target)
		}
		if ev.Code != "" {
			fmt.Fprintf(&b, "  code=%s", ev.Code)
		}
		b.WriteString("\n")
	}
	if p.untrusted {
		switch {
		case p.kind != "gap":
			b.WriteString("  the audit log cannot be trusted: ")
		default:
			b.WriteString("  an earlier change reset every account: ")
		}
		b.WriteString("every account will be put into reset_pending (scope all) and every session secret renewed;\n")
		b.WriteString("  every OAuth grant in oauth-grants.json will be revoked;\n")
		if o.TokensListed {
			fmt.Fprintf(&b, "  every API token (%d: %s) will be written as a pending revocation of every account.\n", len(o.TokenNames), strings.Join(o.TokenNames, ", "))
		} else {
			b.WriteString("  API tokens could not be listed (pass --repo, a clone of the data repository): revoke every API token by hand.\n")
		}
	}
	return b.String()
}

// storeLevel says an event is about the store, not about an account.
func storeLevel(name string) bool {
	return strings.HasPrefix(name, "account_store_") || strings.HasPrefix(name, "settings_")
}

// accountOf names the account a change event is about, "" for none.
func accountOf(ev audit.Event) string {
	if storeLevel(ev.Event) {
		return ""
	}
	n := strings.TrimPrefix(ev.Target, "local:")
	if n == "" && strings.HasPrefix(ev.Identity, "local:") {
		n = strings.TrimPrefix(ev.Identity, "local:")
	}
	if ValidUsername(n) {
		return n
	}
	return ""
}

func detailValues(ev audit.Event, prefix string) []string {
	var out []string
	for _, d := range ev.Detail {
		if v, ok := strings.CutPrefix(d, prefix); ok && v != "" {
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// resetAccount puts an account into reset_pending with scope all (5.8): everything deleted, sessions ended,
// counters, locks and buckets cleared. A removed account stays a tombstone; a disabled one stays disabled.
func resetAccount(a *Account, by string) {
	switch a.State {
	case StateRemoved:
		_ = a.RenewSessions()
		return
	case StateDisabled:
		// it cannot sign in; its credentials go, and enabling it later needs a reset anyway
		a.Pending = nil
	default:
		a.State = StateResetPending
		a.Pending = &Pending{Kind: "reset", Scope: ScopeAll, IssuedBy: by}
	}
	a.Password, a.TOTP, a.Passkeys = "", nil, nil
	a.ConsecutiveFailures, a.TOTPFailures, a.PasskeyPathFailures, a.ReauthFailures = 0, 0, 0, 0
	a.Locks, a.GoodBuckets = nil, nil
	_ = a.RenewSessions()
}

func addUnique(dst []string, add ...string) []string {
	for _, v := range add {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	sort.Strings(dst)
	return dst
}

// reapply applies the restrictive change an event recorded, which needs no secret.
func reapply(st *State, ev audit.Event) {
	name := accountOf(ev)
	a := st.Accounts[name]
	if a == nil {
		return
	}
	switch ev.Event {
	case "account_disabled":
		if a.State != StateRemoved {
			a.State = StateDisabled
		}
		_ = a.RenewSessions()
		a.GoodBuckets = nil
	case "account_removed":
		a.State = StateRemoved
		a.Password, a.TOTP, a.Passkeys, a.Pending, a.Locks, a.GoodBuckets = "", nil, nil, nil, nil, nil
		_ = a.RenewSessions()
	case "sessions_ended":
		_ = a.RenewSessions()
	case "factor_removed":
		if ev.Code == "totp" {
			a.TOTP = nil
		} else {
			a.Passkeys = nil
		}
	case "account_invite_revoked":
		if a.State == StateInvited {
			a.State, a.Pending = StateRemoved, nil
			_ = a.RenewSessions()
		}
	case "account_reset_issued":
		resetAccount(a, "cli")
	}
}

func (s *Store) applyRestore(o Offline, se *StartError, p *accountsPlan, rep *RestoreReport) error {
	doc := se.Doc.(*State)
	grantsDone := map[string]bool{}
	var unknown []string
	if p.untrusted {
		n, err := revokeAllGrantsOffline(o.StateDir)
		if err != nil {
			o.printf("COULD NOT revoke the OAuth grants (%v): remove oauth-grants.json by hand before the server starts\n", err)
		}
		rep.GrantsRevoked = n
	}
	fn := func(st *State) error {
		for _, ev := range p.events {
			if name := accountOf(ev); name != "" && st.Accounts[name] == nil {
				unknown = addUnique(unknown, name)
			}
			reapply(st, ev)
			if a := st.Accounts[accountOf(ev)]; a != nil {
				a.PendingRevocations.Tokens = addUnique(a.PendingRevocations.Tokens, detailValues(ev, "tokens:")...)
				for _, g := range detailValues(ev, "grants:") {
					if done, _ := revokeGrantOffline(o.StateDir, g); done {
						grantsDone[g] = true
					} else {
						a.PendingRevocations.Grants = addUnique(a.PendingRevocations.Grants, g)
					}
				}
			}
		}
		for name, a := range st.Accounts {
			if p.untrusted || p.named[name] {
				resetAccount(a, "cli")
			}
			if p.untrusted && a.State != StateRemoved {
				a.PendingRevocations.Tokens = addUnique(a.PendingRevocations.Tokens, o.TokenNames...)
			}
		}
		// every session secret is renewed and every good bucket cleared, named or not
		for n, a := range st.Accounts {
			_ = a.RenewSessions()
			a.GoodBuckets = nil
			if a.State == StateResetPending && a.Pending != nil && a.Pending.IssuedBy == "cli" {
				rep.ResetNames = append(rep.ResetNames, n)
			}
		}
		sort.Strings(rep.ResetNames)
		return nil
	}
	var ev audit.Event
	if p.kind == "gap" {
		ev = o.event("account_store_restored", "", fmt.Sprintf("from:%d", p.seqs[0]), fmt.Sprintf("to:%d", p.seqs[1]))
	} else {
		ev = o.event("account_store_problem", p.kind, se.Detail...)
	}
	// the stale store is the base of the new one; the usernames of the gap are in the log and are unioned at start
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	s.eng.setCur(doc)
	var named []string
	for _, e := range p.events {
		if e.Event == "account_invited" {
			named = append(named, strings.TrimPrefix(e.Target, "local:"))
		}
	}
	if err := s.loadUsernames(doc); err != nil {
		return err
	}
	s.used.add(named...)
	_, err := s.eng.commit(ev, fn, func(cur, next *State) error {
		next.Usernames = sortedUnique(slices.Concat(s.used.list(), next.Names()))
		return nil
	}, func(*State) error {
		return WriteUsernames(filepath.Join(s.dir, usernamesFil), s.o.Key, s.used.list())
	})
	if err != nil {
		return err
	}
	if len(unknown) > 0 {
		o.printf("accounts the backup does not know (created after it; their names stay used): %s\n", strings.Join(unknown, ", "))
	}
	o.printf("%s: restored. %d account(s) are in reset_pending with scope all; an administrator issues new links (`rackbook accounts recover`).\n", accountsFile, len(rep.ResetNames))
	var pendingTokens []string
	for _, a := range s.eng.cur.Accounts {
		if !a.PendingRevocations.Empty() {
			pendingTokens = append(pendingTokens, fmt.Sprintf("%s (tokens: %s; grants: %s)", a.Username, strings.Join(a.PendingRevocations.Tokens, ","), strings.Join(a.PendingRevocations.Grants, ",")))
		}
	}
	for _, t := range pendingTokens {
		o.printf("  revocations still to apply: %s\n", t)
	}
	if n := len(grantsDone); n > 0 {
		o.printf("  OAuth grants revoked in oauth-grants.json: %d\n", n)
	}
	if p.untrusted {
		o.printf("  every OAuth grant was revoked (%d removed)\n", rep.GrantsRevoked)
		if !o.TokensListed {
			o.printf("  API tokens were NOT listed: revoke every API token of the data repository by hand\n")
		}
	}
	return nil
}

// globalResetAfter says whether the retained log holds, after seq, a global reset of any document: an
// account_store_restored, or an account_store_problem with audit_truncated, month_pruned or discarded. Whatever its
// change marker, it means the log or the stores were not trusted then, and a restored older secrets.enc must not
// bring back what that reset cleared.
//
// The first such event is returned, described for the plan: its kind, code, seq and the document its marker names.
func globalResetAfter(l *audit.Log, seq int64) (cause string, found bool, err error) {
	err = l.EachEvent("", func(ev audit.Event, _ string) bool {
		found = ev.Seq > seq && isGlobalReset(ev)
		if found {
			doc := "no document marker"
			for _, d := range ev.Detail {
				switch {
				case strings.HasPrefix(d, secretsMarker):
					doc = "the secrets store"
				case strings.HasPrefix(d, accountsMarker):
					doc = "the account store"
				}
			}
			cause = fmt.Sprintf("the %s event", ev.Event)
			if ev.Code != "" {
				cause += " (code " + ev.Code + ")"
			}
			cause += fmt.Sprintf(" at seq %d, written for %s", ev.Seq, doc)
		}
		return !found
	})
	return cause, found, err
}

// secretNames are the secrets accept-restore clears for the secrets store: those named by the events after it
// (a clear after the backup must not be undone by it), or all of them when the log cannot be trusted or a global
// reset lies between the backup and now.
func secretNames(se *StartError, kind string, global bool) []string {
	st := se.Doc.(*SecretsState)
	var names []string
	if kind != "gap" || global {
		for n := range st.Secrets {
			names = append(names, n)
		}
	} else {
		for _, ev := range gapEvents(se) {
			names = addUnique(names, detailValues(ev, "name:")...)
		}
	}
	sort.Strings(names)
	return names
}

func (s *Secrets) applyRestore(o Offline, se *StartError, kind string, names []string) error {
	doc := se.Doc.(*SecretsState)
	var ev audit.Event
	if kind == "gap" {
		ev = o.event("account_store_restored", "", "store:secrets")
		if evs := gapEvents(se); len(evs) > 0 {
			ev.Detail = append(ev.Detail, fmt.Sprintf("from:%d", doc.AuditSeq), fmt.Sprintf("to:%d", evs[len(evs)-1].Seq))
		}
	} else {
		ev = o.event("account_store_problem", kind, append([]string{"store:secrets"}, se.Detail...)...)
	}
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	s.eng.setCur(doc)
	_, err := s.eng.commit(ev, func(d *SecretsState) error {
		for _, n := range names {
			delete(d.Secrets, n)
		}
		return nil
	}, nil, nil)
	return err
}

// archiveEvidence moves the evidence files (<base>.*.evidence-*) of the given directories into
// accounts/evidence-<time>/: out of the Users view, and kept.
func archiveEvidence(o Offline, dirBase ...string) error {
	dest := filepath.Join(o.StateDir, accountsDir, "evidence-"+o.now().UTC().Format("20060102T150405Z"))
	moved := 0
	for i := 0; i+1 < len(dirBase); i += 2 {
		dir, base := dirBase[i], dirBase[i+1]
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, ent := range ents {
			if !ent.Type().IsRegular() || !strings.HasPrefix(ent.Name(), base) || !strings.Contains(ent.Name(), ".evidence-") {
				continue
			}
			if err := EnsureDir(dest); err != nil {
				return err
			}
			if err := renameSync(filepath.Join(dir, ent.Name()), filepath.Join(dest, ent.Name())); err != nil {
				return err
			}
			moved++
		}
	}
	if moved > 0 {
		o.printf("%d evidence file(s) moved to %s\n", moved, dest)
	}
	return nil
}

// ---- grants

// revokeGrantOffline removes a grant from oauth-grants.json while the server is stopped. It reports whether
// the file was changed; a file it does not understand is left alone (the revocation then stays pending).
func revokeGrantOffline(stateDir, id string) (bool, error) {
	path := filepath.Join(stateDir, "oauth-grants.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil // nothing to revoke: the grant is not there
	}
	if err != nil {
		return false, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return false, err
	}
	var version int
	if json.Unmarshal(top["version"], &version) != nil || version != 1 {
		return false, errors.New("oauth-grants.json has a version this build does not edit")
	}
	var grants map[string]json.RawMessage
	if err := json.Unmarshal(top["grants"], &grants); err != nil {
		return false, err
	}
	if _, ok := grants[id]; !ok {
		return true, nil
	}
	delete(grants, id)
	top["grants"], _ = json.Marshal(grants)
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return false, err
	}
	return true, writeFile(path, out)
}

// revokeAllGrantsOffline removes every grant from oauth-grants.json (the clients stay), for a log that cannot be
// trusted. It returns how many were removed. A file it does not understand is an error: it is left alone.
func revokeAllGrantsOffline(stateDir string) (int, error) {
	path := filepath.Join(stateDir, "oauth-grants.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return 0, err
	}
	var version int
	if json.Unmarshal(top["version"], &version) != nil || version != 1 {
		return 0, errors.New("oauth-grants.json has a version this build does not edit")
	}
	var grants map[string]json.RawMessage
	if err := json.Unmarshal(top["grants"], &grants); err != nil {
		return 0, err
	}
	n := len(grants)
	if n == 0 {
		return 0, nil
	}
	top["grants"] = json.RawMessage("{}")
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return 0, err
	}
	return n, writeFile(path, out)
}
