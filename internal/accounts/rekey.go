package accounts

import (
	"errors"
	"fmt"
	"github.com/kazuhahub/rackbook/internal/audit"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/statekey"
)

// RekeyReport says which keys were involved (key ids only).
type RekeyReport struct{ OldKID, NewKID string }

// Rekey re-encrypts accounts.enc and secrets.enc and re-MACs usernames under newKey, recorded as
// account_store_rekeyed (4.7). o.Key is the old key. It follows the writer's sequence for both documents at
// once: the new states go to .pending under the old key, one audit event names both changes, and
// the new-key files are written as .next and renamed into place; a crash at any point is recovered
// by the start with whichever key works (the old key undoes it, the new key finishes it).
func Rekey(o Offline, newKey *statekey.Key) (*RekeyReport, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	if newKey == nil {
		return nil, errors.New("rekey needs the new key")
	}
	if newKey.Equal(o.Key) {
		return nil, errors.New("the new key is the same as the old key")
	}
	oo := o.options()
	oo.hook = nil
	s, err := Open(oo)
	if err != nil {
		return nil, fmt.Errorf("the stores must start cleanly under the old key before a rekey: %w", err)
	}
	sec, err := OpenSecrets(oo)
	if err != nil {
		return nil, fmt.Errorf("the stores must start cleanly under the old key before a rekey: %w", err)
	}
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	sec.eng.wmu.Lock()
	defer sec.eng.wmu.Unlock()

	nextA, nextS := s.eng.clone(s.eng.cur), sec.eng.clone(sec.eng.cur)
	nextA.Change, nextS.Change = newChangeID(), newChangeID()
	// the pending files, under the old key: undoing the rekey is a start with the old key
	for _, w := range []struct {
		path string
		data func() ([]byte, error)
	}{
		{s.eng.path(".pending"), func() ([]byte, error) { return s.eng.seal(nextA) }},
		{sec.eng.path(".pending"), func() ([]byte, error) { return sec.eng.seal(nextS) }},
	} {
		b, err := w.data()
		if err == nil {
			err = writeFile(w.path, b)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := o.hookStep("pending"); err != nil {
		return nil, err
	}
	ev := o.event("account_store_rekeyed", "", "change:"+nextA.Change, "secrets_change:"+nextS.Change, "from_kid:"+o.Key.KID(), "to_kid:"+newKey.KID())
	seq, month, err := o.Log.RecordSyncMonth(ev)
	if errors.Is(err, audit.ErrNotDurable) {
		// the event has its seq: the .pending files stay, and a start with the old key finishes them
		return nil, fmt.Errorf("the rekey event was written but not confirmed on disk; run rekey again with the old key (its start recovers the pending change): %w", err)
	}
	if err != nil {
		os.Remove(s.eng.path(".pending"))
		os.Remove(sec.eng.path(".pending"))
		return nil, &auditError{err}
	}
	if err := o.hookStep("event"); err != nil {
		return nil, err
	}
	nextA.AuditSeq, nextA.AuditMonth, nextS.AuditSeq, nextS.AuditMonth = seq, month, seq, month

	// the new-key files, written as .next; usernames.next is MACed under the new key
	sealNew := func(p statekey.Purpose, v any) ([]byte, error) {
		pt, err := marshal(v)
		if err != nil {
			return nil, err
		}
		return statekey.Seal(newKey, p, pt)
	}
	ba, err := sealNew(statekey.PurposeAccounts, nextA)
	if err != nil {
		return nil, err
	}
	bs, err := sealNew(statekey.PurposeSecrets, nextS)
	if err != nil {
		return nil, err
	}
	if err := writeFile(s.eng.path(".next"), ba); err != nil {
		return nil, err
	}
	if err := writeFile(sec.eng.path(".next"), bs); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(s.dir, usernamesFil+".next"), encodeUsernames(newKey, s.used.list())); err != nil {
		return nil, err
	}
	if err := o.hookStep("next"); err != nil {
		return nil, err
	}
	for i, r := range [][2]string{
		{s.eng.path(".next"), s.eng.path("")},
		{sec.eng.path(".next"), sec.eng.path("")},
		{filepath.Join(s.dir, usernamesFil+".next"), filepath.Join(s.dir, usernamesFil)},
	} {
		if err := renameSync(r[0], r[1]); err != nil {
			return nil, err
		}
		if err := o.hookStep(fmt.Sprintf("rename%d", i+1)); err != nil {
			return nil, err
		}
	}
	for _, p := range []string{s.eng.path(".pending"), sec.eng.path(".pending")} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			o.printf("could not delete %s; the next start does\n", filepath.Base(p))
		}
	}
	o.printf("Re-encrypted under key %s (was %s). Use the new key from now on; the old one opens nothing.\n", newKey.KID(), o.Key.KID())
	return &RekeyReport{OldKID: o.Key.KID(), NewKID: newKey.KID()}, nil
}

// promoteUsernamesNext finishes a rekey that stopped before usernames was renamed: usernames.next, if its
// MAC verifies under the loaded key, replaces the file. One that does not verify is set aside.
func promoteUsernamesNext(dir string, key *statekey.Key) error {
	next := filepath.Join(dir, usernamesFil+".next")
	if _, err := os.Lstat(next); err != nil {
		return nil
	}
	if _, err := ReadUsernames(next, key); err == nil {
		return renameSync(next, filepath.Join(dir, usernamesFil))
	}
	to := next + ".evidence-" + time.Now().UTC().Format("20060102T150405Z")
	return renameSync(next, to)
}

// ---- discard-store (4.7)

// DiscardReport says what discard-store did.
type DiscardReport struct {
	Usernames int
	Moved     []string
	Dir       string
}

// DiscardStore is for a lost key: the account store and secrets.enc, which no key opens, are moved aside
// (never deleted), usernames is MACed again under the loaded key after the operator confirmed the list, and
// new empty stores are written, recorded as account_store_problem with code discarded. Everyone is invited
// again under new usernames, and the provider secrets are entered again in the console.
//
// The loaded key is by definition not the store's key here, so the command shows both key ids and, when
// the store's id is known, refuses unless forceWrongKey says the store's key is really lost.
func DiscardStore(o Offline, confirm func(names []string) (bool, error), forceWrongKey bool) (*DiscardReport, error) {
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
	// Only a store the key cannot open (or that is missing) is discarded; a readable one is not touched.
	lost := func(e *StartError) (bool, error) {
		switch {
		case e == nil:
			return false, nil
		case e.Code == CodeWrongKey || e.Code == CodeCorrupt || e.Code == CodeMissing:
			return true, nil
		}
		return false, fmt.Errorf("discard-store is for a lost key; this is another problem: %w", e)
	}
	accSE, secSE := s.eng.start(), sec.eng.start()
	discAcc, err := lost(accSE)
	if err != nil {
		return nil, err
	}
	discSec, err := lost(secSE)
	if err != nil {
		return nil, err
	}
	if !discAcc && !discSec {
		return nil, errors.New("the stores open with this key: there is nothing to discard (use accept-restore for a gap, rekey to change the key)")
	}
	o.printf("Key tried (from RACKBOOK_STATE_KEY or --state-key-file): %s\n", o.Key.KID())
	var known []string
	for _, f := range []struct {
		name string
		se   *StartError
	}{{accountsFile, accSE}, {secretsFile, secSE}} {
		switch {
		case f.se == nil:
		case f.se.FileKID != "":
			o.printf("  %s was encrypted under key %s\n", f.name, f.se.FileKID)
			known = append(known, f.name+" needs "+f.se.FileKID)
		default:
			o.printf("  %s: %s\n", f.name, f.se.Msg)
		}
	}
	if len(known) > 0 && !forceWrongKey {
		return nil, fmt.Errorf("the loaded key is not the one the store was encrypted under (%s). If that key is really lost, run again with --key-is-lost; if you only loaded the wrong key, load the right one and use the store as it is", strings.Join(known, ", "))
	}

	// the usernames file is MACed under the lost key: its list is shown and confirmed, not verified
	uPath := filepath.Join(s.dir, usernamesFil)
	var names []string
	if discAcc {
		fileNames, err := ReadUsernamesUnverified(uPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("the usernames file does not parse: %w", err)
		}
		inv, err := invitedTargets(o.Log)
		if err != nil {
			return nil, err
		}
		names = sortedUnique(slices.Concat(fileNames, inv))
		o.printf("Usernames that stay used and will be MACed again under the new key (%d):\n", len(names))
		for _, n := range names {
			o.printf("  %s\n", n)
		}
	}
	if confirm != nil {
		ok, err := confirm(names)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("not confirmed; nothing was changed")
		}
	}

	rep := &DiscardReport{Usernames: len(names), Dir: filepath.Join(o.StateDir, accountsDir, "discarded-"+o.now().UTC().Format("20060102T150405Z"))}
	if err := EnsureDir(rep.Dir); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		dir, base string
		move      bool
	}{{s.dir, accountsFile, discAcc}, {o.StateDir, secretsFile, discSec}} {
		if !f.move {
			continue
		}
		ents, _ := os.ReadDir(f.dir)
		for _, ent := range ents {
			n := ent.Name()
			if ent.Type().IsRegular() && (n == f.base || strings.HasPrefix(n, f.base+".")) {
				if err := renameSync(filepath.Join(f.dir, n), filepath.Join(rep.Dir, n)); err != nil {
					return nil, err
				}
				rep.Moved = append(rep.Moved, n)
			}
		}
	}
	if err := o.hookStep("moved"); err != nil {
		return nil, err
	}
	if discAcc {
		if err := WriteUsernames(uPath, o.Key, names); err != nil {
			return nil, err
		}
	}
	if err := o.hookStep("usernames"); err != nil {
		return nil, err
	}
	a, b := newState(), newSecretsState()
	a.Change, b.Change = newChangeID(), newChangeID()
	a.Usernames = names
	detail := []string{fmt.Sprintf("usernames:%d", len(names))}
	if discAcc {
		detail = append(detail, "change:"+a.Change)
	}
	if discSec {
		detail = append(detail, "secrets_change:"+b.Change)
	}
	ev := o.event("account_store_problem", "discarded", detail...)
	seq, month, err := o.Log.RecordSyncMonth(ev)
	if err != nil {
		return nil, &auditError{err}
	}
	if err := o.hookStep("event"); err != nil {
		return nil, err
	}
	a.AuditSeq, a.AuditMonth, b.AuditSeq, b.AuditMonth = seq, month, seq, month
	if discAcc {
		if err := s.eng.writeNew(a); err != nil {
			return nil, err
		}
	}
	if discSec {
		if err := sec.eng.writeNew(b); err != nil {
			return nil, err
		}
	}
	o.printf("The stores were moved to %s. Invite everyone again under new usernames, and enter the provider secrets again in the console.\n", rep.Dir)
	return rep, nil
}
