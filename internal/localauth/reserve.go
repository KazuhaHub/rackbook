package localauth

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/config"
)

// Reservations of an account's attempt counters (docs/design-local-accounts.md, 8.4). A counter that is checked before the
// work and written after the answer lets a burst of parallel requests all pass the check against the same old value. So an
// attempt reserves its place before it hashes or verifies anything: the check reads the stored count plus the attempts that
// are in flight, under a lock of the account, and adds this attempt to them in the same critical section. A success gives its
// place back; a failure keeps it until its counter write has landed, and the write and the release are one critical section too.
const guardStripes = 64

type inflight struct{ pwd, totp, pk, reauth int }

func (f inflight) zero() bool { return f.pwd == 0 && f.totp == 0 && f.pk == 0 && f.reauth == 0 }

type acctGuard struct {
	stripes [guardStripes]sync.Mutex
	mu      sync.Mutex
	by      map[string]*inflight
}

func newAcctGuard() *acctGuard { return &acctGuard{by: map[string]*inflight{}} }

// lock takes the lock of the account's stripe (several names may share one: it is never held across a hash).
func (g *acctGuard) lock(name string) func() {
	h := fnv.New32a()
	h.Write([]byte(name))
	m := &g.stripes[h.Sum32()%guardStripes]
	m.Lock()
	return m.Unlock
}

func (g *acctGuard) get(name string) inflight {
	g.mu.Lock()
	defer g.mu.Unlock()
	if f := g.by[name]; f != nil {
		return *f
	}
	return inflight{}
}

func (g *acctGuard) add(name string, f func(*inflight)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	x := g.by[name]
	if x == nil {
		x = &inflight{}
		g.by[name] = x
	}
	f(x)
	if x.zero() {
		delete(g.by, name)
	}
}

// resv is what one attempt holds.
type resv struct {
	g                     *acctGuard
	name                  string
	pwd, totp, pk, reauth bool
}

// releaseLocked gives back the places this attempt holds. The caller holds the account's stripe.
func (r *resv) releaseLocked() {
	if r == nil {
		return
	}
	r.g.add(r.name, func(f *inflight) {
		if r.pwd {
			f.pwd--
		}
		if r.totp {
			f.totp--
		}
		if r.pk {
			f.pk--
		}
		if r.reauth {
			f.reauth--
		}
	})
	r.pwd, r.totp, r.pk, r.reauth = false, false, false, false
}

// release is releaseLocked for a caller that does not hold the stripe. It does nothing twice.
func (r *resv) release() {
	if r == nil {
		return
	}
	defer r.g.lock(r.name)()
	r.releaseLocked()
}

// releasePassword gives back the place of the password check (the password was right, so it was no failure).
func (r *resv) releasePassword() {
	if r == nil {
		return
	}
	defer r.g.lock(r.name)()
	r.g.add(r.name, func(f *inflight) {
		if r.pwd {
			f.pwd--
		}
		if r.pk {
			f.pk--
		}
	})
	r.pwd, r.pk = false, false
}

func totpCount(a *accounts.Account, now time.Time) int {
	if a.TOTPWindowStart.IsZero() || !now.Before(a.TOTPWindowStart.Add(24*time.Hour)) {
		return 0
	}
	return a.TOTPFailures
}

func passkeyCount(a *accounts.Account, now time.Time) int {
	if a.PasskeyWindowStart.IsZero() || !now.Before(a.PasskeyWindowStart.Add(time.Hour)) {
		return 0
	}
	return a.PasskeyPathFailures
}

// reservePassword decides whether a password check may run for the account and, if so, reserves its place. A reason says why
// not (and nothing is reserved): the answer is the dead end of 5.6. The account is read afresh under the stripe, so the state,
// the known networks and the limits are the ones this very attempt is counted against.
//
// reauth is a re-authentication (5.7): it also reserves a place against the three failures that end the sessions.
func (s *Service) reservePassword(name, bucket string, passkeyOK, code, reauth bool, set config.SignInSettings) (*accounts.Account, *resv, string) {
	defer s.guard.lock(name)()
	now := s.now()
	a := s.store.Lookup(name)
	in := s.guard.get(name)
	if a == nil {
		return nil, nil, "unknown_account"
	}
	eff := *a
	eff.ConsecutiveFailures += in.pwd
	eff.State = stateForCount(a.State, eff.ConsecutiveFailures, set.NISTCap) // the state the failures in flight lead to
	if passkeyOK && passkeyCount(a, now)+in.pk >= set.PasskeyPathPerHour {
		return a, nil, "passkey_path_limit"
	}
	if reason := s.cannotSignIn(&eff, signInRequest{Code: codeMark(code)}, passkeyOK, bucket, set, now, totpCount(a, now)+in.totp); reason != "" {
		return a, nil, reason
	}
	if reauth && a.ReauthFailures+in.reauth >= MaxReauthFailures {
		return a, nil, "reauth_exhausted"
	}
	r := &resv{g: s.guard, name: name, pwd: true, pk: passkeyOK, reauth: reauth}
	s.guard.add(name, func(f *inflight) {
		f.pwd++
		if passkeyOK {
			f.pk++
		}
		if reauth {
			f.reauth++
		}
	})
	return a, r, ""
}

func codeMark(code bool) string {
	if code {
		return "x"
	}
	return ""
}

// reserveTOTP reserves one wrong-code place of the account's limit before a code is checked. False: the limit is spent (the
// stored count and the codes in flight), so no code is checked. r may be nil (an account that is not signing in: a reset link's proof).
func (s *Service) reserveTOTP(name string, r *resv, set config.SignInSettings) (*resv, bool) {
	defer s.guard.lock(name)()
	a := s.store.Lookup(name)
	if a == nil {
		return r, false
	}
	in := s.guard.get(name)
	if totpCount(a, s.now())+in.totp >= set.TOTPPerDay {
		return r, false
	}
	if r == nil {
		r = &resv{g: s.guard, name: name}
	}
	r.totp = true
	s.guard.add(name, func(f *inflight) { f.totp++ })
	return r, true
}

// reserveProofPassword reserves one wrong-password place of the account's persistent counter (consecutive_failures, bounded by the
// NIST cap) before the current password is checked as the proof of a second-factor reset (5.8). The account is waiting for its
// setup, so there is no state to restrict: the cap is the limit. False: it is spent, and no password is checked.
func (s *Service) reserveProofPassword(name string, set config.SignInSettings) (*resv, bool) {
	defer s.guard.lock(name)()
	a := s.store.Lookup(name)
	if a == nil {
		return nil, false
	}
	in := s.guard.get(name)
	if a.ConsecutiveFailures+in.pwd >= set.NISTCap {
		return nil, false
	}
	r := &resv{g: s.guard, name: name, pwd: true}
	s.guard.add(name, func(f *inflight) { f.pwd++ })
	return r, true
}
