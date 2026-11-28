package accounts

import (
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

// RFC 6238, appendix B, HMAC-SHA1, seed "12345678901234567890": the 8-digit values; the 6-digit
// code is the last six digits.
var rfc6238 = []struct {
	unix int64
	code string
}{
	{59, "94287082"},
	{1111111109, "07081804"},
	{1111111111, "14050471"},
	{1234567890, "89005924"},
	{2000000000, "69279037"},
	{20000000000, "65353130"},
}

var rfcSecret = []byte("12345678901234567890")

func TestTOTPRFC6238Vectors(t *testing.T) {
	for _, v := range rfc6238 {
		step := v.unix / 30
		if got := hotp(rfcSecret, uint64(step), 8); got != v.code {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.code)
		}
		six := v.code[2:]
		if got := TOTPCode(rfcSecret, step); got != six {
			t.Errorf("T=%d: 6 digits %s, want %s", v.unix, got, six)
		}
		if _, err := VerifyTOTP(rfcSecret, six, time.Unix(v.unix, 0), 0); err != nil {
			t.Errorf("T=%d: %v", v.unix, err)
		}
	}
}

func TestTOTPWindowIsOneStepEitherSide(t *testing.T) {
	now := time.Unix(1111111111, 0)
	cur := TOTPStep(now)
	for off, ok := range map[int64]bool{-3: false, -2: false, -1: true, 0: true, 1: true, 2: false, 3: false} {
		step, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur+off), now, 0)
		if ok && (err != nil || step != cur+off) {
			t.Errorf("offset %d: step %d err %v", off, step, err)
		}
		if !ok && !errors.Is(err, ErrBadCode) {
			t.Errorf("offset %d accepted: %v", off, err)
		}
	}
	// the edge of a period: 29 seconds into a step still accepts the step before, 1 s into the next too
	if _, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur-1), time.Unix(cur*30+29, 0), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur-2), time.Unix(cur*30, 0), 0); err == nil {
		t.Fatal("two steps back is outside the window")
	}
}

func TestTOTPRefusesAStepAtOrBeforeTheLastOne(t *testing.T) {
	now := time.Unix(1111111111, 0)
	cur := TOTPStep(now)
	step, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur), now, 0)
	if err != nil {
		t.Fatal(err)
	}
	// replay of the same code
	if _, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur), now, step); !errors.Is(err, ErrBadCode) {
		t.Fatalf("replay: %v", err)
	}
	// an earlier step is refused too, although it is inside the window
	if _, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur-1), now, step); !errors.Is(err, ErrBadCode) {
		t.Fatalf("earlier step: %v", err)
	}
	// a later step in the window is fine, once
	next, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur+1), now, step)
	if err != nil || next != cur+1 {
		t.Fatalf("later step: %d %v", next, err)
	}
	if _, err := VerifyTOTP(rfcSecret, TOTPCode(rfcSecret, cur+1), now, next); err == nil {
		t.Fatal("the later step replayed")
	}
}

func TestTOTPMalformedCodes(t *testing.T) {
	now := time.Unix(59, 0)
	good := TOTPCode(rfcSecret, TOTPStep(now))
	for _, c := range []string{"", "1", "12345", good + "0", " " + good, good + " ", "12345a", "+12345", "１２３４５６", strings.Repeat("9", 100)} {
		if _, err := VerifyTOTP(rfcSecret, c, now, 0); !errors.Is(err, ErrBadCode) {
			t.Errorf("%q: %v", c, err)
		}
	}
	if _, err := VerifyTOTP(rfcSecret, good, now, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTOTP(nil, good, now, 0); err == nil {
		t.Fatal("no secret")
	}
}

func TestTOTPEnrolment(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil || len(secret) != 20 {
		t.Fatalf("secret: %d bytes, %v", len(secret), err)
	}
	other, _ := NewTOTPSecret()
	if string(secret) == string(other) {
		t.Fatal("secrets repeat")
	}
	now := time.Unix(1700000000, 0)
	if _, err := NewTOTPFactor(secret, "000000", now); err == nil && TOTPCode(secret, TOTPStep(now)) != "000000" && TOTPCode(secret, TOTPStep(now)-1) != "000000" && TOTPCode(secret, TOTPStep(now)+1) != "000000" {
		t.Fatal("a wrong code confirmed the enrolment")
	}
	code := TOTPCode(secret, TOTPStep(now))
	f, err := NewTOTPFactor(secret, code, now)
	if err != nil || f.LastStep != TOTPStep(now) {
		t.Fatalf("factor = %+v, %v", f, err)
	}
	// the code that confirmed the factor cannot sign in
	if _, err := VerifyTOTP(f.Secret, code, now, f.LastStep); err == nil {
		t.Fatal("the confirming code was usable at sign-in")
	}
	if _, err := NewTOTPFactor(secret[:10], code, now); err == nil {
		t.Fatal("a short secret was accepted")
	}
	u, err := url.Parse(TOTPURI("Rackbook (example)", "alice", secret))
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("uri = %v %v", u, err)
	}
	q := u.Query()
	if q.Get("secret") != TOTPBase32(secret) || q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("algorithm") != "SHA1" || q.Get("issuer") != "Rackbook (example)" {
		t.Fatalf("query = %v", q)
	}
	if strings.ContainsAny(TOTPBase32(secret), "=\n ") {
		t.Fatal("base32 for typing must have no padding")
	}
}

func TestUseTOTPRefusesReplayAcrossRequestsAndRestarts(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	secret, _ := NewTOTPSecret()
	now := e.clk.Now()
	if _, err := s.Change(audit.Event{Event: "factor_added", Identity: "local:alice"}, func(st *State) error {
		f, err := NewTOTPFactor(secret, TOTPCode(secret, TOTPStep(now.Add(-time.Hour))+0), now.Add(-time.Hour))
		if err != nil {
			return err
		}
		st.Accounts["alice"].TOTP = f
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	code := TOTPCode(secret, TOTPStep(now))
	ev := audit.Event{Event: "login", Identity: "local:alice"}
	if err := s.UseTOTP("alice", code, now, &ev); err != nil {
		t.Fatal(err)
	}
	if err := s.UseTOTP("alice", code, now, nil); !errors.Is(err, ErrBadCode) {
		t.Fatalf("replay: %v", err)
	}
	// the step is on disk: a restart does not reopen the window
	e.restart()
	s = e.mustOpen()
	if err := s.UseTOTP("alice", code, now, nil); !errors.Is(err, ErrBadCode) {
		t.Fatalf("replay after restart: %v", err)
	}
	for _, name := range []string{"nobody", "alice"} {
		if err := s.UseTOTP(name, "000000", now, nil); !errors.Is(err, ErrBadCode) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := s.UseTOTP("alice", TOTPCode(secret, TOTPStep(now)+1), now, nil); err != nil {
		t.Fatalf("the next step is fine: %v", err)
	}
}

func TestUseTOTPConcurrentRequestsWithOneCodeSucceedOnce(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	secret, _ := NewTOTPSecret()
	now := e.clk.Now()
	s.Change(audit.Event{Event: "factor_added"}, func(st *State) error {
		st.Accounts["alice"].TOTP = &TOTP{Secret: secret, Added: now}
		return nil
	})
	code := TOTPCode(secret, TOTPStep(now))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.UseTOTP("alice", code, now, nil) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d of 16 concurrent uses of one code succeeded", ok)
	}
}
