package accounts

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func withParams(t *testing.T, p argonParams) {
	t.Helper()
	old := current
	current = p
	t.Cleanup(func() { current = old })
}

func TestArgon2idConstants(t *testing.T) {
	withParams(t, argonParams{m: argonMemoryKiB, t: argonTime, p: argonThreads})
	h, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash = %s", h[:40])
	}
	p, err := parsePHC(h)
	if err != nil || len(p.salt) != 16 || len(p.sum) != 32 {
		t.Fatalf("salt %d tag %d err %v", len(p.salt), len(p.sum), err)
	}
	if NeedsRehash(h) {
		t.Fatal("a fresh hash needs no rehash")
	}
	if !verifyPassword("correct horse battery staple", h) || verifyPassword("correct horse battery stapl", h) {
		t.Fatal("verify")
	}
	h2, _ := hashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("two hashes of one password are equal: the salt is not random")
	}
}

func TestVerifyIsNormalisedAndExact(t *testing.T) {
	h, _ := hashPassword("ｐａｓｓｗｏｒｄ１２３４５６") // full-width, NFKC-folds to ASCII
	if !verifyPassword("password123456", h) {
		t.Fatal("NFKC: the full-width and ASCII forms are one password")
	}
	if verifyPassword("Password123456", h) || verifyPassword("password123456 ", h) || verifyPassword("", h) {
		t.Fatal("case and spaces count")
	}
	// the tag is compared whole: a flipped first or last bit, or a shortened tag, fails
	p, _ := parsePHC(h)
	for _, i := range []int{0, len(p.sum) - 1} {
		bad := append([]byte(nil), p.sum...)
		bad[i] ^= 1
		if verifyPassword("password123456", encodePHC(p.argonParams, p.salt, bad)) {
			t.Fatalf("a changed tag byte %d verified", i)
		}
	}
	if verifyPassword("password123456", encodePHC(p.argonParams, p.salt, p.sum[:16])) {
		t.Fatal("a truncated tag verified")
	}
}

func TestMalformedAndHostileHashesNeverVerify(t *testing.T) {
	good, _ := hashPassword("x")
	for _, bad := range []string{
		"", "plain", "$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=18$m=64,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=64,t=1,p=0$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=999999999,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", // would exhaust memory
		"$argon2id$v=19$m=64,t=4000000000,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=64,t=1,p=1$A$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAA$A",
		"$argon2id$v=19$m=64,t=1,p=1$!!$!!",
		good + "$extra", good[:len(good)-1],
	} {
		if verifyPassword("x", bad) {
			t.Errorf("%q verified", bad)
		}
		if bad != good && !NeedsRehash(bad) {
			t.Errorf("%q needs no rehash", bad)
		}
	}
}

func TestRaisedParametersRehashAtNextSignIn(t *testing.T) {
	withParams(t, argonParams{m: 64, t: 1, p: 1})
	h := NewHasher()
	old, err := h.Hash(context.Background(), ClassNormal, "a long passphrase here")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, err := h.Verify(context.Background(), ClassNormal, "a long passphrase here", old); !ok || rehash || err != nil {
		t.Fatalf("same parameters: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	current = argonParams{m: 128, t: 2, p: 1} // the constants were raised
	ok, rehash, err := h.Verify(context.Background(), ClassNormal, "a long passphrase here", old)
	if !ok || !rehash || err != nil {
		t.Fatalf("raised parameters: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, rehash, _ := h.Verify(context.Background(), ClassNormal, "wrong passphrase!!", old); ok || rehash {
		t.Fatal("a wrong password must not ask for a rehash")
	}
	nu, _ := h.Hash(context.Background(), ClassNormal, "a long passphrase here")
	if p, _ := parsePHC(nu); p.m != 128 || p.t != 2 {
		t.Fatalf("new hash parameters %+v", p.argonParams)
	}
	if !verifyPassword("a long passphrase here", old) {
		t.Fatal("the stored parameters, not the constants, are used to verify")
	}
}

func TestSlots(t *testing.T) {
	ctx := context.Background()
	s := NewSlots(3, 40*time.Millisecond) // two general slots and one reserved
	r1, err := s.acquire(ctx, ClassNormal)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.acquire(ctx, ClassNormal)
	if err != nil {
		t.Fatal(err)
	}
	// the general slots are full: a normal attempt waits its queue and gets busy, although the reserved slot is free
	start := time.Now()
	if _, err := s.acquire(ctx, ClassNormal); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) < 30*time.Millisecond {
		t.Fatal("busy came before the queue time ran out")
	}
	// the reserved slot takes re-authentication and known networks
	rr, err := s.acquire(ctx, ClassPriority)
	if err != nil {
		t.Fatalf("the reserved slot is not available: %v", err)
	}
	if _, err := s.acquire(ctx, ClassPriority); !errors.Is(err, ErrBusy) {
		t.Fatalf("all three are in use: %v", err)
	}
	// a waiting attempt gets a slot as soon as one is released
	got := make(chan error, 1)
	go func() {
		rel, err := s.acquire(context.Background(), ClassNormal)
		got <- err
		if rel != nil {
			rel()
		}
	}()
	time.Sleep(5 * time.Millisecond)
	r1()
	if err := <-got; err != nil {
		t.Fatalf("waiter: %v", err)
	}
	r2()
	rr()
	// a cancelled caller stops waiting
	cctx, cancel := context.WithCancel(ctx)
	f1, _ := s.acquire(ctx, ClassNormal)
	f2, _ := s.acquire(ctx, ClassNormal)
	s.queue = time.Minute
	cancel()
	if _, err := s.acquire(cctx, ClassNormal); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	f1()
	f2()
}

func TestSlotsBoundTheNumberOfHashesInFlight(t *testing.T) {
	withParams(t, argonParams{m: 1024, t: 1, p: 1})
	h := NewHasherWith(NewSlots(3, 5*time.Second))
	var mu sync.Mutex
	inflight, peak := 0, 0
	probe := func() {
		mu.Lock()
		inflight++
		peak = max(peak, inflight)
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := h.slots.acquire(context.Background(), ClassPriority)
			if err != nil {
				t.Error(err)
				return
			}
			defer rel()
			probe()
		}()
	}
	wg.Wait()
	if peak > 3 {
		t.Fatalf("%d hashes ran at once, the slots allow 3", peak)
	}
	// and the public calls go through the slots
	if err := h.Dummy(context.Background(), ClassNormal, "x"); err != nil {
		t.Fatal(err)
	}
	if hash, err := h.Hash(context.Background(), ClassPriority, "a b c d e f g h i j k"); err != nil || hash == "" {
		t.Fatal(err)
	}
}

func TestPasswordRules(t *testing.T) {
	rules := PasswordRules{Username: "alice", Host: "rackbook.example.com"}
	code := func(pw string, r PasswordRules) string {
		err := CheckPassword(pw, r)
		var pe *PasswordError
		if errors.As(err, &pe) {
			return pe.Code
		}
		if err != nil {
			return "error: " + err.Error()
		}
		return ""
	}
	long := func(n int) string { return strings.Repeat("the quick brown fox jumps over 13 lazy dogs. ", 5)[:n] }
	for _, c := range []struct {
		name string
		pw   string
		r    PasswordRules
		want string
	}{
		{"eleven characters", "elevenchars", rules, PwTooShort},
		{"twelve characters", "twelve chars", rules, ""},
		{"no composition rules: lower case words only", "correcthorsebatterystaple", rules, ""},
		{"no composition rules: no digit, no capital, no symbol", "just some plain words", rules, ""},
		{"characters, not bytes", strings.Repeat("é", 12), PasswordRules{}, PwCommon}, // 12 characters, but one unit repeated
		{"characters, not bytes (varied)", "éàüöçñßøåæœž", PasswordRules{}, ""},
		{"128 characters", strings.Repeat("xk2q", 32), PasswordRules{}, PwCommon}, // long enough, but a repeated unit
		{"128 varied characters", long(128), PasswordRules{}, ""},
		{"129 characters", long(129), PasswordRules{}, PwTooLong},
		{"NFKC: eleven full-width characters are eleven", "ｐａｓｓｗｏｒｄ１２３", PasswordRules{}, PwTooShort},
		{"NFKC: a ligature unfolds to two characters", "ﬁﬁﬁﬁﬁﬁ", PasswordRules{}, PwCommon}, // 12 characters after folding, one unit repeated
		{"common, any case", "PassWord123456", PasswordRules{}, PwCommon},
		{"common: a keyboard walk", "1q2w3e4r5t6y", PasswordRules{}, PwCommon},
		{"common: full-width form folds first", "ｐａｓｓｗｏｒｄ１２３４５６", PasswordRules{}, PwCommon},
		{"one character repeated", "aaaaaaaaaaaa", PasswordRules{}, PwCommon},
		{"a short unit repeated", "xyzxyzxyzxyz", PasswordRules{}, PwCommon},
		{"contains the username", "my-alice-is-here-1", rules, PwContainsUsername},
		{"contains the username, any case", "MY-ALICE-IS-HERE-1", rules, PwContainsUsername},
		{"a short username is not looked for", "xx-has-an-a-in-it-1", PasswordRules{Username: "a"}, ""},
		{"contains the host", "log in at rackbook.example.com", rules, PwContainsHost},
		{"contains the host from a URL with a port", "rackbook.example.com is the one", PasswordRules{Host: "https://rackbook.example.com:8443/x"}, PwContainsHost},
		{"min 12 is the floor", "twelve chars", PasswordRules{MinLen: 12}, ""},
		{"min 20 asks for 20", "twelve chars here", PasswordRules{MinLen: 20}, PwTooShort},
		{"min 64", long(64), PasswordRules{MinLen: 64}, ""},
		{"min 64 refuses 63", long(63), PasswordRules{MinLen: 64}, PwTooShort},
		{"a setting below 12 is refused", "twelve chars", PasswordRules{MinLen: 8}, "error: password_min_length must be 12 to 64"},
		{"a setting above 64 is refused", "twelve chars", PasswordRules{MinLen: 65}, "error: password_min_length must be 12 to 64"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := code(c.pw, c.r)
			if got != c.want {
				t.Fatalf("code = %q, want %q", got, c.want)
			}
		})
	}
	if err := CheckPassword("short", rules); err == nil || !strings.Contains(err.Error(), "at least 12 characters") {
		t.Fatalf("message: %v", err)
	}
}

func TestCommonListShape(t *testing.T) {
	set := common()
	if len(set) < 200 {
		t.Fatalf("the embedded list has %d entries", len(set))
	}
	for p := range set {
		if p != fold(p) {
			t.Fatalf("entry %q is not folded", p)
		}
	}
	if !set["123456789012"] || !set["qwertyuiop12"] {
		t.Fatal("expected entries are missing")
	}
}

func TestPasswordsAreNotRecordedByTheTestHelpers(t *testing.T) {
	// the PHC string carries no part of the password
	h, _ := hashPassword("a long unusual passphrase")
	if strings.Contains(h, "passphrase") || strings.Contains(h, base64.RawStdEncoding.EncodeToString([]byte("passphrase"))) {
		t.Fatal("the hash shows the password")
	}
}
