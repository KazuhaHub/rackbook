package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

func init() {
	// Tests run many hashes: cheap parameters. TestArgon2idConstants checks the real ones.
	current = argonParams{m: 64, t: 1, p: 1}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// env is a state dir with an audit log and a generated key. restart() is a new process: the log
// is closed and opened again, the stores must be opened again by the test.
type env struct {
	t     *testing.T
	dir   string
	key   *statekey.Key
	clk   *clock
	log   *audit.Log
	pin   *Pin
	retMo int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	k, err := statekey.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: t.TempDir(), key: k, clk: &clock{t: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}}
	e.startLog()
	return e
}

func (e *env) auditDir() string { return filepath.Join(e.dir, "audit") }

func (e *env) startLog() {
	e.t.Helper()
	e.pin = NewPin(e.dir, e.key)
	l, err := audit.Open(e.auditDir(), audit.Options{Now: e.clk.Now, RetentionMonths: e.retMo, Pin: e.pin, Addr: audit.AddrFull})
	if err != nil {
		e.t.Fatal(err)
	}
	e.log = l
}

func (e *env) restart() {
	e.t.Helper()
	e.log.Close()
	e.startLog()
}

func (e *env) opts() Options {
	return Options{StateDir: e.dir, Key: e.key, Log: e.log, Pin: e.pin, Now: e.clk.Now}
}

func (e *env) open() (*Store, error) { return Open(e.opts()) }

func (e *env) mustOpen() *Store {
	e.t.Helper()
	s, err := e.open()
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) openSecrets() (*Secrets, error) { return OpenSecrets(e.opts()) }

func (e *env) accountsPath(name string) string { return filepath.Join(e.dir, "accounts", name) }

// crashing opens a store whose writer stops at step as a crash would.
func (e *env) crashing(step string) *Store {
	e.t.Helper()
	o := e.opts()
	o.hook = func(s string) error {
		if s == step {
			return errCrash
		}
		return nil
	}
	s, err := Open(o)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) invite(s *Store, name string) (int64, error) {
	e.t.Helper()
	return s.Change(audit.Event{Event: "account_invited", Identity: "local:admin", Target: "local:" + name}, func(st *State) error {
		a, err := NewAccount(name, strings.ToUpper(name[:1])+name[1:], "local:admin", e.clk.Now())
		if err != nil {
			return err
		}
		st.Accounts[name] = a
		return nil
	})
}

func (e *env) mustInvite(s *Store, name string) {
	e.t.Helper()
	if _, err := e.invite(s, name); err != nil {
		e.t.Fatal(err)
	}
}

// events returns every event of the log.
func (e *env) events() []audit.Event {
	e.t.Helper()
	var out []audit.Event
	if err := e.log.EachEvent("", func(ev audit.Event, _ string) bool { out = append(out, ev); return true }); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) eventsNamed(name string) []audit.Event {
	var out []audit.Event
	for _, ev := range e.events() {
		if ev.Event == name {
			out = append(out, ev)
		}
	}
	return out
}

func (e *env) verifyChain() {
	e.t.Helper()
	rep, err := audit.Verify(e.auditDir())
	if err != nil || len(rep.Problems) != 0 {
		e.t.Fatalf("the audit chain does not verify: %v %v", rep.Problems, err)
	}
}

func startCode(t *testing.T, err error) Code {
	t.Helper()
	var se *StartError
	if !errors.As(err, &se) {
		t.Fatalf("want a *StartError, got %v", err)
	}
	return se.Code
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

func hasChange(ev audit.Event) bool {
	for _, d := range ev.Detail {
		if strings.HasPrefix(d, "change:") {
			return true
		}
	}
	return false
}

func mustNewKey(t *testing.T) *statekey.Key {
	t.Helper()
	k, err := statekey.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
