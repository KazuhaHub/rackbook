package accounts

import (
	"encoding/json"
	"path/filepath"
	"sync"

	"github.com/kazuhahub/rackbook/internal/statekey"
)

// unknownMonth holds every month: a pin that could not be read must delete nothing.
const unknownMonth = "0000-00"

// Pin is the retention pin of 4.6. It implements audit.RetentionPin: the audit log never deletes
// the month of the last change of the account store or of secrets.enc, nor a later one. It is
// created before the audit log is opened (retention runs at Open) from the files themselves, and
// the stores keep it current.
type Pin struct {
	mu       sync.Mutex
	accounts string
	secrets  string
	unkAcc   bool // a store file that could not be read: everything is held until it is open
	unkSec   bool
	held     bool
	onHeld   []func()
}

// NewPin reads the audit month of the stores under stateDir. Without a key a store that exists
// cannot be read, so everything is held.
func NewPin(stateDir string, key *statekey.Key) *Pin {
	p := &Pin{}
	for _, f := range []struct {
		path    string
		purpose statekey.Purpose
		set     *string
		unk     *bool
	}{
		{filepath.Join(stateDir, "accounts", "accounts.enc"), statekey.PurposeAccounts, &p.accounts, &p.unkAcc},
		{filepath.Join(stateDir, "secrets.enc"), statekey.PurposeSecrets, &p.secrets, &p.unkSec},
	} {
		m, exists, ok := peekMonth(f.path, key, f.purpose)
		switch {
		case !exists:
		case !ok:
			*f.unk = true
		default:
			*f.set = m
		}
	}
	return p
}

func peekMonth(path string, key *statekey.Key, purpose statekey.Purpose) (month string, exists, ok bool) {
	b, err := readIfExists(path)
	if err != nil {
		return "", true, false
	}
	if b == nil {
		return "", false, false
	}
	if key == nil {
		return "", true, false
	}
	pt, err := statekey.Open(key, purpose, b)
	if err != nil {
		return "", true, false
	}
	var m Meta
	if json.Unmarshal(pt, &m) != nil {
		return "", true, false
	}
	return m.AuditMonth, true, true
}

// Month implements audit.RetentionPin.
func (p *Pin) Month() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unkAcc || p.unkSec {
		return unknownMonth
	}
	switch {
	case p.accounts == "":
		return p.secrets
	case p.secrets == "":
		return p.accounts
	}
	return min(p.accounts, p.secrets)
}

// Held implements audit.RetentionPin: the stores write a checkpoint, which moves the pin on.
// Before the stores exist (retention also runs when the log opens) it is remembered for them.
func (p *Pin) Held() {
	p.mu.Lock()
	fns := append([]func(){}, p.onHeld...)
	if len(fns) == 0 {
		p.held = true
	}
	p.mu.Unlock()
	for _, f := range fns {
		f()
	}
}

// takeHeld says whether retention held a month back before the stores were open.
func (p *Pin) takeHeld() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.held
	p.held = false
	return h
}

func (p *Pin) register(f func()) {
	p.mu.Lock()
	p.onHeld = append(p.onHeld, f)
	p.mu.Unlock()
}

// set updates the month of one store once it is open (and after every commit); the pin is
// known from then on.
func (p *Pin) setAccounts(m Meta) {
	p.mu.Lock()
	p.accounts, p.unkAcc = m.AuditMonth, false
	p.mu.Unlock()
}
func (p *Pin) setSecrets(m Meta) {
	p.mu.Lock()
	p.secrets, p.unkSec = m.AuditMonth, false
	p.mu.Unlock()
}
