package accounts

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kazuhahub/rackbook/internal/audit"

	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Pin is the retention pin of 4.6. It implements audit.RetentionPin: the audit log never deletes
// the month of the last change of the account store or of secrets.enc, nor a later one. It is
// created before the audit log is opened (retention runs at Open) from the files themselves, and
// the stores keep it current.
//
// Where the month cannot be read, the pin is conservative instead of unknown: a store file that is
// missing while the log has change events for it, or that exists but cannot be decrypted (no key yet,
// as in `rackbook serve` for now; a wrong key), pins the oldest month that holds a change event of
// that document. The real audit month is never older than that, so nothing the store needs is deleted.
// A document with no change event in the log pins nothing.
type Pin struct {
	mu       sync.Mutex
	accounts string
	secrets  string
	held     [2]bool // retention held a month back before that store was open: it writes its checkpoint when it opens
	onHeld   [2]func()
}

const (
	whoAccounts = 0
	whoSecrets  = 1
)

// NewPin reads the audit month of the stores under stateDir (and, where it cannot, the oldest change
// event of the audit log under stateDir/audit). key may be nil.
func NewPin(stateDir string, key *statekey.Key) *Pin {
	p := &Pin{}
	auditDir := filepath.Join(stateDir, "audit")
	for _, f := range []struct {
		path    string
		purpose statekey.Purpose
		set     *string
		events  map[string]bool
		marker  string
	}{
		{filepath.Join(stateDir, "accounts", "accounts.enc"), statekey.PurposeAccounts, &p.accounts, accountChangeEvents, accountsMarker},
		{filepath.Join(stateDir, "secrets.enc"), statekey.PurposeSecrets, &p.secrets, secretsChangeEvents, secretsMarker},
	} {
		m, exists, ok := peekMonth(f.path, key, f.purpose)
		if exists && ok {
			*f.set = m
			continue
		}
		// missing or unreadable: the log says how far back the document's changes go
		*f.set = oldestChangeMonth(auditDir, f.events, f.marker)
	}
	return p
}

// oldestChangeMonth is the month of the first retained change event of a document, "" for none.
func oldestChangeMonth(auditDir string, events map[string]bool, marker string) string {
	first := ""
	_ = audit.EachEventInDir(auditDir, "", func(ev audit.Event, month string) bool {
		if events[ev.Event] {
			for _, d := range ev.Detail {
				if strings.HasPrefix(d, marker) {
					first = month
					return false
				}
			}
		}
		return true
	})
	return first
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
	switch {
	case p.accounts == "":
		return p.secrets
	case p.secrets == "":
		return p.accounts
	}
	return min(p.accounts, p.secrets)
}

// Held implements audit.RetentionPin: each store writes its own checkpoint, which moves its pin on. A
// store that is not open yet remembers that retention held a month back, and writes its checkpoint when it opens.
func (p *Pin) Held() {
	p.mu.Lock()
	var fns []func()
	for i := range p.onHeld {
		if p.onHeld[i] != nil {
			fns = append(fns, p.onHeld[i])
		} else {
			p.held[i] = true
		}
	}
	p.mu.Unlock()
	for _, f := range fns {
		f()
	}
}

// takeHeld says whether retention held a month back before store who was open.
func (p *Pin) takeHeld(who int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.held[who]
	p.held[who] = false
	return h
}

func (p *Pin) register(who int, f func()) {
	p.mu.Lock()
	p.onHeld[who] = f
	p.mu.Unlock()
}

func (p *Pin) setAccounts(m Meta) { p.mu.Lock(); p.accounts = m.AuditMonth; p.mu.Unlock() }
func (p *Pin) setSecrets(m Meta)  { p.mu.Lock(); p.secrets = m.AuditMonth; p.mu.Unlock() }
