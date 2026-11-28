package accounts

import (
	"crypto/rand"
	"encoding/hex"
)

// RenewSessions makes a new 128-bit session id and 256-bit session secret. Renewing them
// ends every session of the account (6).
func (a *Account) RenewSessions() error {
	sid := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		return err
	}
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	a.SID, a.SessionSecret = hex.EncodeToString(sid), secret
	return nil
}

// newChangeID is a fresh random change id.
func newChangeID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("accounts: " + err.Error())
	}
	return hex.EncodeToString(b)
}
