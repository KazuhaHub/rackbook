package localauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/KazuhaHub/authcore/passkey"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Passkeys of local accounts (docs/design-local-accounts.md, 5.5): a second factor, with the relying-party ID of
// --base-url and a resident key, so that sign-in can use a discoverable ceremony that reveals nothing about the account.
// The ceremony state is sealed into the token the client carries (seal.go), and the credentials are the account
// store's. Sign counts are not persisted, as for the passkeys of single sign-on before.

const (
	purposeLogin = "rackbook passkey login v1"
	purposeEnrol = "rackbook passkey enrol v1"
)

type passkeyKit struct {
	login, enrol *passkey.Service
	handleKey    []byte
	store        *accounts.Store
}

func newPasskeyKit(base *url.URL, st *accounts.Store, k *statekey.Key, s *sealer, now func() time.Time, replay *replaySet) (*passkeyKit, error) {
	mk := func(purpose string) (*passkey.Service, error) {
		return passkey.New(passkey.Config{
			RPID: base.Hostname(), RPDisplayName: "Rackbook", RPOrigins: []string{base.String()},
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
				UserVerification: protocol.VerificationPreferred,
			},
			UserVerification: protocol.VerificationPreferred,
			Credentials:      &credStore{store: st},
			Sessions:         &sealedSessions{s: s, purpose: purpose, now: now, replay: replay},
			Now:              now,
		})
	}
	login, err := mk(purposeLogin)
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	enrol, err := mk(purposeEnrol)
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	return &passkeyKit{login: login, enrol: enrol, handleKey: k.Sub(statekey.PurposePasskeyHandle), store: st}, nil
}

// userHandle is the WebAuthn user handle of an account: stable for its life, the same for all its credentials,
// and it says nothing about the username.
func (k *passkeyKit) userHandle(username string) []byte {
	m := hmac.New(sha256.New, k.handleKey)
	m.Write([]byte("rackbook passkey user handle\x00" + username))
	return m.Sum(nil)
}

// BeginLogin starts a discoverable ceremony; the returned token goes into the attempt.
func (k *passkeyKit) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return k.login.BeginDiscoverableLogin(ctx)
}

// ErrNoPasskey is the one failure of an assertion: whatever was wrong with it.
var ErrNoPasskey = errors.New("the passkey assertion is not valid")

// VerifyAssertion checks an assertion against the sealed ceremony and returns the account that owns the credential.
//
// resetProof lets an account in reset_pending own the credential: a password-scope reset keeps the factors, and the person
// proves one of them before choosing a new password (5.8). It is for that proof only; a sign-in never passes it.
func (k *passkeyKit) VerifyAssertion(ctx context.Context, token string, assertion json.RawMessage, resetProof bool) (username string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(assertion))
	if err != nil {
		return "", ErrNoPasskey
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := k.login.FinishDiscoverableLogin(ctx, token, req)
	if err != nil || res == nil {
		return "", ErrNoPasskey
	}
	st := k.store.Snapshot()
	for _, n := range st.Names() {
		a := st.Accounts[n]
		if !a.Live() && !(resetProof && a.State == accounts.StateResetPending && a.Pending != nil && a.Pending.Scope == accounts.ScopePassword) {
			continue
		}
		for _, p := range a.Passkeys {
			if bytes.Equal(p.ID, res.Credential.ID) && bytes.Equal(p.UserHandle, res.UserHandle) {
				return n, nil
			}
		}
	}
	return "", ErrNoPasskey
}

// BeginEnrol starts a registration for a new credential of the account. hold binds the ceremony to the setup's hold.
func (k *passkeyKit) BeginEnrol(ctx context.Context, username, display, hold string) (*protocol.CredentialCreation, string, error) {
	ctx = withExtra(ctx, hold)
	return k.enrol.BeginRegistration(ctx, k.userHandle(username), username, display)
}

// FinishEnrol verifies the attestation and returns the credential as the store keeps it. Nothing is saved.
func (k *passkeyKit) FinishEnrol(ctx context.Context, username, hold, token string, attestation json.RawMessage, name string, now time.Time) (*accounts.Passkey, error) {
	ctx = withExtra(ctx, hold)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(attestation))
	if err != nil {
		return nil, ErrNoPasskey
	}
	req.Header.Set("Content-Type", "application/json")
	cred, err := k.enrol.FinishRegistration(ctx, k.userHandle(username), token, req)
	if err != nil || cred == nil {
		return nil, ErrNoPasskey
	}
	if name == "" {
		name = "Passkey"
	}
	return &accounts.Passkey{
		ID: cred.ID, PublicKey: cred.PublicKey, UserHandle: k.userHandle(username), Name: name, Added: now.UTC(),
		BackupEligible: cred.Flags.BackupEligible, AAGUID: base64.RawURLEncoding.EncodeToString(cred.Authenticator.AAGUID),
	}, nil
}

// credStore is the passkey.CredentialStore over the account store. It saves nothing: a new credential is written by the
// setup change, together with the password.
type credStore struct{ store *accounts.Store }

func toStored(p accounts.Passkey) passkey.StoredCredential {
	flags := protocol.FlagUserPresent
	if p.BackupEligible {
		flags |= protocol.FlagBackupEligible
	}
	aaguid, _ := base64.RawURLEncoding.DecodeString(p.AAGUID)
	return passkey.StoredCredential{UserHandle: p.UserHandle, Credential: webauthn.Credential{
		ID: p.ID, PublicKey: p.PublicKey, AttestationType: "none",
		Flags:         webauthn.NewCredentialFlags(flags),
		Authenticator: webauthn.Authenticator{AAGUID: aaguid},
	}}
}

func (c *credStore) FindByID(_ context.Context, id []byte) (passkey.StoredCredential, error) {
	st := c.store.Snapshot()
	for _, n := range st.Names() {
		for _, p := range st.Accounts[n].Passkeys {
			if bytes.Equal(p.ID, id) {
				return toStored(p), nil
			}
		}
	}
	return passkey.StoredCredential{}, passkey.ErrCredentialNotFound
}

func (c *credStore) FindByUserHandle(_ context.Context, handle []byte) ([]passkey.StoredCredential, error) {
	var out []passkey.StoredCredential
	st := c.store.Snapshot()
	for _, n := range st.Names() {
		for _, p := range st.Accounts[n].Passkeys {
			if bytes.Equal(p.UserHandle, handle) {
				out = append(out, toStored(p))
			}
		}
	}
	return out, nil
}

func (c *credStore) Save(context.Context, passkey.StoredCredential) error { return nil }

func (c *credStore) UpdateSignCount(context.Context, []byte, webauthn.Credential, time.Time) error {
	return nil
}
