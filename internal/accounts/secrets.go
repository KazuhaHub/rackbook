package accounts

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Secret names (9.3).
const (
	SecretCaptcha    = "captcha_secret"
	SecretOIDCClient = "oidc_client_secret"
)

// MaxSecretLen bounds one stored secret.
const MaxSecretLen = 4096

// Secret is a stored value. It never prints itself, in a log line or an error.
type Secret string

func (Secret) String() string   { return "[secret]" }
func (Secret) GoString() string { return "[secret]" }

// SecretEntry is one entry of secrets.enc. The OIDC client secret is bound to the (issuer,
// client id) it was entered for (9.3).
type SecretEntry struct {
	Value    Secret `json:"value"`
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// SecretsState is the decrypted content of secrets.enc.
type SecretsState struct {
	V int `json:"v"`
	Meta
	Secrets map[string]*SecretEntry `json:"secrets"`
}

func (s *SecretsState) meta() *Meta { return &s.Meta }

func newSecretsState() *SecretsState { return &SecretsState{V: 1, Secrets: map[string]*SecretEntry{}} }

// SecretsStatus is all the API ever says about the secrets: whether each is set.
type SecretsStatus struct {
	HasCaptchaSecret    bool `json:"has_captcha_secret"`
	HasOIDCClientSecret bool `json:"has_oidc_client_secret"`
}

// Errors of Apply.
var (
	ErrUnknownSecret      = errors.New("unknown secret name")
	ErrSecretConflict     = errors.New("a secret cannot be set and cleared in the same save")
	ErrSecretTooLong      = errors.New("the secret is empty or too long")
	ErrOIDCBindingMissing = errors.New("the OIDC client secret needs the issuer and the client id it is for")
	// ErrOIDCSecretRequired: the issuer or client id changed, which clears the stored secret, so the same save must carry a new one.
	ErrOIDCSecretRequired = errors.New("the issuer or client id changed: enter the client secret again in the same save")
)

// Secrets is secrets.enc: write-only secrets, encrypted under the state key (9.3).
type Secrets struct {
	o   Options
	eng *engine[*SecretsState]
}

// OpenSecrets runs the same start sequence as Open on secrets.enc (4.3: "written the same way, with
// its own settings_secret_* events") and returns the store or a *StartError.
func OpenSecrets(o Options) (*Secrets, error) {
	s, err := newSecrets(o)
	if err != nil {
		return nil, err
	}
	if se := s.eng.start(); se != nil {
		return nil, se
	}
	if o.Pin != nil {
		o.Pin.register(whoSecrets, func() {
			if err := s.Checkpoint(); err != nil {
				s.eng.c.Logger.Error("secrets store: the checkpoint failed; retention stays held back", "err", err)
			}
		})
		if o.Pin.takeHeld(whoSecrets) {
			if err := s.Checkpoint(); err != nil {
				return nil, fmt.Errorf("secrets store: checkpoint: %w", err)
			}
		}
	}
	return s, nil
}

func newSecrets(o Options) (*Secrets, error) {
	if o.Key == nil || o.Log == nil {
		return nil, errors.New("secrets need the state key and the audit log")
	}
	if err := EnsureDir(o.StateDir); err != nil {
		return nil, err
	}
	s := &Secrets{o: o}
	s.eng = newEngine(engineConfig[*SecretsState]{
		Dir: o.StateDir, Base: secretsFile, Purpose: statekey.PurposeSecrets, Marker: secretsMarker, Events: secretsChangeEvents,
		Key: o.Key, Log: o.Log, Now: o.Now, Logger: o.Logger, Hook: o.hook,
		New: newSecretsState,
		OnSet: func(m Meta) {
			if o.Pin != nil {
				o.Pin.setSecrets(m)
			}
		},
	})
	return s, nil
}

// Status says which secrets are set. It is what the API shows.
func (s *Secrets) Status() SecretsStatus {
	d := s.eng.snapshot()
	return SecretsStatus{HasCaptchaSecret: d.Secrets[SecretCaptcha] != nil, HasOIDCClientSecret: d.Secrets[SecretOIDCClient] != nil}
}

// CaptchaSecret is the stored CAPTCHA secret, for the server's own use only.
func (s *Secrets) CaptchaSecret() (string, bool) {
	e := s.eng.snapshot().Secrets[SecretCaptcha]
	if e == nil {
		return "", false
	}
	return string(e.Value), true
}

// OIDCClientSecret is the stored client secret, and only for the (issuer, client id) it was
// entered for: for any other pair it is not returned, so it is never sent to another issuer.
func (s *Secrets) OIDCClientSecret(issuer, clientID string) (string, bool) {
	e := s.eng.snapshot().Secrets[SecretOIDCClient]
	if e == nil || issuer == "" || clientID == "" || e.Issuer != issuer || e.ClientID != clientID {
		return "", false
	}
	return string(e.Value), true
}

// OIDCBinding is the (issuer, client id) the stored client secret belongs to.
func (s *Secrets) OIDCBinding() (issuer, clientID string, ok bool) {
	e := s.eng.snapshot().Secrets[SecretOIDCClient]
	if e == nil {
		return "", "", false
	}
	return e.Issuer, e.ClientID, true
}

// Update is one save of the secret fields. A blank value keeps what is stored; clearing takes
// the explicit Clear list ("empty means keep", 9.3).
type Update struct {
	Set   map[string]string
	Clear []string
	// Issuer and ClientID are the OIDC settings in force with this save; the client secret is bound to them.
	Issuer, ClientID string
}

// Apply stores and clears secrets, one audited change per name. actor supplies the identity of the event
// (identity, name, method, addr); its Event and Detail are replaced. A secret value is never in an event.
// Nothing is changed when the update is refused as a whole.
func (s *Secrets) Apply(u Update, actor audit.Event) error {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	known := func(n string) bool { return n == SecretCaptcha || n == SecretOIDCClient }
	for n, v := range u.Set {
		switch {
		case !known(n):
			return fmt.Errorf("%w: %q", ErrUnknownSecret, n)
		case len(v) > MaxSecretLen:
			return ErrSecretTooLong
		case v != "" && slices.Contains(u.Clear, n):
			return ErrSecretConflict
		case v != "" && n == SecretOIDCClient && (u.Issuer == "" || u.ClientID == ""):
			return ErrOIDCBindingMissing
		}
	}
	for _, n := range u.Clear {
		if !known(n) {
			return fmt.Errorf("%w: %q", ErrUnknownSecret, n)
		}
	}
	cur := s.eng.cur
	if e := cur.Secrets[SecretOIDCClient]; e != nil && u.Issuer != "" && u.ClientID != "" && (e.Issuer != u.Issuer || e.ClientID != u.ClientID) &&
		u.Set[SecretOIDCClient] == "" && !slices.Contains(u.Clear, SecretOIDCClient) {
		return ErrOIDCSecretRequired
	}
	for _, n := range sortedKeys(u.Set) {
		v := u.Set[n]
		if v == "" {
			continue // empty means keep
		}
		val, issuer, client := v, u.Issuer, u.ClientID
		ev := actorEvent(actor, "settings_secret_set", n, "")
		if _, err := s.eng.commit(ev, func(d *SecretsState) error {
			e := &SecretEntry{Value: Secret(val)}
			if n == SecretOIDCClient {
				e.Issuer, e.ClientID = issuer, client
			}
			d.Secrets[n] = e
			return nil
		}, nil, nil); err != nil {
			return err
		}
	}
	for _, n := range u.Clear {
		if s.eng.cur.Secrets[n] == nil {
			continue
		}
		name := n
		if _, err := s.eng.commit(actorEvent(actor, "settings_secret_cleared", name, ""), func(d *SecretsState) error {
			delete(d.Secrets, name)
			return nil
		}, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// ClearForBinding clears the stored OIDC client secret when the issuer or client id it was entered
// for no longer match (the console changed them), recorded with because: binding.
func (s *Secrets) ClearForBinding(issuer, clientID string, actor audit.Event) (bool, error) {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	e := s.eng.cur.Secrets[SecretOIDCClient]
	if e == nil || (e.Issuer == issuer && e.ClientID == clientID) {
		return false, nil
	}
	_, err := s.eng.commit(actorEvent(actor, "settings_secret_cleared", SecretOIDCClient, "binding"), func(d *SecretsState) error {
		delete(d.Secrets, SecretOIDCClient)
		return nil
	}, nil, nil)
	return err == nil, err
}

func actorEvent(actor audit.Event, name, secret, because string) audit.Event {
	return audit.Event{
		Event: name, Identity: actor.Identity, Name: actor.Name, Method: actor.Method, Addr: actor.Addr,
		Cause: because, Detail: append(slices.Clone(actor.Detail), "name:"+secret),
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Checkpoint writes secrets.enc as a change with an account_store_checkpoint event (4.6).
func (s *Secrets) Checkpoint() error {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	if s.eng.cur.meta().AuditSeq == 0 {
		return nil
	}
	_, err := s.eng.commit(audit.Event{Event: "account_store_checkpoint", Detail: []string{"store:secrets"}}, nil, nil, nil)
	return err
}

// Evidence lists the evidence files of secrets.enc.
func (s *Secrets) Evidence() []string { return s.eng.evidence() }

// SecretsPath is where secrets.enc lives under stateDir.
func SecretsPath(stateDir string) string { return filepath.Join(stateDir, secretsFile) }
