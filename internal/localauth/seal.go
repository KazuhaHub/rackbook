package localauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Sealed tokens (docs/design-local-accounts.md, 8.7): the state an unauthenticated caller can mint at no cost is not
// kept by the server. It is sealed into a token that the client carries back: an attempt carries the passkey
// challenge, a TOTP enrolment the new secret. The tokens are sealed with the attempts subkey. (Built with
// XChaCha20-Poly1305 and a random 192-bit nonce instead of AES-256-GCM, for the reason given in piece 2.)
type sealer struct {
	key [32]byte
}

func newSealer(k *statekey.Key) *sealer {
	s := &sealer{}
	copy(s.key[:], k.Sub(statekey.PurposeAttempts))
	return s
}

var errBadToken = errors.New("the token is not valid")

// seal returns base64url(nonce || ciphertext) of v, bound to purpose (which is authenticated, not carried).
func (s *sealer) seal(purpose string, v any) (string, error) {
	pt, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(s.key[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(pt)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, pt, []byte(purpose))), nil
}

// open decrypts a token into v. A token of another purpose, a changed one and garbage all give errBadToken.
func (s *sealer) open(purpose, token string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(token) > 16<<10 {
		return errBadToken
	}
	aead, err := chacha20poly1305.NewX(s.key[:])
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return errBadToken
	}
	pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(purpose))
	if err != nil {
		return errBadToken
	}
	if json.Unmarshal(pt, v) != nil {
		return errBadToken
	}
	return nil
}

// ---- the replay set (8.7): each sealed ceremony is used once. Entries are kept until their token expires.

const (
	replayCapacity  = 20_000
	replayPerBucket = 20
)

type replaySet struct {
	mu     sync.Mutex
	now    func() time.Time
	used   map[string]time.Time // nonce -> expiry
	perBkt map[string]int
	owner  map[string]string
}

func newReplaySet(now func() time.Time) *replaySet {
	return &replaySet{now: now, used: map[string]time.Time{}, perBkt: map[string]int{}, owner: map[string]string{}}
}

// Use records the nonce. It returns false when the nonce was used before, or when the set has no room for this
// bucket (nothing is evicted: a full bucket must not push out another's entries).
func (r *replaySet) Use(nonce, bucket string, expires time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if len(r.used) >= replayCapacity || r.perBkt[bucket] >= replayPerBucket {
		r.purge(now)
	}
	if _, dup := r.used[nonce]; dup {
		return false
	}
	if len(r.used) >= replayCapacity || r.perBkt[bucket] >= replayPerBucket {
		return false
	}
	r.used[nonce], r.owner[nonce] = expires, bucket
	r.perBkt[bucket]++
	return true
}

func (r *replaySet) purge(now time.Time) {
	for n, exp := range r.used {
		if !exp.After(now) {
			b := r.owner[n]
			delete(r.used, n)
			delete(r.owner, n)
			if r.perBkt[b]--; r.perBkt[b] <= 0 {
				delete(r.perBkt, b)
			}
		}
	}
}

// ---- a passkey.SessionStore that keeps nothing: the ceremony's session data is the token

type ctxKey int

const ctxBucket ctxKey = 1

func withBucket(ctx context.Context, bucket string) context.Context {
	return context.WithValue(ctx, ctxBucket, bucket)
}

func bucketOf(ctx context.Context) string { s, _ := ctx.Value(ctxBucket).(string); return s }

const ceremonyTTL = 5 * time.Minute

type ceremonyToken struct {
	Nonce   string                `json:"n"`
	Bucket  string                `json:"b"`
	Expires int64                 `json:"e"`
	Data    *webauthn.SessionData `json:"d"`
	// Extra carries what the caller needs back when the ceremony is finished (the hold of a setup).
	Extra string `json:"x,omitempty"`
}

type sealedSessions struct {
	s       *sealer
	purpose string
	now     func() time.Time
	replay  *replaySet
}

func (ss *sealedSessions) Put(ctx context.Context, data *webauthn.SessionData) (string, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	t := ceremonyToken{Nonce: base64.RawURLEncoding.EncodeToString(n), Bucket: bucketOf(ctx), Expires: ss.now().Add(ceremonyTTL).Unix(), Data: data, Extra: extraOf(ctx)}
	return ss.s.seal(ss.purpose, t)
}

// Take opens the token and uses its nonce. It is single use whatever the outcome of the ceremony.
func (ss *sealedSessions) Take(ctx context.Context, id string) (*webauthn.SessionData, bool) {
	var t ceremonyToken
	if ss.s.open(ss.purpose, id, &t) != nil || t.Data == nil {
		return nil, false
	}
	now := ss.now()
	if t.Bucket != bucketOf(ctx) || !now.Before(time.Unix(t.Expires, 0)) || t.Extra != extraOf(ctx) {
		return nil, false
	}
	if !ss.replay.Use(t.Nonce, t.Bucket, time.Unix(t.Expires, 0)) {
		return nil, false
	}
	return t.Data, true
}

const ctxExtra ctxKey = 2

func withExtra(ctx context.Context, extra string) context.Context {
	return context.WithValue(ctx, ctxExtra, extra)
}

func extraOf(ctx context.Context) string { s, _ := ctx.Value(ctxExtra).(string); return s }
