package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 specifies HMAC-SHA1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// TOTP, RFC 6238 (5.4): HMAC-SHA1, 6 digits, 30-second period, a 160-bit secret. Verification
// accepts the current step and one either side, and refuses any step at or before the last one used.
const (
	totpDigits    = 6
	totpPeriod    = 30
	totpSecretLen = 20
	totpWindow    = 1
)

// ErrBadCode is the single answer for a code that is wrong, malformed or already used: the
// sign-in never tells which.
var ErrBadCode = errors.New("the code is wrong or was already used")

// NewTOTPSecret makes a 160-bit secret.
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, totpSecretLen)
	_, err := rand.Read(b)
	return b, err
}

// TOTPBase32 is the secret as the base32 text typed into an authenticator (no padding).
func TOTPBase32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// TOTPURI is the otpauth:// URI the enrolment page draws as a QR code.
func TOTPURI(issuer, account string, secret []byte) string {
	v := url.Values{}
	v.Set("secret", TOTPBase32(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", strconv.Itoa(totpDigits))
	v.Set("period", strconv.Itoa(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + v.Encode()
}

// TOTPStep is the time step of t.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// hotp is RFC 4226 with dynamic truncation, to the given number of digits.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// TOTPCode is the 6-digit code of a step.
func TOTPCode(secret []byte, step int64) string { return hotp(secret, uint64(step), totpDigits) }

// VerifyTOTP checks code against the steps now-1, now and now+1 and refuses any step at or before
// lastStep. It compares every candidate in constant time and does not stop at the first match. On
// success it returns the step that matched, which the caller stores as the new last step.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, error) {
	if len(code) != totpDigits {
		return 0, ErrBadCode
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return 0, ErrBadCode
		}
	}
	cur := TOTPStep(now)
	matched, step := 0, int64(0)
	for s := cur - totpWindow; s <= cur+totpWindow; s++ {
		eq := subtle.ConstantTimeCompare([]byte(code), []byte(TOTPCode(secret, s)))
		fresh := 0
		if s > lastStep {
			fresh = 1
		}
		if eq&fresh == 1 {
			matched, step = 1, s // the latest matching step wins
		}
	}
	if matched != 1 {
		return 0, ErrBadCode
	}
	return step, nil
}

// NewTOTPFactor confirms an enrolment: a current code proves the person has the secret. The code's step
// becomes last_step, so the code that confirmed the factor cannot be used to sign in.
func NewTOTPFactor(secret []byte, code string, now time.Time) (*TOTP, error) {
	if len(secret) != totpSecretLen {
		return nil, errors.New("a TOTP secret is 20 bytes")
	}
	step, err := VerifyTOTP(secret, code, now, 0)
	if err != nil {
		return nil, err
	}
	return &TOTP{Secret: append([]byte(nil), secret...), LastStep: step, Added: now.UTC()}, nil
}
