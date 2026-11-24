package roles

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Bounds on each claim list (groups, app roles) that a session cookie or a stored
// grant keeps, which must stay small. The raw bytes are what the docs promise; the
// encoded size is the safety net for values that JSON escapes (quotes, backslashes),
// so that two full lists plus the rest of a session fit the cookie.
const (
	MaxClaimValues  = 40
	MaxClaimBytes   = 700 // total, of the raw values
	MaxClaimEncoded = 900 // total, as JSON strings with their commas
)

// BoundClaim keeps the first values that fit the bounds, in order. truncated says
// some were dropped for size; values that are empty, longer than 128 bytes or not
// UTF-8 are skipped without counting as a cut. trim removes surrounding spaces
// (group ids, which match without regard to them); app roles are kept as sent.
func BoundClaim(in []string, trim bool) (out []string, truncated bool) {
	total, encoded := 0, 0
	for _, g := range in {
		if trim {
			g = strings.TrimSpace(g)
		}
		if strings.TrimSpace(g) == "" || len(g) > 128 || !utf8.ValidString(g) {
			continue
		}
		enc, _ := json.Marshal(g)
		if len(out) >= MaxClaimValues || total+len(g) > MaxClaimBytes || encoded+len(enc)+1 > MaxClaimEncoded {
			return out, true
		}
		total += len(g)
		encoded += len(enc) + 1
		out = append(out, g)
	}
	return out, false
}
