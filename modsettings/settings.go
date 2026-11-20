// Package modsettings is the one definition of the settings a module can have
// in the console (docs/modules.md, section 7). The Rackbook server uses it to
// check and store them, and both module programs use it to read them, so a
// setting means the same thing on every side.
//
// The package imports only the standard library: modules may not import
// Rackbook's internal packages, and the server may not import module code.
package modsettings

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
	_ "time/tzdata" // a module on a host without tz data still knows its time zone
)

// Module types: the value of `type:` in a modules entry.
const (
	TypeEntra  = "entra"
	TypeNotify = "notify"
)

// Defaults used when a setting is absent.
var (
	DefaultSendAt     = []string{"08:00"}
	DefaultSyncAt     = []string{"03:00"}
	DefaultThresholds = []int{30, 14, 7, 0}
)

// DefaultTimezone is used when `timezone` is absent.
const DefaultTimezone = "UTC"

// Types lists the module types that have settings.
func Types() []string { return []string{TypeEntra, TypeNotify} }

// Settings is the editable part of one module. A nil slice, a nil pointer, an
// empty string and false mean "not set in the console".
type Settings interface {
	// Type is TypeEntra or TypeNotify.
	Type() string
	// Normalize trims, sorts and de-duplicates in place.
	Normalize()
	// Validate checks every value. collectionExists says whether a collection
	// of the ledger has that name.
	Validate(collectionExists func(string) bool) error
	// Schedule returns the daily times (send_at or sync_at), as set (nil when
	// unset), and the time zone ("" when unset).
	Schedule() (times []string, timezone string)
	// IsPaused says the module must not run.
	IsPaused() bool
}

// Notify is the console settings of rackbook-notify.
type Notify struct {
	Paused      bool     `json:"paused,omitempty"`
	Thresholds  []int    `json:"thresholds,omitempty"`
	Recipients  []string `json:"recipients,omitempty"`
	SendAt      []string `json:"send_at,omitempty"`
	Timezone    string   `json:"timezone,omitempty"`
	Language    string   `json:"language,omitempty"`
	Collections []string `json:"collections,omitempty"`
}

// Entra is the console settings of rackbook-entra.
type Entra struct {
	Paused            bool           `json:"paused,omitempty"`
	SyncAt            []string       `json:"sync_at,omitempty"`
	Timezone          string         `json:"timezone,omitempty"`
	ExcludeAppIDs     []string       `json:"exclude_app_ids,omitempty"`
	ServicePrincipals *bool          `json:"service_principals,omitempty"`
	NamePrefix        *string        `json:"name_prefix,omitempty"`
	Purpose           string         `json:"purpose,omitempty"`
	Defaults          map[string]any `json:"defaults,omitempty"`
}

func (*Notify) Type() string { return TypeNotify }
func (*Entra) Type() string  { return TypeEntra }

func (n *Notify) IsPaused() bool { return n.Paused }
func (e *Entra) IsPaused() bool  { return e.Paused }

func (n *Notify) Schedule() ([]string, string) { return n.SendAt, n.Timezone }
func (e *Entra) Schedule() ([]string, string)  { return e.SyncAt, e.Timezone }

// Keys lists the setting names of a module type, in the order the console
// shows them.
func Keys(typ string) []string {
	switch typ {
	case TypeNotify:
		return []string{"paused", "send_at", "timezone", "thresholds", "recipients", "language", "collections"}
	case TypeEntra:
		return []string{"paused", "sync_at", "timezone", "service_principals", "exclude_app_ids", "name_prefix", "purpose", "defaults"}
	}
	return nil
}

// New returns empty settings of the type.
func New(typ string) (Settings, error) {
	switch typ {
	case TypeNotify:
		return &Notify{}, nil
	case TypeEntra:
		return &Entra{}, nil
	}
	return nil, fmt.Errorf("unknown module type %q (use %s)", typ, strings.Join(Types(), " or "))
}

// Decode reads settings of the type from a decoded YAML or JSON mapping. A key
// that is not a setting of the type is an error that names the allowed keys;
// the result is normalized but not yet validated.
func Decode(typ string, raw map[string]any) (Settings, error) {
	s, err := New(typ)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, k := range Keys(typ) {
		allowed[k] = true
	}
	var unknown []string
	for k := range raw {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown setting %q for a %s module (allowed: %s)", unknown[0], typ, strings.Join(Keys(typ), ", "))
	}
	if len(raw) > 0 {
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("settings: %v", err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(s); err != nil {
			return nil, fmt.Errorf("settings: %s", typeMessage(err))
		}
	}
	s.Normalize()
	return s, nil
}

func typeMessage(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Sprintf("%s has the wrong type (expected %s)", te.Field, te.Type)
	}
	return err.Error()
}

// Map returns the settings as a mapping with only the values that are set:
// what is stored under `settings:` in rackbook.yml and sent over the API.
func Map(s Settings) map[string]any {
	b, _ := json.Marshal(s)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return out
}

// Version identifies a settings mapping; a change needs the version it starts
// from, so two administrators cannot overwrite each other.
func Version(m map[string]any) string {
	b, _ := json.Marshal(m) // map keys are sorted
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// ChangedKeys lists the keys whose value differs between two mappings.
func ChangedKeys(old, nw map[string]any) []string {
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range nw {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		a, _ := json.Marshal(old[k])
		b, _ := json.Marshal(nw[k])
		if !bytes.Equal(a, b) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ---- checks ---------------------------------------------------------------

const (
	maxThresholdDays = 3650
	maxList          = 100
)

var (
	timeRe   = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	prefixRe = regexp.MustCompile(`^[A-Za-z0-9._-]{0,24}$`)
	keyRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	holeRe   = regexp.MustCompile(`\{[^{}]*\}`)
)

var purposeHoles = map[string]bool{"{app}": true, "{name}": true, "{type}": true, "{owner}": true, "{app_id}": true}

// ValidTimes checks a list of daily times "HH:MM".
func ValidTimes(field string, times []string) error {
	if len(times) > 24 {
		return fmt.Errorf("%s: at most 24 times", field)
	}
	for _, t := range times {
		if !timeRe.MatchString(t) {
			return fmt.Errorf("%s: %q is not a time of day (HH:MM, 24 hours)", field, t)
		}
	}
	return nil
}

// ValidTimezone checks an IANA time zone name such as Asia/Shanghai.
func ValidTimezone(tz string) error {
	if tz == "" {
		return nil
	}
	if tz == "Local" || len(tz) > 64 {
		return fmt.Errorf("timezone: %q is not an IANA time zone name such as Asia/Shanghai", tz)
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("timezone: %q is not a known time zone (use a name such as Asia/Shanghai or UTC)", tz)
	}
	return nil
}

func normTimes(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func normStrings(in []string, fold bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		k := s
		if fold {
			k = strings.ToLower(s)
		}
		if s == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

// Normalize implements Settings.
func (n *Notify) Normalize() {
	n.SendAt = normTimes(n.SendAt)
	n.Timezone = strings.TrimSpace(n.Timezone)
	// kept as written (en, zh stay): a rackbook-notify older than these tags
	// reads the stored value, and NotifyLanguage maps it when used
	n.Language = strings.TrimSpace(n.Language)
	n.Recipients = normStrings(n.Recipients, true)
	n.Collections = normStrings(n.Collections, false)
	seen := map[int]bool{}
	var ts []int
	for _, t := range n.Thresholds {
		if !seen[t] {
			seen[t] = true
			ts = append(ts, t)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ts)))
	n.Thresholds = ts
}

// Validate implements Settings.
func (n *Notify) Validate(collectionExists func(string) bool) error {
	if err := ValidTimes("send_at", n.SendAt); err != nil {
		return err
	}
	if err := ValidTimezone(n.Timezone); err != nil {
		return err
	}
	if len(n.Thresholds) > 20 {
		return errors.New("thresholds: at most 20 values")
	}
	for _, t := range n.Thresholds {
		if t < 0 || t > maxThresholdDays {
			return fmt.Errorf("thresholds: %d must be between 0 and %d days", t, maxThresholdDays)
		}
	}
	if len(n.Recipients) > 50 {
		return errors.New("recipients: at most 50 addresses")
	}
	for _, r := range n.Recipients {
		if err := ValidEmail(r); err != nil {
			return fmt.Errorf("recipients: %v", err)
		}
	}
	if _, ok := NotifyLanguage(n.Language); !ok && n.Language != "" {
		return fmt.Errorf("language: %q must be one of %s (en and zh also work)", n.Language, strings.Join(NotifyLanguages, ", "))
	}
	if len(n.Collections) > maxList {
		return fmt.Errorf("collections: at most %d", maxList)
	}
	for _, c := range n.Collections {
		if collectionExists != nil && !collectionExists(c) {
			return fmt.Errorf("collections: %q is not a collection of this ledger", c)
		}
	}
	return nil
}

// ValidEmail accepts a plain address (user@host), no display name.
func ValidEmail(s string) error {
	if strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("%q contains a line break", s)
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s || len(s) > 254 {
		return fmt.Errorf("%q is not an e-mail address", s)
	}
	return nil
}

// Normalize implements Settings.
func (e *Entra) Normalize() {
	e.SyncAt = normTimes(e.SyncAt)
	e.Timezone = strings.TrimSpace(e.Timezone)
	e.Purpose = strings.TrimSpace(e.Purpose)
	ids := normStrings(e.ExcludeAppIDs, true)
	for i := range ids {
		ids[i] = strings.ToLower(ids[i])
	}
	e.ExcludeAppIDs = ids
	if len(e.Defaults) == 0 {
		e.Defaults = nil
	}
}

// Validate implements Settings.
func (e *Entra) Validate(func(string) bool) error {
	if err := ValidTimes("sync_at", e.SyncAt); err != nil {
		return err
	}
	if err := ValidTimezone(e.Timezone); err != nil {
		return err
	}
	if len(e.ExcludeAppIDs) > 500 {
		return errors.New("exclude_app_ids: at most 500 ids")
	}
	for _, id := range e.ExcludeAppIDs {
		if !uuidRe.MatchString(id) {
			return fmt.Errorf("exclude_app_ids: %q is not an application id (a UUID such as 00000000-0000-0000-0000-000000000000)", id)
		}
	}
	if e.NamePrefix != nil && !prefixRe.MatchString(*e.NamePrefix) {
		return fmt.Errorf("name_prefix: %q must be at most 24 characters of letters, digits . _ -", *e.NamePrefix)
	}
	if len(e.Purpose) > 300 {
		return errors.New("purpose: at most 300 characters")
	}
	for _, h := range holeRe.FindAllString(e.Purpose, -1) {
		if !purposeHoles[h] {
			return fmt.Errorf("purpose: %s is not a placeholder (use {app}, {name}, {type}, {owner}, {app_id})", h)
		}
	}
	if len(e.Defaults) > 30 {
		return errors.New("defaults: at most 30 fields")
	}
	for k, v := range e.Defaults {
		if !keyRe.MatchString(k) {
			return fmt.Errorf("defaults: %q is not a field name", k)
		}
		if err := defaultValue(v); err != nil {
			return fmt.Errorf("defaults.%s: %v", k, err)
		}
	}
	return nil
}

// defaultValue accepts a string, a number, a boolean or a list of strings.
func defaultValue(v any) error {
	switch x := v.(type) {
	case string:
		if len(x) > 500 {
			return errors.New("at most 500 characters")
		}
	case bool, float64, int, int64, json.Number:
	case []any:
		if len(x) > 50 {
			return errors.New("at most 50 items")
		}
		for _, e := range x {
			if s, ok := e.(string); !ok || len(s) > 200 {
				return errors.New("a list holds short strings only")
			}
		}
	case []string:
		return defaultValue(strToAny(x))
	default:
		return errors.New("use a string, a number, true/false or a list of strings")
	}
	return nil
}

func strToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// DecodeAndValidate decodes and validates in one step.
func DecodeAndValidate(typ string, raw map[string]any, collectionExists func(string) bool) (Settings, error) {
	s, err := Decode(typ, raw)
	if err != nil {
		return nil, err
	}
	if err := s.Validate(collectionExists); err != nil {
		return nil, err
	}
	return s, nil
}

// NotifyLanguages are the languages rackbook-notify writes in.
var NotifyLanguages = []string{"zh-CN", "zh-TW", "en-US"}

// NotifyLanguage maps a language setting to one of NotifyLanguages, ignoring
// case: the tags themselves, and the older values en (en-US) and zh (zh-CN).
// ok is false for anything else, including "".
func NotifyLanguage(s string) (string, bool) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "_", "-")) {
	case "zh-cn", "zh":
		return "zh-CN", true
	case "zh-tw":
		return "zh-TW", true
	case "en-us", "en":
		return "en-US", true
	}
	return "", false
}
