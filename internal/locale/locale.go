// Package locale lists the languages of the web console and maps what a
// browser or a stored preference says onto them.
package locale

import (
	"strings"

	"golang.org/x/text/language"
)

// Supported is every locale the console is translated into.
var Supported = []string{"zh-CN", "zh-TW", "en-US"}

// Default is the locale used when neither the browser nor the user chose one.
const Default = "zh-CN"

var matcher = language.NewMatcher(func() []language.Tag {
	tags := make([]language.Tag, len(Supported))
	for i, s := range Supported {
		tags[i] = language.MustParse(s)
	}
	return tags
}())

// Normalize maps s to a supported locale, case-insensitively and accepting
// the aliases zh, zh-Hans, zh-SG (zh-CN), zh-Hant, zh-HK, zh-MO (zh-TW) and
// en or en-* (en-US). ok is false for anything else, including "".
func Normalize(s string) (string, bool) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "_", "-"))
	switch s {
	case "zh-cn", "zh", "zh-hans", "zh-sg":
		return "zh-CN", true
	case "zh-tw", "zh-hant", "zh-hk", "zh-mo":
		return "zh-TW", true
	case "en":
		return "en-US", true
	}
	if strings.HasPrefix(s, "en-") {
		return "en-US", true
	}
	return "", false
}

// Match picks the supported locale that best fits an Accept-Language header
// value. It returns fallback when the header is empty, malformed or names
// no supported language.
func Match(acceptLanguage, fallback string) string {
	if strings.TrimSpace(acceptLanguage) == "" {
		return fallback
	}
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return fallback
	}
	// Tags come sorted by preference. Match them one at a time so the user's
	// first choice decides: given together, a plain "zh" would outrank an
	// earlier "zh-HK" because zh-CN is its exact default.
	for _, t := range tags {
		if _, i, conf := matcher.Match(t); conf != language.No && i >= 0 && i < len(Supported) {
			return Supported[i]
		}
	}
	return fallback
}
