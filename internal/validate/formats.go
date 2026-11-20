package validate

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
)

// FormatNames lists the string formats Rackbook validates itself. The console
// registers the same names with the same rules (web/src/lib/formats.ts), so the
// form and the server agree.
var FormatNames = []string{"ip", "ipv4", "ipv6", "cidr", "port-spec", "date", "textarea", "hostname", "uri", "country", "subdivision"}

// CheckFormat validates s against one of FormatNames. ok is false for a name
// Rackbook does not know.
func CheckFormat(name, s string) (err error, ok bool) {
	switch name {
	case "ip":
		return checkIP(s, 0), true
	case "ipv4":
		return checkIP(s, 4), true
	case "ipv6":
		return checkIP(s, 6), true
	case "cidr":
		return checkCIDR(s), true
	case "port-spec":
		return checkPortSpec(s), true
	case "date":
		return checkDate(s), true
	case "textarea":
		return nil, true
	case "hostname":
		return checkHostname(s), true
	case "uri":
		return checkURI(s), true
	case "country":
		return checkCountry(s), true
	case "subdivision":
		return checkSubdivision(s), true
	}
	return nil, false
}

// registerFormats makes comp assert formats and installs Rackbook's own.
func registerFormats(comp *jsonschema.Compiler) {
	comp.AssertFormat()
	for _, name := range FormatNames {
		comp.RegisterFormat(&jsonschema.Format{Name: name, Validate: func(v any) error {
			s, isStr := v.(string)
			if !isStr {
				return nil // formats only apply to strings
			}
			err, _ := CheckFormat(name, s)
			return err
		}})
	}
}

func checkIP(s string, version int) error {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return errors.New("not an IP address")
	}
	switch {
	case version == 4 && !a.Is4():
		return errors.New("not an IPv4 address")
	case version == 6 && !a.Is6():
		return errors.New("not an IPv6 address")
	}
	return nil
}

func checkCIDR(s string) error {
	if !strings.Contains(s, "/") {
		return errors.New("not a CIDR (expected address/prefix)")
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Zone() != "" {
		return errors.New("not a CIDR (expected address/prefix)")
	}
	return nil
}

var portSpecRe = regexp.MustCompile(`^(?i:(TCP|UDP)(/(TCP|UDP))?) +([0-9]+(-[0-9]+)?)(, *[0-9]+(-[0-9]+)?)*$`)

func checkPortSpec(s string) error {
	bad := errors.New(`not a port spec (e.g. "TCP 443", "UDP 41641", "TCP 8000-8010, 9000")`)
	if !portSpecRe.MatchString(s) {
		return bad
	}
	_, ports, _ := strings.Cut(s, " ")
	for _, part := range strings.Split(ports, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return fmt.Errorf("port %s is outside 1-65535", lo)
		}
		if isRange {
			b, err := strconv.Atoi(hi)
			if err != nil || b < 1 || b > 65535 {
				return fmt.Errorf("port %s is outside 1-65535", hi)
			}
			if b < a {
				return fmt.Errorf("port range %s-%s is reversed", lo, hi)
			}
		}
	}
	return nil
}

var dateRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

func checkDate(s string) error {
	if !dateRe.MatchString(s) {
		return errors.New("not a date (YYYY-MM-DD)")
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return errors.New("not a real calendar date")
	}
	return nil
}

var labelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func checkHostname(s string) error {
	if s == "" || len(s) > 253 {
		return errors.New("not a host name")
	}
	for _, l := range strings.Split(s, ".") {
		if !labelRe.MatchString(l) {
			return errors.New("not a host name (letters, digits and hyphens, labels up to 63 characters)")
		}
	}
	return nil
}

var uriRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:[^\s\x00-\x1f\x7f]+$`)

func checkURI(s string) error {
	if !uriRe.MatchString(s) {
		return errors.New("not a URI (e.g. https://example.com/path)")
	}
	return nil
}

// Tbd is the placeholder for a value that is not known yet. The country and
// subdivision formats accept it next to real codes.
const Tbd = "tbd"

// notAssigned lists region codes that x/text counts as countries but that ISO
// 3166-1 does not assign: exceptionally reserved codes (AC, CP, DG, EA, IC, TA,
// UN, EZ), transitional ones (AN, CS, FQ, NT, PC, SU, YU), CQ and XK (Kosovo,
// user-assigned). What is left are the 249 officially assigned codes.
var notAssigned = map[string]bool{
	"AC": true, "AN": true, "CP": true, "CQ": true, "CS": true, "DG": true, "EA": true, "EZ": true,
	"FQ": true, "IC": true, "XK": true, "NT": true, "PC": true, "SU": true, "TA": true, "UN": true, "YU": true,
}

// isCountryCode reports an assigned, upper-case ISO 3166-1 alpha-2 code. The
// code must be what x/text reads it as: "UK" (read as GB) and numeric codes fail.
func isCountryCode(s string) bool {
	if len(s) != 2 || notAssigned[s] {
		return false
	}
	r, err := language.ParseRegion(s)
	return err == nil && r.String() == s && r.IsCountry() && r.Canonicalize() == r
}

// Countries lists every country code the country format accepts, sorted. The
// console keeps the same list (web/src/lib/countries.ts); a test compares them.
func Countries() []string {
	var out []string
	for a := 'A'; a <= 'Z'; a++ {
		for b := 'A'; b <= 'Z'; b++ {
			if s := string([]rune{a, b}); isCountryCode(s) {
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

func checkCountry(s string) error {
	if s == Tbd || isCountryCode(s) {
		return nil
	}
	return errors.New(`not a country code (ISO 3166-1 alpha-2 in capitals, like US, or "tbd")`)
}

var subdivisionRe = regexp.MustCompile(`^([A-Z]{2})-[A-Z0-9]{1,3}$`)

func checkSubdivision(s string) error {
	if s == Tbd {
		return nil
	}
	if m := subdivisionRe.FindStringSubmatch(s); m != nil && isCountryCode(m[1]) {
		return nil
	}
	return errors.New(`not a subdivision code (ISO 3166-2, like US-CA or CN-GD, or "tbd")`)
}
