package validate

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// FormatNames lists the string formats Rackbook validates itself. The console
// registers the same names with the same rules (web/src/lib/formats.ts), so the
// form and the server agree.
var FormatNames = []string{"ip", "ipv4", "ipv6", "cidr", "port-spec", "date", "textarea", "hostname", "uri"}

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
