package gitstore

import (
	"strings"

	"github.com/kazuhahub/rackbook/internal/auth"
)

// oneLine makes a value safe for a commit trailer: control characters
// (including newlines, which would inject extra trailers) become spaces.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// AuthorOf is the Git author for who: "Name <email-or-id>". The e-mail is the
// identity's address, else its ID (an MCPHub username or token name). The
// result is zero when who carries neither, so callers can fall back to the Git
// configuration.
func AuthorOf(who *auth.Identity) Identity {
	if who == nil {
		return Identity{}
	}
	addr := oneLine(who.Email)
	if addr == "" {
		addr = oneLine(who.ID)
	}
	if addr == "" {
		return Identity{}
	}
	name := oneLine(who.Name)
	if name == "" {
		name = strings.SplitN(addr, "@", 2)[0]
	}
	// Angle brackets would break the author line.
	r := strings.NewReplacer("<", "", ">", "")
	return Identity{Name: r.Replace(name), Email: r.Replace(addr)}
}

// Trailers builds the commit trailers for a change made by who:
//
//	Edited-by: <id>
//	Edited-via: <via> (<method>[, client <client>])
//	Record: <collection>/<id>
//
// Edited-by is left out for an anonymous caller, the parenthesis for an
// unknown method and Record when record is empty. via is the product name,
// normally "rackbook".
func Trailers(who *auth.Identity, via, record string) []string {
	var t []string
	if who != nil && oneLine(who.ID) != "" {
		t = append(t, "Edited-by: "+oneLine(who.ID))
	}
	v := via
	if who != nil && who.Method != "" {
		detail := oneLine(who.Method)
		if c := oneLine(who.Client); c != "" {
			detail += ", client " + c
		}
		v += " (" + detail + ")"
	}
	t = append(t, "Edited-via: "+v)
	if r := oneLine(record); r != "" {
		t = append(t, "Record: "+r)
	}
	return t
}

// CommitMessage is the subject, a blank line and the trailers. This is the
// one place every Rackbook commit message is built, for the server, the CLI
// and MCP.
func CommitMessage(subject string, who *auth.Identity, via, record string) string {
	return subject + "\n\n" + strings.Join(Trailers(who, via, record), "\n") + "\n"
}
