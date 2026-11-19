package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits of a Client ID Metadata Document fetch.
const (
	maxCIMDBytes   = 8 << 10
	cimdTimeout    = 5 * time.Second
	cimdMinTTL     = time.Minute
	cimdMaxTTL     = time.Hour
	cimdDefaultTTL = 5 * time.Minute
	cimdCacheSize  = 256
	maxRedirects   = 10
	maxNameLen     = 100
)

// clientInfo is what the authorization endpoint needs to know of a client.
type clientInfo struct {
	ID           string
	Name         string
	RedirectURIs []string
}

// specialPrefixes are special-use ranges a client_id URL may never lead to,
// besides everything that is not a global unicast address or is private.
var specialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, and the broadcast address
	netip.MustParsePrefix("::/96"),         // IPv4-compatible
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"), // Teredo
	netip.MustParsePrefix("2002::/16"), // 6to4
	netip.MustParsePrefix("fc00::/7"),  // unique local
	netip.MustParsePrefix("fe80::/10"), // link-local
}

// blockedAddr says an address must not be connected to: anything that is not
// a global unicast address, a private address, or a special-use range.
func blockedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return true
	}
	for _, p := range specialPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// safeClient fetches client metadata documents. The address check runs in the
// dialer's Control hook, on the address that is about to be connected, so a name
// that resolves to a private address (or changes its answer between the check
// and the connection) is refused whatever DNS says. Proxies are not used and
// redirects are not followed.
func safeClient() *http.Client {
	d := &net.Dialer{
		Timeout: cimdTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			a, err := netip.ParseAddr(host)
			if err != nil || blockedAddr(a) {
				return fmt.Errorf("address %s is not allowed", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: cimdTimeout,
		Transport: &http.Transport{
			Proxy: nil, DialContext: d.DialContext, TLSHandshakeTimeout: cimdTimeout,
			ResponseHeaderTimeout: cimdTimeout, DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type cimdEntry struct {
	info    clientInfo
	expires time.Time
}

type cimdFetcher struct {
	client *http.Client
	now    func() time.Time
	log    *slog.Logger
	mu     sync.Mutex
	cache  map[string]cimdEntry
}

func newCIMDFetcher(client *http.Client, now func() time.Time, log *slog.Logger) *cimdFetcher {
	if client == nil {
		client = safeClient()
	}
	return &cimdFetcher{client: client, now: now, log: log, cache: map[string]cimdEntry{}}
}

// errFetch is all the person is told when the document could not be fetched:
// the detail (a DNS answer, an address) stays in the server's log.
var errFetch = errors.New("could not fetch the client's metadata document")

// fetchError marks a failure of the fetch itself, whose detail is not shown.
type fetchError struct{ err error }

func (e *fetchError) Error() string { return e.err.Error() }
func (e *fetchError) Unwrap() error { return e.err }

// isCIMDClientID tells a Client ID Metadata Document client_id (an https URL)
// from a registered client's identifier.
func isCIMDClientID(id string) bool { return strings.HasPrefix(id, "https://") }

// validCIMDURL checks the shape the draft requires of a client_id URL.
func validCIMDURL(raw string) (*url.URL, error) {
	if len(raw) > 512 {
		return nil, errors.New("client_id is too long")
	}
	if !plainASCII(raw) {
		return nil, errors.New("client_id may only contain ASCII characters (write international host names as punycode)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("client_id must be an https URL")
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("client_id must not carry credentials or a fragment")
	}
	if badHost(u) {
		return nil, errors.New("client_id has a host that is not plain ASCII (write international host names as punycode)")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errors.New("client_id needs a path")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return nil, errors.New("client_id must not contain dot segments")
		}
	}
	return u, nil
}

// get returns the client behind a client_id URL: from the cache, else fetched.
func (f *cimdFetcher) get(ctx context.Context, clientID string) (*clientInfo, error) {
	if _, err := validCIMDURL(clientID); err != nil {
		return nil, err
	}
	f.mu.Lock()
	if e, ok := f.cache[clientID]; ok && f.now().Before(e.expires) {
		f.mu.Unlock()
		info := e.info
		return &info, nil
	}
	f.mu.Unlock()
	info, ttl, err := f.fetch(ctx, clientID)
	var fe *fetchError
	if errors.As(err, &fe) {
		f.log.Info("client metadata document not fetched", "client", clientID, "err", fe.err.Error())
		return nil, errFetch
	}
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cache) >= cimdCacheSize {
		for k, e := range f.cache {
			if !f.now().Before(e.expires) {
				delete(f.cache, k)
			}
		}
		for k := range f.cache { // still full: drop an arbitrary entry
			if len(f.cache) < cimdCacheSize {
				break
			}
			delete(f.cache, k)
		}
	}
	f.cache[clientID] = cimdEntry{info: *info, expires: f.now().Add(ttl)}
	return info, nil
}

var maxAge = regexp.MustCompile(`(?i)max-age=(\d+)`)

func (f *cimdFetcher) fetch(ctx context.Context, clientID string) (*clientInfo, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, 0, &fetchError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, &fetchError{fmt.Errorf("the client metadata document answered %d", resp.StatusCode)}
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
		return nil, 0, &fetchError{errors.New("the client metadata document is not JSON")}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBytes+1))
	if err != nil {
		return nil, 0, &fetchError{err}
	}
	if len(raw) > maxCIMDBytes {
		return nil, 0, fmt.Errorf("the client metadata document is larger than %d bytes", maxCIMDBytes)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, errors.New("the client metadata document is not a JSON object")
	}
	if id, _ := doc["client_id"].(string); id != clientID {
		return nil, 0, errors.New("client_id in the document does not equal the URL it was fetched from")
	}
	for _, k := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := doc[k]; ok {
			return nil, 0, fmt.Errorf("the client metadata document must not contain %s", k)
		}
	}
	if m, ok := doc["token_endpoint_auth_method"].(string); ok && m != "none" {
		return nil, 0, errors.New("only public clients are supported (token_endpoint_auth_method none)")
	}
	uris, err := redirectList(doc["redirect_uris"])
	if err != nil {
		return nil, 0, err
	}
	name, _ := doc["client_name"].(string)
	u, _ := url.Parse(clientID)
	info := &clientInfo{ID: clientID, Name: cleanName(name, u.Host), RedirectURIs: uris}
	ttl := cimdDefaultTTL
	if m := maxAge.FindStringSubmatch(resp.Header.Get("Cache-Control")); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			ttl = time.Duration(n) * time.Second
		}
	}
	return info, min(max(ttl, cimdMinTTL), cimdMaxTTL), nil
}

// cleanName makes a client-supplied name safe to show and to put in a commit
// trailer: printable, one line, bounded. An empty name becomes fallback.
func cleanName(s, fallback string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7f, r == 0x85, r == 0x2028, r == 0x2029, r == '<', r == '>', unicode.Is(unicode.Cf, r):
		default:
			b.WriteRune(r)
		}
		if b.Len() >= maxNameLen*2 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if rs := []rune(out); len(rs) > maxNameLen {
		out = string(rs[:maxNameLen])
	}
	if out == "" {
		return fallback
	}
	return out
}

// redirectList validates a redirect_uris value.
func redirectList(v any) ([]string, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return nil, errors.New("redirect_uris must be a non-empty list")
	}
	if len(arr) > maxRedirects {
		return nil, fmt.Errorf("at most %d redirect_uris", maxRedirects)
	}
	var out []string
	for _, e := range arr {
		s, _ := e.(string)
		if err := validateRedirect(s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// deniedSchemes are never a redirect target, whatever else is allowed.
var deniedSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "vbscript": true, "blob": true,
	"about": true, "ftp": true, "ws": true, "wss": true, "http": true,
}

var schemeRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// validateRedirect allows an https URL, an http URL on the loopback host
// (localhost, 127.0.0.1, [::1]) and the private-use scheme of a native
// application (cursor://..., vscode://...). It never allows a fragment or
// credentials.
func validateRedirect(s string) error {
	if s == "" || len(s) > 2048 {
		return errors.New("a redirect_uri is empty or too long")
	}
	if !plainASCII(s) || strings.Contains(s, "\\") {
		return fmt.Errorf("redirect_uri %q may only contain printable ASCII characters (write international host names as punycode)", s)
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Opaque != "" {
		return fmt.Errorf("redirect_uri %q is not an absolute URL", s)
	}
	if u.Fragment != "" || u.User != nil || strings.Contains(s, "#") {
		return fmt.Errorf("redirect_uri %q must not carry credentials or a fragment", s)
	}
	if badHost(u) {
		return fmt.Errorf("redirect_uri %q has a host that is not plain ASCII (write international host names as punycode)", s)
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("redirect_uri %q has no host", s)
		}
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return fmt.Errorf("redirect_uri %q: http is only allowed for localhost", s)
		}
	default:
		if deniedSchemes[u.Scheme] || !schemeRe.MatchString(u.Scheme) || (u.Host == "" && u.Path == "") {
			return fmt.Errorf("redirect_uri %q uses a scheme that is not allowed", s)
		}
	}
	return nil
}

// redirectHost is what the consent page shows as the place the code is sent to.
func redirectHost(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if u.Scheme == "https" || u.Scheme == "http" {
		return u.Host
	}
	return u.Scheme + "://" + u.Host
}

// plainASCII is true for a string of printable ASCII only: no control, bidi or
// zero-width character, and no look-alike letters from other scripts.
func plainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// hasPunycode says a host has a label that starts with xn--, which a browser
// may show as foreign letters that look like others.
func hasPunycode(host string) bool {
	for _, l := range strings.Split(strings.ToLower(host), ".") {
		if strings.HasPrefix(l, "xn--") {
			return true
		}
	}
	return false
}

// badHost refuses a host that is not plain ASCII once decoded: a percent
// escape in a host (https://%D0%B0pple.com) would pass a check on the raw text
// and show as look-alike letters. No '%' is allowed in a host at all.
func badHost(u *url.URL) bool {
	return strings.Contains(u.Host, "%") || !plainASCII(u.Hostname())
}
