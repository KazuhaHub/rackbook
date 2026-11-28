package accounts

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Usernames are never reused (4.5). Three records are unioned at every start: the file
// <state-dir>/accounts/usernames (one name per line, then mac:<HMAC-SHA256 under the usernames
// subkey>), the store's own list, and the target of every account_invited event in the retained
// audit log. A file that is older than the others, though validly MACed, cannot bring a name back.

const usernamesMACLabel = "rackbook usernames v1\n"

func usernamesMAC(key *statekey.Key, names []string) string {
	return hex.EncodeToString(key.MAC(statekey.PurposeUsernames, []byte(usernamesMACLabel+strings.Join(names, "\n"))))
}

// encodeUsernames is the file's content for names (sorted, unique).
func encodeUsernames(key *statekey.Key, names []string) []byte {
	names = sortedUnique(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n + "\n")
	}
	b.WriteString("mac:" + usernamesMAC(key, names) + "\n")
	return []byte(b.String())
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// parseUsernames splits the file into names and the stated MAC (hex).
func parseUsernames(b []byte) (names []string, mac string, err error) {
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "mac:") {
		return nil, "", errors.New("the usernames file has no mac line")
	}
	mac = strings.TrimPrefix(lines[len(lines)-1], "mac:")
	for _, l := range lines[:len(lines)-1] {
		if !ValidUsername(l) {
			return nil, "", fmt.Errorf("the usernames file holds a line that is not a username")
		}
		names = append(names, l)
	}
	return names, mac, nil
}

// ReadUsernames reads the file and checks its MAC under key. A missing file is fs.ErrNotExist;
// a bad MAC is a *StartError with CodeUsernamesMAC.
func ReadUsernames(path string, key *statekey.Key) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	names, mac, err := parseUsernames(b)
	if err != nil {
		return nil, &StartError{Code: CodeUsernamesMAC, Msg: err.Error() + ": " + path}
	}
	want, _ := hex.DecodeString(usernamesMAC(key, names))
	got, derr := hex.DecodeString(mac)
	if derr != nil || !hmac.Equal(got, want) {
		return nil, &StartError{Code: CodeUsernamesMAC, Msg: "the usernames file has a bad MAC (it was edited, or it belongs to another key): " + path}
	}
	return names, nil
}

// ReadUsernamesUnverified reads the names without checking the MAC. discard-store uses it, because
// the key the file was MACed under is lost then; the operator confirms the list.
func ReadUsernamesUnverified(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	names, _, err := parseUsernames(b)
	return names, err
}

// WriteUsernames writes the file for names under key.
func WriteUsernames(path string, key *statekey.Key, names []string) error {
	return writeFile(path, encodeUsernames(key, names))
}

// usedSet is the union of every record of usernames, as the running store sees it.
type usedSet struct {
	mu  sync.Mutex
	set map[string]bool
}

func (u *usedSet) has(n string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.set[n]
}

func (u *usedSet) add(names ...string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.set == nil {
		u.set = map[string]bool{}
	}
	for _, n := range names {
		u.set[n] = true
	}
}

func (u *usedSet) list() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]string, 0, len(u.set))
	for n := range u.set {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// invitedTargets are the usernames named by account_invited events in the retained log.
func invitedTargets(l *audit.Log) ([]string, error) {
	var out []string
	err := l.EachEvent("", func(e audit.Event, _ string) bool {
		if e.Event == "account_invited" {
			if n := strings.TrimPrefix(e.Target, "local:"); ValidUsername(n) {
				out = append(out, n)
			}
		}
		return true
	})
	return out, err
}

func readUsernamesIfAny(path string, key *statekey.Key) ([]string, error) {
	names, err := ReadUsernames(path, key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return names, err
}

func readIfExists(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}
