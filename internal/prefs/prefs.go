// Package prefs keeps per-person console preferences (today: the language).
// They live in <state-dir>/preferences.json, outside the Git data repository,
// and are keyed by identity ID. Without a path they are kept in memory only.
package prefs

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/internal/locale"
)

// MaxUsers caps how many people the file holds.
const MaxUsers = 10_000

var (
	// ErrInvalidLocale is returned for a locale that is not supported.
	ErrInvalidLocale = errors.New("prefs: unsupported locale")
	// ErrFull is returned when MaxUsers people already have a preference.
	ErrFull = errors.New("prefs: too many users")
)

// User is one person's preferences.
type User struct {
	Locale string `json:"locale,omitempty"`
}

type file struct {
	Version int             `json:"version"`
	Users   map[string]User `json:"users"`
}

// Store is safe for concurrent use. The zero value is an in-memory store; set
// Path before first use to keep it in a file.
type Store struct {
	// Path is the JSON file; empty = in memory only.
	Path string

	mu      sync.Mutex
	loaded  bool
	corrupt bool // the file existed but did not parse; see save
	users   map[string]User
}

// load reads Path once. A missing file starts empty. A file that does not
// parse is logged and treated as empty, but is left untouched on disk until
// the first successful write, which first moves it aside to Path+".corrupt"
// so a hand-edit mistake never silently destroys everyone's settings.
//
// A file that exists but cannot be read (permissions, I/O) is not treated as
// corrupt: load reports the error, nothing is loaded and the next call tries
// again, and writes are refused meanwhile so they cannot replace it.
func (s *Store) load() error {
	if s.loaded {
		return nil
	}
	s.users = map[string]User{}
	if s.Path == "" {
		s.loaded = true
		return nil
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("preferences not read; will retry", "file", s.Path, "err", err)
			return err
		}
		s.loaded = true
		return nil
	}
	s.loaded = true
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		slog.Warn("preferences not read; starting empty (the file is kept until the next save)", "file", s.Path, "err", err)
		s.corrupt = true
		return nil
	}
	for id, u := range f.Users {
		if len(s.users) >= MaxUsers {
			break
		}
		if l, ok := locale.Normalize(u.Locale); ok {
			s.users[id] = User{Locale: l}
		}
	}
	return nil
}

// Locale returns the stored locale of identity id, or "" for none.
func (s *Store) Locale(id string) string {
	if s == nil || id == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return ""
	}
	return s.users[id].Locale
}

// SetLocale stores the locale of identity id and returns the normalized
// value. An empty loc clears the preference. An unsupported value is never
// stored (ErrInvalidLocale). On a write error the change is rolled back.
func (s *Store) SetLocale(id, loc string) (string, error) {
	if id == "" {
		return "", errors.New("prefs: empty identity")
	}
	norm := ""
	if loc != "" {
		var ok bool
		if norm, ok = locale.Normalize(loc); !ok {
			return "", ErrInvalidLocale
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", fmt.Errorf("prefs: %w", err)
	}
	prev, had := s.users[id]
	if norm == "" {
		if !had {
			return "", nil
		}
		delete(s.users, id)
	} else {
		if !had && len(s.users) >= MaxUsers {
			return "", ErrFull
		}
		s.users[id] = User{Locale: norm}
	}
	if err := s.save(); err != nil {
		if had {
			s.users[id] = prev
		} else {
			delete(s.users, id)
		}
		return "", err
	}
	return norm, nil
}

func (s *Store) save() error {
	if s.Path == "" {
		return nil
	}
	b, err := json.Marshal(file{Version: 1, Users: s.users})
	if err != nil {
		return err
	}
	if s.corrupt {
		if err := os.Rename(s.Path, s.Path+".corrupt"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(s.Path, b, 0o600); err != nil {
		return err
	}
	s.corrupt = false
	return nil
}
