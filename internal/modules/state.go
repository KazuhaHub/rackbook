// Package modules holds the server side of the modules panel
// (docs/modules.md, section 7): the run history and "run now" requests kept in
// the state directory, the edit of a module's settings in rackbook.yml, and the
// preview of what a settings change does to the ledger.
package modules

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/modsettings"
)

const stateVersion = 1

// Request is a "run now" request that no run has answered yet.
type Request struct {
	ID        string    `json:"id"`
	Requested time.Time `json:"requested"`
	By        string    `json:"by,omitempty"`
}

type moduleState struct {
	Runs    []modsettings.Run `json:"runs"` // oldest first
	Request *Request          `json:"request,omitempty"`
}

type fileData struct {
	Version int                     `json:"version"`
	Modules map[string]*moduleState `json:"modules"`
}

// State keeps the runs and requests of every module. With a Path it is a JSON
// file (modules.json in serve --state-dir) that is rewritten atomically after
// every change; without one it lives in memory until the server stops. The
// file holds no secrets.
type State struct {
	// Path is the file; empty = memory only.
	Path string
	// Now is the clock; nil = time.Now.
	Now func() time.Time

	mu     sync.Mutex
	data   fileData
	loaded bool
}

func (s *State) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// load reads the file once. A missing file starts empty; an unreadable or
// corrupt one is logged and also starts empty (the history is a convenience,
// and the next change replaces the file).
func (s *State) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	s.data = fileData{Version: stateVersion, Modules: map[string]*moduleState{}}
	if s.Path == "" {
		return
	}
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err == nil {
		var d fileData
		if err = json.Unmarshal(b, &d); err == nil && d.Version == stateVersion {
			if d.Modules != nil {
				s.data = d
			}
			return
		} else if err == nil {
			err = fmt.Errorf("unsupported version %d", d.Version)
		}
	}
	slog.Warn("module state not read, starting empty", "file", s.Path, "err", err)
}

func (s *State) mod(name string) *moduleState {
	m := s.data.Modules[name]
	if m == nil {
		m = &moduleState{}
		s.data.Modules[name] = m
	}
	return m
}

// save writes the file through a temporary file and a rename.
func (s *State) save() error {
	if s.Path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".modules-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return fsutil.Rename(tmp.Name(), s.Path)
}

// Runs returns the kept runs of a module, newest first.
func (s *State) Runs(name string) []modsettings.Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	var out []modsettings.Run
	if m := s.data.Modules[name]; m != nil {
		for i := len(m.Runs) - 1; i >= 0; i-- {
			out = append(out, m.Runs[i])
		}
	}
	return out
}

// LastRun is the newest run, or nil.
func (s *State) LastRun(name string) *modsettings.Run {
	if r := s.Runs(name); len(r) > 0 {
		return &r[0]
	}
	return nil
}

// LastOK is when the module last finished a successful run (zero = never).
func (s *State) LastOK(name string) time.Time {
	var t time.Time
	for _, r := range s.Runs(name) {
		if r.Status == modsettings.StatusOK && r.Finished.After(t) {
			t = r.Finished
		}
	}
	return t
}

// AddRun records a run the module reported. Rules:
//   - only the newest MaxRuns runs are kept;
//   - a skipped run that follows a skipped run replaces it, so a paused module
//     that checks every hour does not push the real history out;
//   - a run that names the pending request clears it.
func (s *State) AddRun(name string, r modsettings.Run) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	m := s.mod(name)
	if n := len(m.Runs); n > 0 && r.Status == modsettings.StatusSkipped && m.Runs[n-1].Status == modsettings.StatusSkipped {
		m.Runs[n-1] = r
	} else {
		m.Runs = append(m.Runs, r)
	}
	if len(m.Runs) > modsettings.MaxRuns {
		m.Runs = append([]modsettings.Run(nil), m.Runs[len(m.Runs)-modsettings.MaxRuns:]...)
	}
	if m.Request != nil && r.RunRequest == m.Request.ID && r.Status != modsettings.StatusSkipped {
		m.Request = nil
	}
	return s.save()
}

// Pending returns the waiting "run now" request, or nil.
func (s *State) Pending(name string) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	if m := s.data.Modules[name]; m != nil && m.Request != nil {
		r := *m.Request
		return &r
	}
	return nil
}

// Request stores a "run now" request for the module and returns it. While one
// is waiting, asking again returns the same request (nothing is queued twice).
func (s *State) Request(name, by string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	m := s.mod(name)
	if m.Request != nil {
		return *m.Request, nil
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Request{}, err
	}
	m.Request = &Request{ID: hex.EncodeToString(b[:]), Requested: s.now().UTC().Truncate(time.Second), By: by}
	if err := s.save(); err != nil {
		m.Request = nil
		return Request{}, err
	}
	return *m.Request, nil
}
