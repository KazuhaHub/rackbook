package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/kazuhahub/rackbook/modules/rbclient"
)

const stateVersion = 1

type Entry struct {
	Expires string `json:"expires"`
	Fired   []int  `json:"fired"`
}

type State struct {
	Version int              `json:"version"`
	Items   map[string]Entry `json:"items"`
	// Recipients are the addresses the last mail went to; a change is announced
	// once to the old and the new addresses (recipients.go).
	Recipients []string `json:"recipients,omitempty"`
	// FailedSeen holds, per module, the finish time of the failed run that a
	// digest already reported, so one failure is reported once.
	FailedSeen map[string]string `json:"failed_seen,omitempty"`
}

func newState() *State { return &State{Version: stateVersion, Items: map[string]Entry{}} }

func stateKey(collection, id string) string { return collection + "\x00" + id }

func resolveStatePath(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		// systemd lists several directories separated by ":" (";" on Windows)
		if first := filepath.SplitList(dir)[0]; first != "" {
			return filepath.Join(first, name)
		}
	}
	return name
}

func loadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("state file %s is corrupt: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("state file %s is corrupt: trailing data", path)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("state file %s has unsupported version %d", path, s.Version)
	}
	if s.Items == nil {
		s.Items = map[string]Entry{}
	}
	return &s, nil
}

func saveState(path string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".notify-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// plan decides which items are due and returns the state to save once the
// digest has been delivered. thresholds must be sorted descending.
func plan(old *State, items []rbclient.Item, thresholds []int) (due []rbclient.Item, next *State) {
	next = newState()
	for _, it := range items {
		if it.DaysLeft == nil {
			continue
		}
		d := *it.DaysLeft
		var crossed []int
		for _, t := range thresholds {
			if d <= t {
				crossed = append(crossed, t)
			}
		}
		if len(crossed) == 0 {
			continue
		}
		key := stateKey(it.Collection, it.ID)
		fired := map[int]bool{}
		if e, ok := old.Items[key]; ok && e.Expires == it.Expires {
			for _, t := range e.Fired {
				fired[t] = true
			}
		}
		smallest := crossed[len(crossed)-1]
		isDue := !fired[smallest]
		if isDue {
			for t := range fired {
				if t <= smallest {
					isDue = false
				}
			}
		}
		if isDue {
			due = append(due, it)
		}
		for _, t := range crossed {
			fired[t] = true
		}
		var list []int
		for t := range fired {
			list = append(list, t)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(list)))
		next.Items[key] = Entry{Expires: it.Expires, Fired: list}
	}
	sort.SliceStable(due, func(i, j int) bool { return *due[i].DaysLeft < *due[j].DaysLeft })
	return due, next
}
