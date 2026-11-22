package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The commit index answers "did this server make that commit, and for whom?"
// without reading the whole log each time. It is a cache of the `commit` lines
// of the chain, kept in <audit dir>/index.json; the chain is the truth, and
// deleting the file is always safe: the next lookup rebuilds it.

const (
	indexName    = "index.json"
	indexVersion = 1
	// minShortHash is the shortest stored hash a longer one may match by prefix.
	minShortHash = 7
)

// CommitRef is what the log knows about a commit this server made.
type CommitRef struct {
	Seq      int64  `json:"seq"`
	Identity string `json:"identity,omitempty"`
	Name     string `json:"name,omitempty"`
	Method   string `json:"method,omitempty"`
	// Token is the name of the API token the commit was made with, if any.
	Token string `json:"token,omitempty"`
}

// CommitKey names a commit: the area of the `commit` event ("ledger" or "infra")
// and the commit hash.
type CommitKey struct{ Area, Hash string }

func (k CommitKey) String() string { return k.Area + ":" + k.Hash }

type commitIndex struct {
	Version      int                  `json:"version"`
	LastSeq      int64                `json:"last_seq"`
	LastLineHash string               `json:"last_line_hash"`
	Commits      map[string]CommitRef `json:"commits"`

	short []string // keys whose hash is a short one (older lines): matched by prefix
}

type indexState struct {
	mu  sync.Mutex
	idx *commitIndex
}

func newCommitIndex() *commitIndex {
	return &commitIndex{Version: indexVersion, Commits: map[string]CommitRef{}}
}

func (x *commitIndex) add(k CommitKey, r CommitRef) {
	x.Commits[k.String()] = r
	if len(k.Hash) < 40 && len(k.Hash) >= minShortHash {
		x.short = append(x.short, k.String())
	}
}

func (x *commitIndex) find(k CommitKey) (CommitRef, bool) {
	if r, ok := x.Commits[k.String()]; ok {
		return r, true
	}
	// A line from before the full hash was written: a prefix of at least
	// seven characters, and only when exactly one line fits.
	var found CommitRef
	n := 0
	prefix := k.Area + ":"
	for _, s := range x.short {
		if h := strings.TrimPrefix(s, prefix); h != s && strings.HasPrefix(k.Hash, h) {
			found = x.Commits[s]
			n++
		}
	}
	return found, n == 1
}

// LookupCommits returns, for the keys that were committed by this server, who
// made them. It brings the index up to date first (reading only the lines
// appended since the last call) and never holds the writer's lock while it reads.
func (l *Log) LookupCommits(keys []CommitKey) map[CommitKey]CommitRef {
	out := map[CommitKey]CommitRef{}
	if l == nil || len(keys) == 0 {
		return out
	}
	l.index.mu.Lock()
	defer l.index.mu.Unlock()
	if err := l.syncIndex(); err != nil {
		l.log.Warn("audit log: could not read the commit index; commits show as unverified for now", "err", err)
		return out
	}
	for _, k := range keys {
		if r, ok := l.index.idx.find(k); ok {
			out[k] = r
		}
	}
	return out
}

// syncIndex loads index.json once, checks that it still describes this log and
// adds the commit lines written since. Any doubt rebuilds it from the files.
func (l *Log) syncIndex() error {
	if l.index.idx == nil {
		l.index.idx = l.loadIndex()
	}
	files, err := listFiles(l.dir)
	if err != nil {
		return err
	}
	x := l.index.idx
	added, ok, err := l.readSince(files, x)
	if err != nil {
		return err
	}
	if !ok {
		x = newCommitIndex()
		l.index.idx = x
		if added, _, err = l.readSince(files, x); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(l.dir, indexName)); added || err != nil {
		l.saveIndex(x) // also when the file was deleted while this process runs
	}
	return nil
}

// readSince adds the commit lines after x.LastSeq to x. ok is false when x does
// not describe this log: the line at x.LastSeq is not there, or is another one.
// With LastSeq 0 every line is new.
func (l *Log) readSince(files []string, x *commitIndex) (added, ok bool, err error) {
	type found struct {
		k CommitKey
		r CommitRef
	}
	var fresh []found
	var newestSeq int64
	var newestHash string
	verified := x.LastSeq == 0
	stop := errors.New("stop")
	for i := len(files) - 1; i >= 0 && !verified; i-- {
		f, oerr := os.Open(filepath.Join(l.dir, files[i]))
		if errors.Is(oerr, os.ErrNotExist) {
			continue
		}
		if oerr != nil {
			return false, false, oerr
		}
		err = eachLineBackward(f, func(raw []byte) error {
			var e Event
			if json.Unmarshal(raw, &e) != nil {
				return nil
			}
			if newestSeq == 0 {
				newestSeq, newestHash = e.Seq, hashOf(raw)
			}
			switch {
			case e.Seq > x.LastSeq:
				if e.Event == "commit" && e.Hash != "" {
					fresh = append(fresh, found{CommitKey{e.Area, e.Hash}, refOf(e)})
				}
				return nil
			case e.Seq == x.LastSeq && hashOf(raw) == x.LastLineHash:
				verified = true
			}
			return stop // the line at LastSeq is not what the index saw, or was passed
		})
		f.Close()
		if err != nil && !errors.Is(err, stop) {
			return false, false, err
		}
		if verified || errors.Is(err, stop) {
			break
		}
	}
	if !verified && x.LastSeq != 0 {
		return false, false, nil
	}
	if x.LastSeq == 0 {
		// Rebuild: every line, newest first.
		fresh, newestSeq, newestHash = nil, 0, ""
		for i := len(files) - 1; i >= 0; i-- {
			f, oerr := os.Open(filepath.Join(l.dir, files[i]))
			if errors.Is(oerr, os.ErrNotExist) {
				continue
			}
			if oerr != nil {
				return false, false, oerr
			}
			err = eachLineBackward(f, func(raw []byte) error {
				var e Event
				if json.Unmarshal(raw, &e) != nil {
					return nil
				}
				if newestSeq == 0 {
					newestSeq, newestHash = e.Seq, hashOf(raw)
				}
				if e.Event == "commit" && e.Hash != "" {
					fresh = append(fresh, found{CommitKey{e.Area, e.Hash}, refOf(e)})
				}
				return nil
			})
			f.Close()
			if err != nil {
				return false, false, err
			}
		}
		added = newestSeq != 0
	} else {
		added = newestSeq > x.LastSeq
	}
	for i := len(fresh) - 1; i >= 0; i-- { // oldest first: a later line for the same commit wins
		x.add(fresh[i].k, fresh[i].r)
	}
	if newestSeq != 0 {
		x.LastSeq, x.LastLineHash = newestSeq, newestHash
	}
	return added, true, nil
}

func refOf(e Event) CommitRef {
	r := CommitRef{Seq: e.Seq, Identity: e.Identity, Name: e.Name, Method: e.Method}
	for _, d := range e.Detail {
		if v, ok := strings.CutPrefix(d, "token:"); ok {
			r.Token = v
		}
	}
	return r
}

func (l *Log) loadIndex() *commitIndex {
	b, err := os.ReadFile(filepath.Join(l.dir, indexName))
	if err != nil {
		return newCommitIndex()
	}
	x := &commitIndex{}
	if json.Unmarshal(b, x) != nil || x.Version != indexVersion || x.Commits == nil {
		return newCommitIndex()
	}
	for k := range x.Commits {
		if area, h, ok := strings.Cut(k, ":"); ok && len(h) < 40 && len(h) >= minShortHash {
			x.short = append(x.short, area+":"+h)
		}
	}
	return x
}

// saveIndex replaces index.json (mode 0600): temp file, rename. A failure is
// only logged; the cache is rebuilt when it is missing.
func (l *Log) saveIndex(x *commitIndex) {
	b, err := json.Marshal(x)
	if err == nil {
		tmp := filepath.Join(l.dir, indexName+".tmp")
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			if err = os.Chmod(tmp, 0o600); err == nil {
				err = os.Rename(tmp, filepath.Join(l.dir, indexName))
			}
		}
		if err != nil {
			os.Remove(tmp)
		}
	}
	if err != nil {
		l.log.Warn("audit log: could not write the commit index", "err", err)
	}
}
