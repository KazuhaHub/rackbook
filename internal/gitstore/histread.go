package gitstore

// Reading a collection as it was at a commit, for the history views. What it
// costs is parsing: a file of a few hundred records takes tens of milliseconds
// to parse, and a long history has hundreds of versions. So nothing is read or
// parsed by commit but by blob: a commit is resolved to the ids of the blobs of
// rackbook.yml, the collection file and its type with one git process, and what
// is parsed from a blob (the collection definitions of a rackbook.yml, the records
// of a file, the annotations of a type) is kept in small caches shared by all
// requests. A commit that has the same blob of the file as its parent is never parsed.

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/lru"
	"github.com/kazuhahub/rackbook/internal/secretscan"
)

// Sizes of the caches of parsed blobs, variables for the tests.
var (
	histFileCache   = 12   // parsed collection files
	histSmallCache  = 64   // parsed rackbook.yml and type files
	histCommitCache = 2048 // resolved commits
)

// histStats counts the work the history views do, for the tests.
var histStats struct{ parses, blobReads, resolves atomic.Int64 }

// parsedFile is the records of one blob of a collection file.
type parsedFile struct {
	recs   []*ledger.Record
	byID   map[string]*ledger.Record
	broken bool // it did not parse
}

type histConfig struct {
	cols       map[string]*config.Collection
	unreadable bool
}

// treeInfo is what a commit has of one collection: its definition there and the
// ids of the blobs of its file and type.
type treeInfo struct {
	found       bool // the collection is defined there and its file exists
	approximate bool // the definition is today's, because that commit's could not be read
	col         *config.Collection
	fileBlob    string
	schemaBlob  string
}

// histCache is shared by all the requests of a store.
type histCache struct {
	mu      sync.Mutex
	configs *lru.Cache[string, *histConfig]
	files   *lru.Cache[string, *parsedFile]
	schemas *lru.Cache[string, secretscan.Annotations]
	trees   *lru.Cache[string, *treeInfo]
}

func newHistCache() *histCache {
	return &histCache{
		configs: lru.New[string, *histConfig](histSmallCache),
		files:   lru.New[string, *parsedFile](histFileCache),
		schemas: lru.New[string, secretscan.Annotations](histSmallCache),
		trees:   lru.New[string, *treeInfo](histCommitCache),
	}
}

func (s *Store) histCache() *histCache {
	s.histOnce.Do(func() { s.hc = newHistCache() })
	return s.hc
}

// snapshot is one collection as it was at a commit.
type snapshot struct {
	found       bool // the collection and its file existed there
	unreadable  bool // the file is too large, cannot be read or does not parse: nothing can be said
	approximate bool
	fileBlob    string
	col         *config.Collection
	recs        []*ledger.Record
	byID        map[string]*ledger.Record
	ann         secretscan.Annotations
}

// find returns the record with the id, or the one whose redacted id (what the
// API shows for a record whose key holds a secret) it is.
func (sn *snapshot) find(cfg *config.Config, id string) *ledger.Record {
	if sn == nil || !sn.found || sn.unreadable {
		return nil
	}
	if r := sn.byID[id]; r != nil {
		return r
	}
	if strings.Contains(id, "…~") { // the shape of secretscan.RedactID
		for _, r := range sn.recs {
			if ledger.SafeID(cfg, sn.col.Name, r.ID) == id {
				return r
			}
		}
	}
	return nil
}

// snapReader reads snapshots of one collection; the ones it has read it keeps for
// the request (a commit's version is read again as the next commit's parent).
type snapReader struct {
	s     *Store
	ctx   context.Context
	coll  string
	hc    *histCache
	snaps map[string]*snapshot
	trees map[string]*treeInfo
}

func (s *Store) newSnapReader(ctx context.Context, collection string) *snapReader {
	return &snapReader{s: s, ctx: ctx, coll: collection, hc: s.histCache(), snaps: map[string]*snapshot{}, trees: map[string]*treeInfo{}}
}

// histConfigOf parses the rackbook.yml blob (once; the answer is kept).
func (rd *snapReader) histConfigOf(blob string) (*histConfig, error) {
	rd.hc.mu.Lock()
	h, ok := rd.hc.configs.Get(blob)
	rd.hc.mu.Unlock()
	if ok {
		return h, nil
	}
	h = &histConfig{}
	data, truncated, err := rd.s.repo.catBlob(rd.ctx, blob, maxBlobBytes)
	histStats.blobReads.Add(1)
	if err != nil {
		if rd.ctx.Err() != nil {
			return nil, rd.ctx.Err()
		}
		h.unreadable = true
	} else if truncated {
		h.unreadable = true
	} else {
		histStats.parses.Add(1)
		if h.cols, err = config.ParseHistoric(data); err != nil {
			h.unreadable = true
		}
	}
	rd.hc.mu.Lock()
	rd.hc.configs.Put(blob, h)
	rd.hc.mu.Unlock()
	return h, nil
}

// tree resolves the commit (a full hash) to what it has of the collection.
func (rd *snapReader) tree(commit string) (*treeInfo, error) {
	if t, ok := rd.trees[commit]; ok {
		return t, nil
	}
	key := commit + "\x00" + rd.coll
	rd.hc.mu.Lock()
	t, ok := rd.hc.trees.Get(key)
	rd.hc.mu.Unlock()
	if ok {
		rd.trees[commit] = t
		return t, nil
	}
	t = &treeInfo{}
	cur := rd.s.Config()
	curCol := cur.Collection(rd.coll)
	cfgName := filepath.Base(cur.Path)
	guessFile, guessSchema := "", ""
	if curCol != nil {
		guessFile, guessSchema = curCol.File, curCol.Schema
	}
	histStats.resolves.Add(1)
	ids, err := rd.s.repo.lsTree(rd.ctx, commit, cfgName, guessFile, guessSchema)
	if err != nil {
		return nil, err
	}
	// the collection as that commit's rackbook.yml defines it; today's only for what it cannot give
	var col *config.Collection
	fallback := func() {
		t.approximate = true
		if curCol != nil {
			c := *curCol
			col = &c
		}
	}
	if blob := ids[cfgName]; blob == "" {
		fallback()
	} else {
		h, err := rd.histConfigOf(blob)
		if err != nil {
			return nil, err
		}
		if h.unreadable {
			fallback()
		} else if d := h.cols[rd.coll]; d != nil {
			if d.File == "" {
				fallback()
			} else {
				col = d
			}
		}
	}
	if col != nil {
		t.col = col
		if col.File != guessFile || (col.Schema != guessSchema && col.Schema != "") {
			if ids, err = rd.s.repo.lsTree(rd.ctx, commit, col.File, col.Schema); err != nil {
				return nil, err
			}
		}
		t.fileBlob, t.schemaBlob = ids[filepath.ToSlash(filepath.Clean(col.File))], ids[filepath.ToSlash(filepath.Clean(col.Schema))]
		t.found = t.fileBlob != ""
	}
	rd.hc.mu.Lock()
	rd.hc.trees.Put(key, t)
	rd.hc.mu.Unlock()
	rd.trees[commit] = t
	return t, nil
}

// fileOf parses the blob of a collection file (once; kept). The definition of the
// collection decides ids and where the list is, so it is part of what is kept.
func (rd *snapReader) fileOf(blob string, col *config.Collection) (*parsedFile, bool, error) {
	key := blob + "\x00" + col.Path + "\x00" + strings.Join(col.Key, "\x01")
	rd.hc.mu.Lock()
	pf, ok := rd.hc.files.Get(key)
	rd.hc.mu.Unlock()
	if ok {
		return pf, true, nil
	}
	data, truncated, err := rd.s.repo.catBlob(rd.ctx, blob, maxBlobBytes)
	histStats.blobReads.Add(1)
	if err != nil {
		if rd.ctx.Err() != nil {
			return nil, false, rd.ctx.Err()
		}
		return nil, false, nil // unreadable: the caller marks the version
	}
	if truncated {
		return nil, false, nil
	}
	histStats.parses.Add(1)
	pf = &parsedFile{}
	recs, err := ledger.ParseRecords(col, data)
	if err != nil {
		pf.broken = true
	} else {
		pf.recs, pf.byID = recs, make(map[string]*ledger.Record, len(recs))
		for _, r := range recs {
			if _, dup := pf.byID[r.ID]; !dup {
				pf.byID[r.ID] = r
			}
		}
	}
	rd.hc.mu.Lock()
	rd.hc.files.Put(key, pf)
	rd.hc.mu.Unlock()
	return pf, true, nil
}

func (rd *snapReader) annotationsOf(blob string) secretscan.Annotations {
	if blob == "" {
		return nil
	}
	rd.hc.mu.Lock()
	a, ok := rd.hc.schemas.Get(blob)
	rd.hc.mu.Unlock()
	if ok {
		return a
	}
	if data, truncated, err := rd.s.repo.catBlob(rd.ctx, blob, maxBlobBytes); err == nil && !truncated {
		histStats.blobReads.Add(1)
		a = secretscan.AnnotationsOf(data)
	}
	rd.hc.mu.Lock()
	rd.hc.schemas.Put(blob, a)
	rd.hc.mu.Unlock()
	return a
}

// at reads the collection at the commit (a full hash; "" = before the first commit).
func (rd *snapReader) at(commit string) (*snapshot, error) {
	if commit == "" {
		return &snapshot{}, nil
	}
	if sn, ok := rd.snaps[commit]; ok {
		return sn, nil
	}
	t, err := rd.tree(commit)
	if err != nil {
		return nil, err
	}
	sn := &snapshot{approximate: t.approximate, fileBlob: t.fileBlob}
	rd.snaps[commit] = sn
	if !t.found {
		return sn, nil
	}
	sn.found, sn.col = true, t.col
	pf, ok, err := rd.fileOf(t.fileBlob, t.col)
	if err != nil {
		delete(rd.snaps, commit)
		return nil, err
	}
	if !ok || pf.broken {
		sn.unreadable = true
		return sn, nil
	}
	sn.recs, sn.byID = pf.recs, pf.byID
	sn.ann = rd.annotationsOf(t.schemaBlob)
	return sn, nil
}
