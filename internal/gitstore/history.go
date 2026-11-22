package gitstore

// A record's version history (docs/design-audit.md, section 3.3): the commits
// that changed one record, each with a field-level diff against the parent's
// version of the record. A version is read from the collection file *as it was at
// that commit*, with the collection's file path, key and type definition of that
// commit, never today's.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/secretscan"
)

// How the commits of a record are found (VersionQuery.Mode).
const (
	// ModeRecord lists the commits that carry the exact trailer "Record: <collection>/<id>".
	ModeRecord = "record"
	// ModeFile is the fallback for a record no commit names (edited before the
	// trailer existed, or by hand): the commits that touched the collection's
	// file, those in which the record did not change left out.
	ModeFile = "file"
)

// Limits of one RecordVersions call, variables for the tests.
var (
	MaxVersions   = 50      // versions one call returns
	VersionBudget = 400     // commits one call walks
	MaxChanges    = 200     // field changes kept for one version
	maxValueBytes = 8 << 10 // a value longer than this (as JSON) is cut
	maxBlobBytes  = 8 << 20 // the largest file read at a commit
)

// ErrNotInCommit is matched by errors.Is when the record did not exist in the commit.
var ErrNotInCommit = errors.New("the record did not exist in that commit")

var fullRevRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// blobAt reads the file rel (config-relative, a literal path) as it was in the
// commit, a full hash. found is false when the commit has no such file. It is
// the only way a file is read at a commit: "git cat-file blob <commit>:./<path>"
// with a validated hash and a path that is relative and inside the data
// directory, never "git show" and never an option.
func (r *Repo) blobAt(ctx context.Context, commit, rel string) (data []byte, found bool, err error) {
	if !fullRevRe.MatchString(commit) {
		return nil, false, fmt.Errorf("%w: %q", ErrNoCommit, commit)
	}
	p := path.Clean(filepath.ToSlash(rel))
	if rel == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") ||
		strings.ContainsAny(p, "\x00\n\r") || config.IsStatePath(p) || p == ".git" || strings.HasPrefix(p, ".git/") {
		return nil, false, fmt.Errorf("refusing to read %q at a commit", rel)
	}
	out, truncated, err := r.runLimited(ctx, maxBlobBytes, "cat-file", "blob", commit+":./"+p)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "Not a valid object name") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "but not in") {
			return nil, false, nil
		}
		return nil, false, err
	}
	if truncated {
		return nil, false, fmt.Errorf("%s is too large to read at a commit", p)
	}
	return []byte(out), true, nil
}

// resolveOnBranch turns rev into a full commit hash and checks that the commit
// is on the tracked branch's accepted history (reachable from tip). One error
// for every refusal.
func resolveOnBranch(ctx context.Context, r *Repo, tip, rev string) (string, error) {
	notFound := fmt.Errorf("%w: %s", ErrNoCommit, rev)
	if !ValidRev(rev) {
		return "", notFound
	}
	full, err := r.git(ctx, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil || full == "" {
		return "", notFound
	}
	if _, err := r.git(ctx, "merge-base", "--is-ancestor", full, tip); err != nil {
		return "", notFound
	}
	return full, nil
}

// snapshot is one collection as it was at a commit.
type snapshot struct {
	found  bool // the collection and its file existed and the file could be read
	broken bool // the file existed but did not parse: nothing can be said about it
	col    *config.Collection
	recs   []*ledger.Record
	byID   map[string]*ledger.Record
	ann    secretscan.Annotations
}

// find returns the record with the id, or the one whose redacted id (what the
// API shows for a record whose key holds a secret) it is.
func (sn *snapshot) find(cfg *config.Config, id string) *ledger.Record {
	if sn == nil || !sn.found {
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

// snapReader reads snapshots of one collection and keeps the ones it has read
// (a commit's version is read again as the next commit's parent).
type snapReader struct {
	s     *Store
	ctx   context.Context
	coll  string
	cfgs  map[string]*config.Config
	snaps map[string]*snapshot
}

func (s *Store) newSnapReader(ctx context.Context, collection string) *snapReader {
	return &snapReader{s: s, ctx: ctx, coll: collection, cfgs: map[string]*config.Config{}, snaps: map[string]*snapshot{}}
}

// config is the rackbook.yml of the commit; nil when it is missing or does not load.
func (rd *snapReader) config(commit string) *config.Config {
	if c, ok := rd.cfgs[commit]; ok {
		return c
	}
	var cfg *config.Config
	cur := rd.s.Config()
	if data, ok, err := rd.s.repo.blobAt(rd.ctx, commit, filepath.Base(cur.Path)); err == nil && ok {
		if c, err := config.Parse(data, cur.Path); err == nil {
			cfg = c
		}
	}
	rd.cfgs[commit] = cfg
	return cfg
}

// at reads the collection at the commit (a full hash; "" = before the first commit).
func (rd *snapReader) at(commit string) (*snapshot, error) {
	if commit == "" {
		return &snapshot{}, nil
	}
	if sn, ok := rd.snaps[commit]; ok {
		return sn, nil
	}
	sn := &snapshot{}
	rd.snaps[commit] = sn
	var col *config.Collection
	if old := rd.config(commit); old != nil {
		col = old.Collection(rd.coll)
	} else if c := rd.s.Config().Collection(rd.coll); c != nil {
		col = c // the config of that commit is unreadable: assume the collection was as it is now
	}
	if col == nil {
		return sn, nil
	}
	src, ok, err := rd.s.repo.blobAt(rd.ctx, commit, col.File)
	if err != nil {
		delete(rd.snaps, commit)
		return nil, err
	}
	if !ok {
		return sn, nil
	}
	recs, err := ledger.ParseRecords(col, src)
	if err != nil {
		sn.broken = true
		return sn, nil
	}
	sn.found, sn.col, sn.recs, sn.byID = true, col, recs, make(map[string]*ledger.Record, len(recs))
	for _, r := range recs {
		if _, dup := sn.byID[r.ID]; !dup {
			sn.byID[r.ID] = r
		}
	}
	if col.Schema != "" {
		if raw, ok, err := rd.s.repo.blobAt(rd.ctx, commit, col.Schema); err == nil && ok {
			sn.ann = secretscan.AnnotationsOf(raw)
		}
	}
	return sn, nil
}

// FieldChange is one difference between two versions of a record.
type FieldChange struct {
	// Path locates the field: "a.b", "ports[2].proto".
	Path string `json:"path"`
	Op   string `json:"op"` // "added", "removed" or "changed"
	// Old and New are the values (null where the op has none). A value that the
	// secret scan flags is replaced by "(hidden)" and Hidden is set.
	Old       any  `json:"old"`
	New       any  `json:"new"`
	Hidden    bool `json:"hidden,omitempty"`
	Truncated bool `json:"truncated,omitempty"`
}

// Kinds of a version.
const (
	KindCreated = "created"
	KindChanged = "changed"
	KindDeleted = "deleted"
	KindRenamed = "renamed" // the id changed (the key fields were edited)
)

// RecordVersion is one commit that changed a record.
type RecordVersion struct {
	Commit ActivityCommit `json:"-"`
	Kind   string         `json:"kind"`
	// RenamedFrom and RenamedTo are the other id of a rename (redacted when needed).
	RenamedFrom string `json:"renamedFrom,omitempty"`
	RenamedTo   string `json:"renamedTo,omitempty"`
	// Hash is the record's hash at this commit ("" when the commit deleted it).
	Hash        string        `json:"hash"`
	Changes     []FieldChange `json:"changes"`
	MoreChanges bool          `json:"moreChanges,omitempty"`
}

// VersionQuery selects the versions of one record. The caller pages by walk
// position, as for the activity view: Tip pins the commit the walk starts from
// (as a previous page returned it), Mode is the one the first page chose and
// Skip the commits of the walk already consumed.
type VersionQuery struct {
	Collection, ID string
	Tip, Mode      string
	Skip           int
	Limit          int // at most MaxVersions, 20 when 0
}

// VersionPage is one page of versions, newest first.
type VersionPage struct {
	Tip, Mode string
	// Skip is where the next page resumes; Done says there is no next page.
	Skip     int
	Done     bool
	ID       string // the id as it is shown (redacted when it holds a secret)
	Versions []RecordVersion
}

func (s *Store) versionPlan(collection, id string) (*ledger.Collection, string, error) {
	col := s.cur.Load().Collection(collection)
	if col == nil {
		return nil, "", fmt.Errorf("unknown collection %q", collection)
	}
	if id == "" {
		return nil, "", errors.New("id is required")
	}
	return col, ledger.SafeID(s.Config(), collection, id), nil
}

// RecordVersions lists the commits that changed the record, newest first, each
// with what changed in the record against the commit's parent. Commits are the
// ones with the exact Record trailer; a record no commit names falls back to the
// commits that touched the collection's file, from which those in which the
// record did not change are left out. A page walks at most VersionBudget
// commits, so Versions may be short or empty while Done is false.
func (s *Store) RecordVersions(ctx context.Context, q VersionQuery) (*VersionPage, error) {
	col, shown, err := s.versionPlan(q.Collection, q.ID)
	if err != nil {
		return nil, err
	}
	pg := &VersionPage{Versions: []RecordVersion{}, Done: true, ID: shown, Mode: q.Mode, Skip: q.Skip}
	if !s.git {
		return pg, nil
	}
	branchTip, ok := s.trackedTip(ctx)
	if !ok {
		return pg, nil
	}
	tip, err := pinnedTip(ctx, s.repo, branchTip, q.Tip)
	if err != nil {
		return nil, err
	}
	pg.Tip = tip
	record := edit.RecordRef(q.Collection, shown)
	mode := q.Mode
	switch mode {
	case "":
		found := false
		err := activityLog(ctx, s.repo, tip, ActivityQuery{Limit: MaxActivity}, nil, record, func(c ActivityCommit) bool {
			found = !c.Excluded
			return !found
		})
		if err != nil {
			return nil, err
		}
		mode = ModeRecord
		if !found {
			mode = ModeFile
		}
	case ModeRecord, ModeFile:
	default:
		return nil, ErrBadTip
	}
	pg.Mode = mode
	limit := q.Limit
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, MaxVersions)
	var paths []string
	want := ""
	if mode == ModeFile {
		paths = []string{filepath.FromSlash(col.File)}
	} else {
		want = record
	}
	rd := s.newSnapReader(ctx, q.Collection)
	budget := min(VersionBudget, MaxActivity)
	consumed, stopped := 0, false
	var inner error
	err = activityLog(ctx, s.repo, tip, ActivityQuery{Skip: q.Skip, Limit: budget}, paths, want, func(c ActivityCommit) bool {
		consumed++
		if c.Excluded {
			return true
		}
		v, err := rd.version(c, q.ID, mode)
		if err != nil {
			inner = err
			return false
		}
		if v != nil {
			pg.Versions = append(pg.Versions, *v)
			if len(pg.Versions) >= limit {
				stopped = true
				return false
			}
		}
		return true
	})
	if err == nil {
		err = inner
	}
	if err != nil {
		return nil, err
	}
	pg.Skip = q.Skip + consumed
	pg.Done = !stopped && consumed < budget
	return pg, nil
}

// version builds the version of the record that commit c made, nil when the
// record is not involved (or did not change, in the file fallback).
func (rd *snapReader) version(c ActivityCommit, id, mode string) (*RecordVersion, error) {
	cfg := rd.s.Config()
	cur, err := rd.at(c.Hash)
	if err != nil {
		return nil, err
	}
	prev, err := rd.at(c.Parent)
	if err != nil {
		return nil, err
	}
	if cur.broken || prev.broken {
		return nil, nil // a file that does not parse says nothing about the record
	}
	newRec, oldRec := cur.find(cfg, id), prev.find(cfg, id)
	v := &RecordVersion{Commit: c, Kind: KindChanged}
	switch {
	case newRec == nil && oldRec == nil:
		return nil, nil
	case oldRec == nil:
		if from := renamedFrom(prev, cur, newRec); from != nil {
			oldRec, v.Kind, v.RenamedFrom = from, KindRenamed, ledger.SafeID(cfg, rd.coll, from.ID)
		} else {
			v.Kind = KindCreated
		}
	case newRec == nil:
		if to := renamedTo(prev, cur, oldRec); to != nil {
			newRec, v.Kind, v.RenamedTo = to, KindRenamed, ledger.SafeID(cfg, rd.coll, to.ID)
		} else {
			v.Kind = KindDeleted
		}
	}
	if newRec != nil {
		v.Hash = ledger.Hash(newRec.Data)
	}
	if mode == ModeFile && v.Kind == KindChanged && v.Hash == ledger.Hash(oldRec.Data) {
		return nil, nil
	}
	var from, to map[string]any
	var fromSn, toSn = prev, cur
	if oldRec != nil {
		from = oldRec.Data
	}
	if newRec != nil {
		to = newRec.Data
	}
	v.Changes, v.MoreChanges = rd.s.diffRecords(rd.coll, cfg, fromSn, oldRec, from, toSn, newRec, to)
	return v, nil
}

// renamedFrom finds the record that became rec when its key fields were edited:
// the one at the same position of the list whose id is gone (an edit keeps the
// position).
func renamedFrom(prev, cur *snapshot, rec *ledger.Record) *ledger.Record {
	if len(prev.recs) != len(cur.recs) || rec.Index >= len(prev.recs) || len(cur.col.Key) == 0 {
		return nil
	}
	old := prev.recs[rec.Index]
	if old.ID == rec.ID || cur.byID[old.ID] != nil || prev.byID[rec.ID] != nil {
		return nil
	}
	return old
}

// renamedTo is renamedFrom the other way round.
func renamedTo(prev, cur *snapshot, rec *ledger.Record) *ledger.Record {
	if len(prev.recs) != len(cur.recs) || rec.Index >= len(cur.recs) || len(prev.col.Key) == 0 {
		return nil
	}
	nw := cur.recs[rec.Index]
	if nw.ID == rec.ID || prev.byID[nw.ID] != nil || cur.byID[rec.ID] != nil {
		return nil
	}
	return nw
}

// diffRecords compares two versions of a record. A value the secret scan flags
// (as it would for the record today, with the type definition of its own commit)
// is not returned: it is "(hidden)", and a change between two hidden values is
// still reported. A nil side is a record that did not exist.
func (s *Store) diffRecords(coll string, cfg *config.Config, fromSn *snapshot, fromRec *ledger.Record, from map[string]any, toSn *snapshot, toRec *ledger.Record, to map[string]any) ([]FieldChange, bool) {
	sc := cfg.SecretScanner()
	a := hideFindings(from, scanOf(sc, coll, cfg, fromSn, fromRec))
	b := hideFindings(to, scanOf(sc, coll, cfg, toSn, toRec))
	var out []FieldChange
	more := false
	diffValues("", a, b, func(c FieldChange) {
		if len(out) >= MaxChanges {
			more = true
			return
		}
		out = append(out, finishChange(c))
	})
	if out == nil {
		out = []FieldChange{}
	}
	return out, more
}

func scanOf(sc *secretscan.Scanner, coll string, cfg *config.Config, sn *snapshot, rec *ledger.Record) []secretscan.Finding {
	if rec == nil || sn == nil {
		return nil
	}
	return sc.ScanRecordWith(coll, ledger.SafeID(cfg, coll, rec.ID), rec.Data, sn.ann)
}

// The value shown in place of a hidden one, and what stands for it while two
// versions are compared (it carries a short hash, so that a change between two
// hidden values is still a change).
const (
	hiddenText = "(hidden)"
	hiddenMark = "\x00hidden:"
)

// pointerSegs splits a JSON pointer.
func pointerSegs(p string) []string {
	if p == "" || p == "/" {
		return nil
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		segs[i] = strings.NewReplacer("~1", "/", "~0", "~").Replace(s)
	}
	return segs
}

func hiddenValue(v any) string {
	b, _ := json.Marshal(v)
	return hiddenMark + secretscan.Hash(string(b))[:12]
}

// hideFindings returns a copy of data in which the values the findings point at
// are replaced by hidden marks; data itself when there are none.
func hideFindings(data map[string]any, fs []secretscan.Finding) map[string]any {
	if len(fs) == 0 || data == nil {
		return data
	}
	out := copyValue(data).(map[string]any)
	for _, f := range fs {
		segs := pointerSegs(f.Path)
		if len(segs) == 0 {
			// a secret in a field name of the record itself: nothing of it can be shown
			return map[string]any{hiddenText: hiddenValue(data)}
		}
		var at any = out
		for i, seg := range segs {
			last := i == len(segs)-1
			switch x := at.(type) {
			case map[string]any:
				if last {
					if v, ok := x[seg]; ok {
						x[seg] = hiddenValue(v)
					}
					at = nil
				} else {
					at = x[seg]
				}
			case []any:
				n, err := strconv.Atoi(seg)
				if err != nil || n < 0 || n >= len(x) {
					at = nil
				} else if last {
					x[n] = hiddenValue(x[n])
					at = nil
				} else {
					at = x[n]
				}
			default:
				at = nil
			}
			if at == nil {
				break
			}
		}
	}
	return out
}

func copyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = copyValue(e)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = copyValue(e)
		}
		return l
	}
	return v
}

// scrub replaces the hidden marks in v and says whether there were any.
func scrub(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, hiddenMark) {
			return hiddenText, true
		}
	case map[string]any:
		hid := false
		out := make(map[string]any, len(x))
		for k, e := range x {
			n, h := scrub(e)
			out[k], hid = n, hid || h
		}
		return out, hid
	case []any:
		hid := false
		out := make([]any, len(x))
		for i, e := range x {
			n, h := scrub(e)
			out[i], hid = n, hid || h
		}
		return out, hid
	}
	return v, false
}

// finishChange scrubs the hidden marks out of a change and cuts long values.
func finishChange(c FieldChange) FieldChange {
	var h1, h2 bool
	c.Old, h1 = scrub(c.Old)
	c.New, h2 = scrub(c.New)
	c.Hidden = h1 || h2
	var t1, t2 bool
	c.Old, t1 = limitValue(c.Old)
	c.New, t2 = limitValue(c.New)
	c.Truncated = t1 || t2
	return c
}

// limitValue cuts a value whose JSON is longer than maxValueBytes to a string
// of its first part.
func limitValue(v any) (any, bool) {
	switch v.(type) {
	case nil, bool, float64, int, int64, json.Number:
		return v, false
	}
	b, _ := json.Marshal(v)
	if len(b) <= maxValueBytes {
		return v, false
	}
	s := string(b[:maxValueBytes])
	if str, ok := v.(string); ok {
		s = str
		if len(s) > maxValueBytes {
			s = s[:maxValueBytes]
		}
	}
	return strings.ToValidUTF8(s, "") + "…", true
}

// diffValues reports the differences between a and b, as added, removed or
// changed fields at the deepest path where the two still have the same shape
// (a map against a map, a list against a list); a value of another shape is
// one change.
func diffValues(p string, a, b any, add func(FieldChange)) {
	switch x := a.(type) {
	case map[string]any:
		if y, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range x {
				keys[k] = true
			}
			for k := range y {
				keys[k] = true
			}
			sorted := make([]string, 0, len(keys))
			for k := range keys {
				sorted = append(sorted, k)
			}
			sort.Strings(sorted)
			for _, k := range sorted {
				ov, inA := x[k]
				nv, inB := y[k]
				switch {
				case inA && !inB:
					add(FieldChange{Path: keyPath(p, k), Op: "removed", Old: ov})
				case !inA && inB:
					add(FieldChange{Path: keyPath(p, k), Op: "added", New: nv})
				default:
					diffValues(keyPath(p, k), ov, nv, add)
				}
			}
			return
		}
	case []any:
		if y, ok := b.([]any); ok {
			for i := 0; i < max(len(x), len(y)); i++ {
				ip := p + "[" + strconv.Itoa(i) + "]"
				switch {
				case i >= len(y):
					add(FieldChange{Path: ip, Op: "removed", Old: x[i]})
				case i >= len(x):
					add(FieldChange{Path: ip, Op: "added", New: y[i]})
				default:
					diffValues(ip, x[i], y[i], add)
				}
			}
			return
		}
	}
	if !sameValue(a, b) {
		add(FieldChange{Path: p, Op: "changed", Old: a, New: b})
	}
}

var plainKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func keyPath(parent, key string) string {
	switch {
	case !plainKeyRe.MatchString(key):
		return parent + "[" + strconv.Quote(key) + "]"
	case parent == "":
		return key
	}
	return parent + "." + key
}

func sameValue(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// VersionDetail is one version of a record, with what it differs from today's.
type VersionDetail struct {
	Commit ActivityCommit
	ID     string // as shown
	Hash   string // the record's hash at the commit
	// Data is the record at the commit, without the values the secret scan flags.
	Data map[string]any
	// Hidden counts the values left out of Data.
	Hidden int
	// Exists says the record exists now; Current that it is the same as this version.
	Exists, Current bool
	// Changes are what restoring would change: from today's record to this
	// version (nothing when the record does not exist now).
	Changes     []FieldChange
	MoreChanges bool
}

// RestoreSource is a version of a record as a restore needs it: the whole
// content, with the commit it comes from.
type RestoreSource struct {
	Commit string // full hash
	// Data is the record as it was at the commit.
	Data map[string]any
	Hash string
	// ID is the id the record had then; KeyID the id its key fields give under
	// today's definition of the collection ("" for a collection without a key).
	ID string
	// Visible is Data without the values the secret scan flags, and Hidden how
	// many were left out: it is what may be shown to the caller.
	Visible map[string]any
	Hidden  int
}

// atCommit finds the record in the commit, which must be on the tracked branch.
func (s *Store) atCommit(ctx context.Context, collection, id, rev string) (full string, sn *snapshot, rec *ledger.Record, rd *snapReader, err error) {
	if _, _, err = s.versionPlan(collection, id); err != nil {
		return
	}
	if !s.git {
		err = errors.New("history needs the data directory to be a repository")
		return
	}
	tip, ok := s.trackedTip(ctx)
	if !ok {
		err = fmt.Errorf("%w: %s", ErrNoCommit, rev)
		return
	}
	if full, err = resolveOnBranch(ctx, s.repo, tip, rev); err != nil {
		return
	}
	rd = s.newSnapReader(ctx, collection)
	if sn, err = rd.at(full); err != nil {
		return
	}
	if rec = sn.find(s.Config(), id); rec == nil {
		err = fmt.Errorf("%w: %s", ErrNotInCommit, rev)
	}
	return
}

// hiddenCount counts the hidden marks in v.
func hiddenCount(v any) int {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, hiddenMark) {
			return 1
		}
	case map[string]any:
		n := 0
		for _, e := range x {
			n += hiddenCount(e)
		}
		return n
	case []any:
		n := 0
		for _, e := range x {
			n += hiddenCount(e)
		}
		return n
	}
	return 0
}

// dropHidden returns v without the entries that are hidden marks (a hidden
// element of a list stays as an empty string, so that the others keep their place).
func dropHidden(v any) any {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, hiddenMark) {
			return ""
		}
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if s, ok := e.(string); ok && strings.HasPrefix(s, hiddenMark) {
				continue
			}
			out[k] = dropHidden(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = dropHidden(e)
		}
		return out
	}
	return v
}

// RestoreSourceAt reads the record as it was at the commit (any hash or
// abbreviation of at least 7 digits) for a restore. It fails with ErrNoCommit
// when the commit is not on the tracked branch and with ErrNotInCommit when the
// record did not exist in it.
func (s *Store) RestoreSourceAt(ctx context.Context, collection, id, rev string) (*RestoreSource, error) {
	full, sn, rec, _, err := s.atCommit(ctx, collection, id, rev)
	if err != nil {
		return nil, err
	}
	cfg := s.Config()
	hidden := hideFindings(rec.Data, scanOf(cfg.SecretScanner(), collection, cfg, sn, rec))
	out := &RestoreSource{Commit: full, Data: rec.Data, Hash: ledger.Hash(rec.Data), ID: rec.ID, Hidden: hiddenCount(hidden)}
	out.Visible = dropHidden(hidden).(map[string]any)
	return out, nil
}

// VersionAt describes the record as it was at the commit and how it differs from
// the record today.
func (s *Store) VersionAt(ctx context.Context, collection, id, rev string) (*VersionDetail, error) {
	full, sn, rec, _, err := s.atCommit(ctx, collection, id, rev)
	if err != nil {
		return nil, err
	}
	cfg := s.Config()
	d := &VersionDetail{ID: ledger.SafeID(cfg, collection, rec.ID), Hash: ledger.Hash(rec.Data), Changes: []FieldChange{}}
	hidden := hideFindings(rec.Data, scanOf(cfg.SecretScanner(), collection, cfg, sn, rec))
	d.Hidden = hiddenCount(hidden)
	scrubbed, _ := scrub(hidden)
	d.Data = scrubbed.(map[string]any)
	found := false
	if err := activityLog(ctx, s.repo, full, ActivityQuery{Limit: 1}, nil, "", func(c ActivityCommit) bool {
		d.Commit, found = c, true
		return false
	}); err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNoCommit, rev)
	}
	if cur := s.cur.Load().Collection(collection); cur != nil {
		if now := cur.Get(rec.ID); now != nil || cur.Get(id) != nil {
			if now == nil {
				now = cur.Get(id)
			}
			d.Exists, d.Current = true, now.Hash == d.Hash
			// the secret scan of today's definition, for today's record
			curSn := &snapshot{found: true, col: cur.Collection, ann: secretscan.AnnotationsOf(cur.SchemaRaw)}
			d.Changes, d.MoreChanges = s.diffRecords(collection, cfg, curSn, now, now.Data, sn, rec, rec.Data)
		}
	}
	return d, nil
}
