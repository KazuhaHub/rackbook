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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/secretscan"
)

// Limits of one RecordVersions call, variables for the tests.
var (
	MaxVersions   = 50   // versions one call returns
	VersionBudget = 1000 // commits one call walks (most are skipped without reading anything)
	// VersionTimeBudget is how long one call works before it ends the page, whatever
	// it has: the cursor goes on from there. It always finishes the commit it is at.
	VersionTimeBudget = 700 * time.Millisecond
	MaxChanges        = 200     // field changes kept for one version
	maxValueBytes     = 8 << 10 // a value longer than this (as JSON) is cut
	maxBlobBytes      = 8 << 20 // the largest file read at a commit
)

// ErrNotInCommit is matched by errors.Is when the record did not exist in the commit.
var ErrNotInCommit = errors.New("the record did not exist in that commit")

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
	// Unreadable says the file is too large, cannot be read or does not parse at
	// that commit (or its parent): nothing is said of the record.
	Unreadable bool `json:"unreadable,omitempty"`
	// Approximate says the commit's rackbook.yml could not be read, so the collection
	// is taken as it is today.
	Approximate bool `json:"approximate,omitempty"`
}

// VersionQuery selects the versions of one record. The caller pages by walk
// position, as for the activity view: Tip pins the commit the walk starts from
// (as a previous page returned it) and Skip is the commits of the walk already
// consumed.
type VersionQuery struct {
	Collection, ID string
	Tip            string
	Skip           int
	Limit          int // at most MaxVersions, 20 when 0
}

// VersionPage is one page of versions, newest first.
type VersionPage struct {
	Tip string
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
// with what changed in the record against the commit's parent. A commit counts when
// it carries the exact Record trailer, or when it changed the collection's file and
// the record's content in it (a hand edit, or one from before the trailer): a
// commit whose file is the very blob of its parent's is not read at all. A page
// walks at most VersionBudget commits and works for at most VersionTimeBudget, so
// Versions may be short or empty while Done is false.
func (s *Store) RecordVersions(ctx context.Context, q VersionQuery) (*VersionPage, error) {
	col, shown, err := s.versionPlan(q.Collection, q.ID)
	if err != nil {
		return nil, err
	}
	pg := &VersionPage{Versions: []RecordVersion{}, Done: true, ID: shown, Skip: q.Skip}
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
	limit := q.Limit
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, MaxVersions)
	rd := s.newSnapReader(ctx, q.Collection)
	budget := min(VersionBudget, MaxActivity)
	start := time.Now()
	consumed, stopped := 0, false
	var inner error
	err = activityLog(ctx, s.repo, tip, ActivityQuery{Skip: q.Skip, Limit: budget, Touch: col.File}, nil, "", func(c ActivityCommit) bool {
		consumed++
		if exact := contains(c.Records, record); exact || c.Touched {
			v, err := rd.version(c, q.ID, exact)
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
		}
		if time.Since(start) > VersionTimeBudget {
			stopped = true
			return false
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
// record is not involved or did not change. named says the commit carries the
// record's own Record trailer; without it the record's content must have changed.
func (rd *snapReader) version(c ActivityCommit, id string, named bool) (*RecordVersion, error) {
	cfg := rd.s.Config()
	ct, err := rd.tree(c.Hash)
	if err != nil {
		return nil, err
	}
	var pt *treeInfo
	if c.Parent != "" {
		if pt, err = rd.tree(c.Parent); err != nil {
			return nil, err
		}
	} else {
		pt = &treeInfo{}
	}
	if ct.found == pt.found && ct.fileBlob == pt.fileBlob {
		return nil, nil // the file is the same blob: the record did not change, and nothing is parsed
	}
	cur, err := rd.at(c.Hash)
	if err != nil {
		return nil, err
	}
	prev, err := rd.at(c.Parent)
	if err != nil {
		return nil, err
	}
	v := &RecordVersion{Commit: c, Kind: KindChanged, Approximate: cur.approximate || prev.approximate}
	if cur.unreadable || prev.unreadable {
		// too large, unreadable or not valid YAML there: nothing can be said, but the commit is named
		if !named {
			return nil, nil
		}
		v.Unreadable, v.Changes = true, []FieldChange{}
		return v, nil
	}
	newRec, oldRec := cur.find(cfg, id), prev.find(cfg, id)
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
	if v.Kind == KindChanged && v.Hash == ledger.Hash(oldRec.Data) && !named {
		return nil, nil
	}
	var from, to map[string]any
	if oldRec != nil {
		from = oldRec.Data
	}
	if newRec != nil {
		to = newRec.Data
	}
	v.Changes, v.MoreChanges = rd.s.diffRecords(rd.coll, cfg, prev, oldRec, from, cur, newRec, to)
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
	a := hideFindings(from, s.findingsOf(coll, fromSn, fromRec))
	b := hideFindings(to, s.findingsOf(coll, toSn, toRec))
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

// findingsOf are the findings that decide which values of a version are hidden: what
// the secret scan flags with the type of the version's own commit, and with today's
// type, and with no type at all (so that a type that exempts a value today or then
// does not make a value visible that a plainer reading flags).
func (s *Store) findingsOf(coll string, sn *snapshot, rec *ledger.Record) []secretscan.Finding {
	if rec == nil || sn == nil {
		return nil
	}
	cfg := s.Config()
	sc := cfg.SecretScanner()
	if !sc.Enabled() {
		return nil
	}
	id := ledger.SafeID(cfg, coll, rec.ID)
	var today secretscan.Annotations
	if c := s.cur.Load().Collection(coll); c != nil {
		today = secretscan.AnnotationsOf(c.SchemaRaw)
	}
	fs := sc.ScanRecordWith(coll, id, rec.Data, sn.ann)
	fs = append(fs, sc.ScanRecordWith(coll, id, rec.Data, today)...)
	return append(fs, sc.ScanRecordWith(coll, id, rec.Data, nil)...)
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
	out, _ := hideAt(data, fs)
	return out
}

// hideAt is hideFindings that also says where the values it hid are, as JSON
// pointers ("" for the record itself, when a secret is in one of its field names).
func hideAt(data map[string]any, fs []secretscan.Finding) (map[string]any, []string) {
	if len(fs) == 0 || data == nil {
		return data, nil
	}
	out := copyValue(data).(map[string]any)
	var paths []string
	seen := map[string]bool{}
	for _, f := range fs {
		segs := pointerSegs(f.Path)
		if len(segs) == 0 {
			// a secret in a field name of the record itself: nothing of it can be shown
			return map[string]any{hiddenText: hiddenValue(data)}, []string{""}
		}
		var at any = out
		hid := false
		for i, seg := range segs {
			last := i == len(segs)-1
			switch x := at.(type) {
			case map[string]any:
				if last {
					if v, ok := x[seg]; ok {
						x[seg], hid = hiddenValue(v), true
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
					x[n], hid = hiddenValue(x[n]), true
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
		if hid && !seen[f.Path] {
			seen[f.Path] = true
			paths = append(paths, f.Path)
		}
	}
	sort.Strings(paths)
	return out, paths
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
	// HiddenPaths are where the left out values were, as JSON pointers: a left out
	// field of a map is missing from Visible and an element of a list is "" there.
	HiddenPaths []string
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
	hidden, paths := hideAt(rec.Data, s.findingsOf(collection, sn, rec))
	out := &RestoreSource{Commit: full, Data: rec.Data, Hash: ledger.Hash(rec.Data), ID: rec.ID, Hidden: len(paths), HiddenPaths: paths}
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
	hidden, hpaths := hideAt(rec.Data, s.findingsOf(collection, sn, rec))
	d.Hidden = len(hpaths)
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
