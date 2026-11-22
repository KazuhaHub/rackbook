package gitstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

const miniConfig = `title: t
collections:
  hosts:
    title: Hosts
    file: %FILE%
    schema: schemas/host.json
    key: [name]
    label: name
    list: [name, os]
`

const miniSchema = `{
  "type": "object",
  "required": ["name"],
  "properties": {
    "name": {"type": "string"},
    "os": {"type": "string"},
    "note": {"type": "string"},
    "ports": {"type": "array", "items": {"type": "object", "properties": {"port": {"type": "integer"}, "proto": {"type": "string"}}}},
    "meta": {"type": "object"}
  }
}
`

// mini is a small ledger in its own repository (no remote), with helpers that make
// commits the way a person with push access does and the way Rackbook does.
type mini struct {
	t    *testing.T
	dir  string
	file string // the collection file now
	n    int    // the clock: each commit is a minute after the one before
}

func newMini(t *testing.T) *mini {
	t.Helper()
	m := &mini{t: t, dir: t.TempDir(), file: "data/hosts.yml"}
	sh(t, m.dir, "init", "-b", "main")
	m.put("schemas/host.json", miniSchema)
	m.put("rackbook.yml", strings.ReplaceAll(miniConfig, "%FILE%", m.file))
	m.put(m.file, "")
	m.commit("seed")
	return m
}

func (m *mini) put(rel, body string) {
	m.t.Helper()
	p := filepath.Join(m.dir, rel)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		m.t.Fatal(err)
	}
}

// commit commits everything as somebody else than Rackbook, with the given message.
func (m *mini) commit(msg string) string {
	m.t.Helper()
	m.n++
	when := time.Date(2026, 3, 1, 10, m.n, 0, 0, time.UTC).Format(time.RFC3339)
	sh(m.t, m.dir, "add", "-A")
	cmd := exec.Command("git", "-C", m.dir, "commit", "-q", "-m", msg)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Lap Top", "GIT_AUTHOR_EMAIL=lap@example.com", "GIT_COMMITTER_NAME=Lap Top", "GIT_COMMITTER_EMAIL=lap@example.com",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	if out, err := cmd.CombinedOutput(); err != nil {
		m.t.Fatalf("%v\n%s", err, out)
	}
	return sh(m.t, m.dir, "rev-parse", "HEAD")
}

func (m *mini) store() *Store { return open(m.t, m.dir, nil) }

// writeAt makes the next Rackbook write have a distinct commit date (they are
// all made within the same second otherwise, which orders nothing wrongly but
// keeps tests from noticing a bad order).
func (m *mini) rackbook(s *Store, op edit.Op) string {
	m.t.Helper()
	if _, err := s.Write(context.Background(), op, editor); err != nil {
		m.t.Fatal(err)
	}
	return sh(m.t, m.dir, "rev-parse", "HEAD")
}

func add(name string, extra map[string]any) edit.Op {
	d := map[string]any{"name": name}
	for k, v := range extra {
		d[k] = v
	}
	return edit.Op{Kind: edit.Add, Collection: "hosts", Data: d}
}

func editOf(t *testing.T, s *Store, name string, data map[string]any) edit.Op {
	t.Helper()
	r := s.Ledger().Collection("hosts").Get(name)
	if r == nil {
		t.Fatalf("no record %s", name)
	}
	data["name"] = name
	return edit.Op{Kind: edit.Edit, Collection: "hosts", ID: name, Hash: r.Hash, Data: data}
}

func versions(t *testing.T, s *Store, id string) *VersionPage {
	t.Helper()
	pg, err := s.RecordVersions(context.Background(), VersionQuery{Collection: "hosts", ID: id})
	if err != nil {
		t.Fatal(err)
	}
	return pg
}

func changeOf(v RecordVersion, path string) *FieldChange {
	for i := range v.Changes {
		if v.Changes[i].Path == path {
			return &v.Changes[i]
		}
	}
	return nil
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRecordVersionsHaveFieldLevelDiffs(t *testing.T) {
	m := newMini(t)
	s := m.store()
	m.rackbook(s, add("alpha", map[string]any{"os": "debian", "note": "first", "ports": []any{map[string]any{"port": 22, "proto": "tcp"}, map[string]any{"port": 80, "proto": "tcp"}}}))
	m.rackbook(s, add("other", map[string]any{"os": "alpine"}))
	m.rackbook(s, editOf(t, s, "alpha", map[string]any{"os": "debian", "note": "first", "ports": []any{map[string]any{"port": 22, "proto": "tcp"}, map[string]any{"port": 80, "proto": "udp"}, map[string]any{"port": 443, "proto": "tcp"}}}))
	m.rackbook(s, editOf(t, s, "alpha", map[string]any{"os": "ubuntu", "ports": []any{map[string]any{"port": 22, "proto": "tcp"}, map[string]any{"port": 80, "proto": "udp"}}, "meta": map[string]any{"owner": "ann"}}))

	pg := versions(t, s, "alpha")
	if pg.Mode != ModeRecord || !pg.Done || len(pg.Versions) != 3 || pg.ID != "alpha" {
		t.Fatalf("%+v", pg)
	}
	v3, v2, v1 := pg.Versions[0], pg.Versions[1], pg.Versions[2]
	if v1.Kind != KindCreated || v2.Kind != KindChanged || v3.Kind != KindChanged {
		t.Fatalf("%s %s %s", v1.Kind, v2.Kind, v3.Kind)
	}
	if c := changeOf(v1, "ports"); c == nil || c.Op != "added" {
		t.Fatalf("a created record lists its fields as added: %+v", v1.Changes)
	}
	// nested paths, one entry per leaf; a list longer than before adds an element
	if c := changeOf(v2, "ports[1].proto"); c == nil || c.Op != "changed" || c.Old != "tcp" || c.New != "udp" {
		t.Fatalf("%+v", v2.Changes)
	}
	if c := changeOf(v2, "ports[2]"); c == nil || c.Op != "added" || !strings.Contains(jsonOf(c.New), `"port":443`) {
		t.Fatalf("%+v", v2.Changes)
	}
	if len(v2.Changes) != 2 {
		t.Fatalf("only what changed: %+v", v2.Changes)
	}
	// os changed, note removed, ports[2] removed, meta added as a whole
	if c := changeOf(v3, "os"); c == nil || c.Op != "changed" || c.Old != "debian" || c.New != "ubuntu" {
		t.Fatalf("%+v", v3.Changes)
	}
	if c := changeOf(v3, "note"); c == nil || c.Op != "removed" || c.Old != "first" || c.New != nil {
		t.Fatalf("%+v", v3.Changes)
	}
	if c := changeOf(v3, "ports[2]"); c == nil || c.Op != "removed" {
		t.Fatalf("%+v", v3.Changes)
	}
	if c := changeOf(v3, "meta"); c == nil || c.Op != "added" {
		t.Fatalf("%+v", v3.Changes)
	}
	// commit facts
	if v3.Commit.Author != "Ann Editor" || v3.Commit.EditedBy != "ann@example.com" || v3.Commit.Subject != "ledger(hosts): edit alpha" || v3.Hash == v2.Hash || v3.Commit.Parent != v2.Commit.Hash {
		t.Fatalf("%+v", v3)
	}
	// the other record's commit is not a version of this one
	if vs := versions(t, s, "other").Versions; len(vs) != 1 || vs[0].Kind != KindCreated {
		t.Fatalf("%+v", vs)
	}
}

func TestRecordVersionsPageByWalkPosition(t *testing.T) {
	m := newMini(t)
	s := m.store()
	m.rackbook(s, add("alpha", map[string]any{"os": "a"}))
	for _, os := range []string{"b", "c", "d"} {
		m.rackbook(s, editOf(t, s, "alpha", map[string]any{"os": os}))
	}
	ctx := context.Background()
	p1, err := s.RecordVersions(ctx, VersionQuery{Collection: "hosts", ID: "alpha", Limit: 2})
	if err != nil || len(p1.Versions) != 2 || p1.Done {
		t.Fatalf("%v %+v", err, p1)
	}
	// a commit that lands between the pages changes nothing for the next page
	m.rackbook(s, editOf(t, s, "alpha", map[string]any{"os": "e"}))
	p2, err := s.RecordVersions(ctx, VersionQuery{Collection: "hosts", ID: "alpha", Limit: 2, Tip: p1.Tip, Mode: p1.Mode, Skip: p1.Skip})
	if err != nil || len(p2.Versions) != 2 {
		t.Fatalf("%v %+v", err, p2)
	}
	seen := map[string]bool{}
	for _, v := range append(p1.Versions, p2.Versions...) {
		if seen[v.Commit.Hash] {
			t.Fatal("a version twice")
		}
		seen[v.Commit.Hash] = true
	}
	if len(seen) != 4 {
		t.Fatalf("%+v", p2)
	}
	if p3, err := s.RecordVersions(ctx, VersionQuery{Collection: "hosts", ID: "alpha", Limit: 2, Tip: p2.Tip, Mode: p2.Mode, Skip: p2.Skip}); err != nil || len(p3.Versions) != 0 || !p3.Done {
		t.Fatalf("%v %+v", err, p3)
	}
	for _, q := range []VersionQuery{{Collection: "hosts", ID: "alpha", Tip: "nothex"}, {Collection: "hosts", ID: "alpha", Mode: "nope"}, {Collection: "nope", ID: "x"}, {Collection: "hosts"}} {
		if _, err := s.RecordVersions(ctx, q); err == nil {
			t.Fatalf("%+v accepted", q)
		}
	}
}

// The record is read from the collection file, the config and the type as they
// were at the commit: here the file moved in the very commit that changed it.
func TestRecordVersionReadsThatCommitsFileAndConfig(t *testing.T) {
	m := newMini(t)
	s := m.store()
	m.rackbook(s, add("alpha", map[string]any{"os": "debian"}))
	// a commit by hand that moves the file, renames the collection's file in the
	// config and changes the record, and names the record in its trailer
	sh(t, m.dir, "mv", "data/hosts.yml", "data/machines.yml")
	m.put("rackbook.yml", strings.ReplaceAll(miniConfig, "%FILE%", "data/machines.yml"))
	m.put("data/machines.yml", "- {name: alpha, os: ubuntu}\n")
	m.commit("move and change\n\nRecord: hosts/alpha")
	s2 := m.store()
	pg := versions(t, s2, "alpha")
	if len(pg.Versions) != 2 {
		t.Fatalf("a record found by its trailer is followed across the move of its file: %+v", pg)
	}
	if c := changeOf(pg.Versions[0], "os"); c == nil || c.Old != "debian" || c.New != "ubuntu" || len(pg.Versions[0].Changes) != 1 {
		t.Fatalf("%+v", pg.Versions[0].Changes)
	}
	// and a restore of the version from before the move reads it from the old path
	first := pg.Versions[1].Commit.Hash
	src, err := s2.RestoreSourceAt(context.Background(), "hosts", "alpha", first)
	if err != nil || src.Data["os"] != "debian" || src.Commit != first {
		t.Fatalf("%v %+v", err, src)
	}
}

func TestRecordVersionsFileFallbackDropsCommitsThatDidNotChangeTheRecord(t *testing.T) {
	m := newMini(t)
	m.put(m.file, "- {name: alpha, os: a}\n- {name: beta, os: a}\n")
	c1 := m.commit("add both")
	m.put(m.file, "- {name: alpha, os: a}\n- {name: beta, os: b}\n")
	m.commit("change beta")
	m.put(m.file, "- {name: alpha, os: z}\n- {name: beta, os: b}\n")
	c3 := m.commit("change alpha")
	m.put(m.file, "- {name: alpha, os: z}\n- {name: beta, os: c}\n")
	m.commit("change beta again")
	s := m.store()
	pg := versions(t, s, "alpha")
	if pg.Mode != ModeFile || len(pg.Versions) != 2 || pg.Versions[0].Commit.Hash != c3 || pg.Versions[1].Commit.Hash != c1 {
		t.Fatalf("%+v", pg)
	}
	if pg.Versions[1].Kind != KindCreated {
		t.Fatalf("%+v", pg.Versions[1])
	}
	// the commit that touched only beta is a version of beta, not of alpha
	if vs := versions(t, s, "beta").Versions; len(vs) != 3 {
		t.Fatalf("%d", len(vs))
	}
}

func TestRecordVersionsMarkCreatedDeletedAndRenamed(t *testing.T) {
	m := newMini(t)
	s := m.store()
	m.rackbook(s, add("alpha", map[string]any{"os": "a"}))
	m.rackbook(s, add("beta", map[string]any{"os": "b"}))
	// a rename is an edit of the key field: the position of the record stays
	op := editOf(t, s, "alpha", map[string]any{"os": "a2"})
	op.Data["name"] = "gamma"
	m.rackbook(s, op)
	del := edit.Op{Kind: edit.Delete, Collection: "hosts", ID: "beta", Hash: s.Ledger().Collection("hosts").Get("beta").Hash}
	m.rackbook(s, del)

	g := versions(t, s, "gamma").Versions
	if len(g) != 1 || g[0].Kind != KindRenamed || g[0].RenamedFrom != "alpha" || changeOf(g[0], "os") == nil || changeOf(g[0], "name") == nil || changeOf(g[0], "os").Old != "a" {
		t.Fatalf("%+v", g)
	}
	b := versions(t, s, "beta").Versions
	if len(b) != 2 || b[0].Kind != KindDeleted || b[0].Hash != "" || b[1].Kind != KindCreated {
		t.Fatalf("%+v", b)
	}
	if c := changeOf(b[0], "os"); c == nil || c.Op != "removed" || c.Old != "b" {
		t.Fatalf("a deleted record lists what it had: %+v", b[0].Changes)
	}
}

func TestRecordVersionsHideWhatTheSecretScanFlags(t *testing.T) {
	m := newMini(t)
	const key = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	m.put(m.file, "- {name: alpha, os: a, note: \"token "+key+"\"}\n- {name: \"tok "+key+"\", os: a}\n")
	m.commit("by hand\n\nRecord: hosts/alpha")
	m.put(m.file, "- {name: alpha, os: a, note: \"token "+key+"2\"}\n- {name: \"tok "+key+"\", os: a}\n")
	m.commit("by hand again\n\nRecord: hosts/alpha")
	s := m.store()
	pg := versions(t, s, "alpha")
	if len(pg.Versions) != 2 {
		t.Fatalf("%+v", pg)
	}
	if strings.Contains(jsonOf(pg), key) {
		t.Fatalf("a flagged value is returned: %s", jsonOf(pg))
	}
	c := changeOf(pg.Versions[0], "note")
	if c == nil || c.Op != "changed" || !c.Hidden || c.Old != "(hidden)" || c.New != "(hidden)" {
		t.Fatalf("a change between two hidden values is still a change: %+v", pg.Versions[0].Changes)
	}
	// the record whose key holds a secret shows its redacted id, and is found by it
	var red string
	for _, r := range s.Ledger().Collection("hosts").Records {
		if strings.Contains(r.ID, key) {
			red = r.ID
		}
	}
	if red == "" {
		t.Fatal("no such record")
	}
	shown := ledger.SafeID(s.Config(), "hosts", red)
	if shown == red || strings.Contains(shown, key) {
		t.Fatalf("%q", shown)
	}
	pg2, err := s.RecordVersions(context.Background(), VersionQuery{Collection: "hosts", ID: red})
	if err != nil || pg2.ID != shown || strings.Contains(jsonOf(pg2), key) {
		t.Fatalf("%v %s", err, jsonOf(pg2))
	}
	// what a restore returns to the console leaves the value out too
	src, err := s.RestoreSourceAt(context.Background(), "hosts", "alpha", pg.Versions[1].Commit.Hash)
	if err != nil || src.Hidden != 1 || strings.Contains(jsonOf(src.Visible), key) || src.Data["note"] == nil {
		t.Fatalf("%v %+v", err, src)
	}
	d, err := s.VersionAt(context.Background(), "hosts", "alpha", pg.Versions[1].Commit.Hash)
	if err != nil || strings.Contains(jsonOf(d), key) || d.Hidden != 1 {
		t.Fatalf("%v %s", err, jsonOf(d))
	}
}

func TestVersionAtAndRestoreSourceRefuseWhatIsNotTheRecordsHistory(t *testing.T) {
	m := newMini(t)
	s := m.store()
	m.rackbook(s, add("alpha", map[string]any{"os": "a"}))
	before := sh(t, m.dir, "rev-parse", "HEAD")
	m.rackbook(s, add("beta", map[string]any{"os": "b"}))
	m.rackbook(s, editOf(t, s, "alpha", map[string]any{"os": "c"}))
	ctx := context.Background()
	if _, err := s.RestoreSourceAt(ctx, "hosts", "beta", before); !errors.Is(err, ErrNotInCommit) {
		t.Fatalf("a commit in which the record did not exist: %v", err)
	}
	// a commit that is not on the tracked branch
	sh(t, m.dir, "checkout", "-q", "-b", "side", before)
	m.put("side.txt", "x\n")
	side := m.commit("on the side")
	sh(t, m.dir, "checkout", "-q", "main")
	for _, rev := range []string{side, "HEAD", "nothex", "", "--all", strings.Repeat("0", 40)} {
		if _, err := s.RestoreSourceAt(ctx, "hosts", "alpha", rev); !errors.Is(err, ErrNoCommit) {
			t.Fatalf("%q: %v", rev, err)
		}
	}
	d, err := s.VersionAt(ctx, "hosts", "alpha", before)
	if err != nil || d.Data["os"] != "a" || !d.Exists || d.Current || len(d.Changes) != 1 || d.Changes[0].Old != "c" || d.Changes[0].New != "a" {
		t.Fatalf("what restoring would change goes from today's record to the version: %v %+v", err, d)
	}
	if d.Commit.Subject != "ledger(hosts): add alpha" {
		t.Fatalf("%+v", d.Commit)
	}
}

func TestBlobAtRefusesWhatIsNotAPlainFileOfTheDataDirectory(t *testing.T) {
	m := newMini(t)
	s := m.store()
	head := sh(t, m.dir, "rev-parse", "HEAD")
	ctx := context.Background()
	if b, ok, err := s.repo.blobAt(ctx, head, "rackbook.yml"); err != nil || !ok || !strings.Contains(string(b), "title: t") {
		t.Fatalf("%v %v", ok, err)
	}
	if _, ok, err := s.repo.blobAt(ctx, head, "nope.yml"); err != nil || ok {
		t.Fatalf("a missing file is not an error: %v %v", ok, err)
	}
	for _, rel := range []string{"", ".", "..", "../x", "/etc/passwd", ".rackbook/tokens.yml", ".git/config", "a\nb", "a\x00b", "sub/../../x"} {
		if _, _, err := s.repo.blobAt(ctx, head, rel); err == nil {
			t.Errorf("%q was read", rel)
		}
	}
	for _, rev := range []string{"HEAD", "main", "-x", head[:10], head + ":x", "HEAD^{tree}", ""} {
		if _, _, err := s.repo.blobAt(ctx, rev, "rackbook.yml"); err == nil {
			t.Errorf("%q accepted as a commit", rev)
		}
	}
}

// Deleted records ---------------------------------------------------------------

func deletedIDs(t *testing.T, s *Store) ([]string, bool) {
	t.Helper()
	res, err := s.DeletedRecords(context.Background(), "hosts")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range res.Records {
		ids = append(ids, r.ID)
	}
	return ids, res.Complete
}

func deleteOf(s *Store, name string) edit.Op {
	return edit.Op{Kind: edit.Delete, Collection: "hosts", ID: name, Hash: s.Ledger().Collection("hosts").Get(name).Hash}
}

func TestDeletedRecordsAreThoseWhoseLastChangeRemovedThem(t *testing.T) {
	m := newMini(t)
	s := m.store()
	for _, n := range []string{"alpha", "beta", "gamma", "delta"} {
		m.rackbook(s, add(n, map[string]any{"os": "x"}))
	}
	m.rackbook(s, deleteOf(s, "beta"))
	m.rackbook(s, deleteOf(s, "gamma"))
	m.rackbook(s, add("gamma", map[string]any{"os": "again"})) // deleted and added again: not deleted
	op := editOf(t, s, "delta", map[string]any{"os": "x"})
	op.Data["name"] = "delta2" // renamed: the old id is not a deleted record
	m.rackbook(s, op)
	del := m.rackbook(s, deleteOf(s, "delta2"))
	m.rackbook(s, add("delta2", nil))
	m.rackbook(s, deleteOf(s, "delta2")) // deleted, added and deleted again: once, and the newest deletion

	res, err := s.DeletedRecords(context.Background(), "hosts")
	if err != nil || !res.Complete {
		t.Fatalf("%v %+v", err, res)
	}
	var ids []string
	for _, r := range res.Records {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "delta2,beta" {
		t.Fatalf("%v", ids)
	}
	d := res.Records[0]
	if d.Commit == del || d.Commit != sh(t, m.dir, "rev-parse", "HEAD") || d.Last != sh(t, m.dir, "rev-parse", "HEAD~1") || d.Subject != "ledger(hosts): delete delta2" || d.EditedBy != "ann@example.com" || d.Time.IsZero() {
		t.Fatalf("%+v", d)
	}
	sums, err := s.Summaries(context.Background(), "hosts", res.Records)
	if err != nil || len(sums) != 2 || len(sums[1].Fields) != 2 || sums[1].Fields[0].Field != "name" || sums[1].Fields[0].Value != "beta" || sums[1].Fields[1].Value != "x" {
		t.Fatalf("%v %+v", err, sums)
	}
	// the last version can be read for a restore
	src, err := s.RestoreSourceAt(context.Background(), "hosts", "beta", res.Records[1].Last)
	if err != nil || src.Data["os"] != "x" {
		t.Fatalf("%v %+v", err, src)
	}
}

type countRunner struct{ n *int }

func (c countRunner) Run(ctx context.Context, cmd Cmd) (string, string, error) {
	if len(cmd.Args) > 0 && cmd.Args[0] == "cat-file" {
		*c.n++
	}
	return RealRunner().Run(ctx, cmd)
}

func TestDeletedCacheIsKeptCanBeDeletedAndIsExtendedFromTheLastTip(t *testing.T) {
	m := newMini(t)
	state := filepath.Join(t.TempDir(), "state")
	blobs := 0
	openState := func() *Store {
		return open(t, m.dir, func(o *Options) { o.StateDir = state; o.Runner = countRunner{&blobs} })
	}
	s := openState()
	for _, n := range []string{"a", "b", "c", "d"} {
		m.rackbook(s, add(n, nil))
	}
	m.rackbook(s, deleteOf(s, "a"))
	m.rackbook(s, deleteOf(s, "b"))
	file := filepath.Join(state, "history", "deleted-hosts.json")

	blobs = 0
	if ids, complete := deletedIDs(t, s); strings.Join(ids, ",") != "b,a" || !complete {
		t.Fatalf("%v", ids)
	}
	full := blobs
	if _, err := os.Stat(file); err != nil {
		t.Fatal("no cache file: ", err)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 {
		t.Fatalf("%v", st.Mode())
	}
	if b, _ := os.ReadFile(file); strings.Contains(string(b), "ann@example.com") == false || !strings.Contains(string(b), `"tip"`) {
		t.Fatalf("%s", b)
	}
	// nothing new: nothing is read
	blobs = 0
	deletedIDs(t, s)
	if blobs != 0 {
		t.Fatalf("the cache was not used: %d blobs", blobs)
	}
	// a new commit: only it is read
	m.rackbook(s, deleteOf(s, "c"))
	blobs = 0
	if ids, _ := deletedIDs(t, s); strings.Join(ids, ",") != "c,b,a" {
		t.Fatalf("%v", ids)
	}
	if blobs == 0 || blobs >= full {
		t.Fatalf("an incremental update reads less than a full one: %d against %d", blobs, full)
	}
	// deleting the file is always safe: it is built again, with the same result
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if ids, _ := deletedIDs(t, s); strings.Join(ids, ",") != "c,b,a" {
		t.Fatalf("%v", ids)
	}
	// so is a file that is garbage, or of another collection file
	for _, junk := range []string{"{", `{"version":1,"collection":"hosts","file":"other.yml","tip":"` + strings.Repeat("a", 40) + `","events":[]}`, `{"version":1,"collection":"hosts","file":"data/hosts.yml","tip":"zz","events":[]}`} {
		if err := os.WriteFile(file, []byte(junk), 0o600); err != nil {
			t.Fatal(err)
		}
		if ids, complete := deletedIDs(t, openState()); strings.Join(ids, ",") != "c,b,a" || !complete {
			t.Fatalf("%q: %v", junk, ids)
		}
	}
}

func TestDeletedCacheIsRebuiltWhenTheHistoryWasRewritten(t *testing.T) {
	m := newMini(t)
	state := filepath.Join(t.TempDir(), "state")
	openState := func() *Store { return open(t, m.dir, func(o *Options) { o.StateDir = state }) }
	s := openState()
	for _, n := range []string{"a", "b", "c"} {
		m.rackbook(s, add(n, nil))
	}
	m.rackbook(s, deleteOf(s, "a"))
	m.rackbook(s, deleteOf(s, "b"))
	if ids, _ := deletedIDs(t, s); strings.Join(ids, ",") != "b,a" {
		t.Fatalf("%v", ids)
	}
	// the last commit (the deletion of b) is rewritten into another one
	sh(t, m.dir, "reset", "--hard", "-q", "HEAD~1")
	m.put(m.file, "- {name: b}\n")
	m.commit("by hand: something else")
	s = openState()
	if ids, complete := deletedIDs(t, s); strings.Join(ids, ",") != "c,a" || !complete {
		t.Fatalf("the deletion of b was rewritten away, the hand edit removed c: %v", ids)
	}
}

// The first build of a long history is spread over requests: what is known is
// returned, marked incomplete, and each request goes on.
func TestDeletedBuildIsBudgetedAndResumes(t *testing.T) {
	old := DeletedBudget
	DeletedBudget = 2
	t.Cleanup(func() { DeletedBudget = old })
	m := newMini(t)
	s := m.store() // no state directory: the cache is in memory
	for _, n := range []string{"a", "b", "c", "d"} {
		m.rackbook(s, add(n, nil))
	}
	for _, n := range []string{"a", "b", "c", "d"} {
		m.rackbook(s, deleteOf(s, n))
	}
	// 8 commits to read, 2 at a time: the newest first
	var got []string
	calls := 0
	for {
		calls++
		ids, complete := deletedIDs(t, s)
		got = ids
		if complete {
			break
		}
		if calls > 10 {
			t.Fatal("never completes")
		}
		if calls == 1 && strings.Join(ids, ",") != "d,c" {
			t.Fatalf("the newest first: %v", ids)
		}
	}
	if calls != 5 || strings.Join(got, ",") != "d,c,b,a" {
		t.Fatalf("%d calls: %v", calls, got)
	}
	// a commit that lands in the middle of a build does not disturb it
	m.rackbook(s, add("e", nil))
	if ids, complete := deletedIDs(t, s); !complete || strings.Join(ids, ",") != "d,c,b,a" {
		t.Fatalf("%v %v", ids, complete)
	}
}

func TestDeletedRecordsOfAnUnknownCollectionOrWithoutGit(t *testing.T) {
	m := newMini(t)
	if _, err := m.store().DeletedRecords(context.Background(), "nope"); err == nil {
		t.Fatal("unknown collection")
	}
	s := open(t, m.dir, func(o *Options) { o.NoGit = true })
	if res, err := s.DeletedRecords(context.Background(), "hosts"); err != nil || len(res.Records) != 0 || !res.Complete {
		t.Fatalf("%v %+v", err, res)
	}
}
