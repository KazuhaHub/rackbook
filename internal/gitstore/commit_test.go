package gitstore

import (
	"context"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/edit"
)

func TestAuthorAndTrailers(t *testing.T) {
	ann := &auth.Identity{ID: "ann@example.com", Name: "Ann", Email: "Ann@Example.com", Method: auth.MethodOIDC}
	if a := AuthorOf(ann); a != (Identity{"Ann", "Ann@Example.com"}) {
		t.Fatalf("%+v", a)
	}
	// MCPHub: no e-mail, so the author address is the username, plus the client.
	mcp := &auth.Identity{ID: "alice", Name: "Alice", Method: auth.MethodMCPHub, Client: "client-123"}
	if a := AuthorOf(mcp); a != (Identity{"Alice", "alice"}) {
		t.Fatalf("%+v", a)
	}
	got := CommitMessage("ledger(todo): add x", mcp, "rackbook", "todo/x")
	want := "ledger(todo): add x\n\nEdited-by: alice\nEdited-via: rackbook (mcphub, client client-123)\nRecord: todo/x\n"
	if got != want {
		t.Fatalf("\n%q\n%q", got, want)
	}
	// No name: derived from the address; no method: plain via; no record: no trailer.
	if a := AuthorOf(&auth.Identity{ID: "bob@example.com"}); a.Name != "bob" {
		t.Fatalf("%+v", a)
	}
	if m := CommitMessage("s", &auth.Identity{ID: "bob@example.com"}, "rackbook", ""); m != "s\n\nEdited-by: bob@example.com\nEdited-via: rackbook\n" {
		t.Fatalf("%q", m)
	}
	// Anonymous: no author (callers fall back), no Edited-by.
	if !AuthorOf(nil).IsZero() || !AuthorOf(&auth.Identity{}).IsZero() {
		t.Fatal("anonymous must have no author")
	}
	if m := CommitMessage("s", nil, "rackbook", "a/b"); m != "s\n\nEdited-via: rackbook\nRecord: a/b\n" {
		t.Fatalf("%q", m)
	}
	// Values cannot inject trailers or break the author line.
	evil := &auth.Identity{ID: "x\nEdited-by: root", Name: "N <a@b>\n", Client: "c\nRecord: other/x", Method: "m"}
	m := CommitMessage("s", evil, "rackbook", "c/i\nEdited-by: root")
	if strings.Count(m, "\n") != 5 || strings.Contains(m, "\nEdited-by: root") || strings.Contains(m, "\nRecord: other") {
		t.Fatalf("%q", m)
	}
	if a := AuthorOf(evil); strings.ContainsAny(a.Name+a.Email, "<>\n") {
		t.Fatalf("%+v", a)
	}
}

func TestRecordTrailerAndPerRecordHistory(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	add := func(item string) {
		t.Helper()
		if _, err := s.Write(ctx, edit.Op{Kind: edit.Add, Collection: "todo", Data: map[string]any{"item": item, "status": "待办"}}, editor); err != nil {
			t.Fatal(err)
		}
	}
	add("v1.2")
	add("v1x2")
	if _, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	if got := sh(t, e.bare, "log", "-1", "--format=%(trailers:key=Record,valueonly)", "main"); got != "services/web-hostco-ashburn-va-us-dc/SSH" {
		t.Fatalf("Record trailer: %q", got)
	}
	// "." must not act as a regex wildcard, and v1.2 must not match v1.20.
	h, err := s.History(ctx, 10, "todo", "v1.2")
	if err != nil || len(h) != 1 || h[0].Subject != "ledger(todo): add v1.2" {
		t.Fatalf("%v %+v", err, h)
	}
	h, _ = s.History(ctx, 10, "services", "web-hostco-ashburn-va-us-dc/SSH")
	if len(h) != 1 || !strings.Contains(h[0].Subject, "edit web-hostco") {
		t.Fatalf("%+v", h)
	}
	// A record with no trailer commits (or one that never changed) falls back to
	// the collection's file history.
	h, _ = s.History(ctx, 10, "todo", "never-edited")
	if len(h) != 3 || h[2].Subject != "seed" {
		t.Fatalf("fallback should list the todo file's commits: %+v", h)
	}
	if _, err := s.History(ctx, 10, "", "x"); err == nil {
		t.Fatal("id without collection must fail")
	}
	if _, err := s.History(ctx, 10, "nope", "x"); err == nil {
		t.Fatal("unknown collection must fail")
	}
}

func TestLongAndAwkwardIDsKeepAStableTrailer(t *testing.T) {
	e := newEnv(t)
	sh(t, e.server, "config", "grep.patternType", "perl") // must not change how History searches
	s := open(t, e.server, nil)
	ctx := context.Background()
	long := strings.Repeat("x", 150)
	other := strings.Repeat("x", 149) + "y" // same first 100 characters
	ids := []string{long, other, "a+b|(c).*[d]^$"}
	for _, id := range ids {
		if _, err := s.Write(ctx, edit.Op{Kind: edit.Add, Collection: "todo", Data: map[string]any{"item": id, "status": "待办"}}, editor); err != nil {
			t.Fatal(err)
		}
	}
	for i, id := range ids {
		want := edit.RecordRef("todo", id)
		if i < 2 && (len(want) > len("todo/")+100+9 || !strings.Contains(want, "~")) {
			t.Fatalf("long ids must be truncated with a hash: %q", want)
		}
		h, err := s.History(ctx, 10, "todo", id)
		if err != nil || len(h) != 1 {
			t.Fatalf("id %q: %v %+v", id, err, h)
		}
		if got := sh(t, e.bare, "log", "-1", "--format=%(trailers:key=Record,valueonly)", h[0].Hash); got != want {
			t.Fatalf("trailer %q, want the RecordRef value %q", got, want)
		}
	}
	if edit.RecordRef("todo", long) == edit.RecordRef("todo", other) {
		t.Fatal("ids sharing a long prefix must get distinct trailers")
	}
	// A different id that is only a prefix of a real one is not a match: the
	// history falls back to the file's, which has the seed plus the three adds.
	if h, _ := s.History(ctx, 10, "todo", "a+b|(c).*[d]"); len(h) != 4 || h[3].Subject != "seed" {
		t.Fatalf("%+v", h)
	}
}

func TestRecordRefIsOneLine(t *testing.T) {
	if got := edit.RecordRef("todo", "a\nEdited-by: root"); got != "todo/a Edited-by: root" {
		t.Fatalf("%q", got)
	}
}
