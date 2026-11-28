package yamledit

import (
	"errors"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func decodeList(t *testing.T, src, key string) []string {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(src), &m); err != nil {
		t.Fatalf("%v\n%s", err, src)
	}
	var out []string
	roles, _ := m["auth"].(map[string]any)["roles"].(map[string]any)
	if l, ok := roles[key].([]any); ok {
		for _, e := range l {
			out = append(out, e.(string))
		}
	}
	return out
}

const listDoc = `# top comment
name: demo

auth:
  mode: oidc   # how people sign in
  roles:
    # who runs it
    admin: [boss@example.com, "*@ops.example.com"]   # the owners
    editor:
      - tom@team.example.com   # tom
      # the rest of the team
      - "*@team.example.com"

      - zed@team.example.com
    viewer: []
  auditors: [audie@example.com]

# after
other: 1
`

func TestSetStringListBlockAndFlowKeepEverythingElse(t *testing.T) {
	t.Parallel()
	out, err := SetStringList([]byte(listDoc), "auth.roles.editor", []string{"tom@team.example.com", "zed@team.example.com", "new@team.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(listDoc, `      - "*@team.example.com"

      - zed@team.example.com
`, `
      - zed@team.example.com
      - new@team.example.com
`, 1)
	if string(out) != want {
		t.Fatalf("block list:\n%s\nwant:\n%s", out, want)
	}
	// a flow list keeps the quoting of what stays and the comment after the bracket
	out, err = SetStringList([]byte(listDoc), "auth.roles.admin", []string{"*@ops.example.com", "x@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want = strings.Replace(listDoc, `[boss@example.com, "*@ops.example.com"]`, `["*@ops.example.com", x@example.com]`, 1)
	if string(out) != want {
		t.Fatalf("flow list:\n%s", out)
	}
	if got := decodeList(t, string(out), "admin"); strings.Join(got, ",") != "*@ops.example.com,x@example.com" {
		t.Fatal(got)
	}
}

func TestSetStringListEmptiesAndFills(t *testing.T) {
	t.Parallel()
	// a block list emptied becomes `key: []`
	out, err := SetStringList([]byte(listDoc), "auth.roles.editor", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "    editor: []\n    viewer: []\n") || strings.Contains(string(out), "tom@team") {
		t.Fatalf("%s", out)
	}
	// an empty flow list is filled
	out, err = SetStringList([]byte(listDoc), "auth.roles.viewer", []string{"a@b.org"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "    viewer: [a@b.org]\n") {
		t.Fatalf("%s", out)
	}
	// a key with no value
	src := "auth:\n  roles:\n    admin: [a@b.org]\n    viewer:   # nobody yet\n"
	out, err = SetStringList([]byte(src), "auth.roles.viewer", []string{"v@b.org"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "auth:\n  roles:\n    admin: [a@b.org]\n    viewer: [v@b.org]   # nobody yet\n" {
		t.Fatalf("%q", out)
	}
	// a missing key is added at the end of its mapping, before what follows
	out, err = SetStringList([]byte(listDoc), "auth.roles.extra", []string{"q@b.org"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "    viewer: []\n    extra: [q@b.org]\n  auditors:") {
		t.Fatalf("%s", out)
	}
	// ... and the list under auth.auditors is edited like any other
	out, err = SetStringList([]byte(listDoc), "auth.auditors", []string{"audie@example.com", "n@x.org"})
	if err != nil || !strings.Contains(string(out), "  auditors: [audie@example.com, n@x.org]\n") {
		t.Fatalf("%v\n%s", err, out)
	}
	// nothing to do: the same bytes
	out, err = SetStringList([]byte(listDoc), "auth.roles.viewer", nil)
	if err != nil || string(out) != listDoc {
		t.Fatalf("%v", err)
	}
	out, err = SetStringList([]byte(listDoc), "auth.roles.nokey", nil)
	if err != nil || string(out) != listDoc {
		t.Fatalf("%v", err)
	}
}

func TestSetStringListQuotesWhatNeedsIt(t *testing.T) {
	t.Parallel()
	out, err := SetStringList([]byte(listDoc), "auth.roles.editor", []string{"tom@team.example.com", "*@team.example.com", "zed@team.example.com", "*@new.example.com", "group:a1b2", "app-role:Rackbook.Admin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`- "*@new.example.com"`, "- group:a1b2", "- app-role:Rackbook.Admin"} {
		if !strings.Contains(string(out), s) {
			t.Fatalf("%q is missing:\n%s", s, out)
		}
	}
	if got := decodeList(t, string(out), "editor"); len(got) != 6 || got[3] != "*@new.example.com" {
		t.Fatal(got)
	}
	out, err = SetStringList([]byte(listDoc), "auth.roles.admin", []string{"boss@example.com", "*@ops.example.com", "*", "oidc:abc-123"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `[boss@example.com, "*@ops.example.com", "*", `) {
		t.Fatalf("%s", out)
	}
	if got := decodeList(t, string(out), "admin"); strings.Join(got, "|") != "boss@example.com|*@ops.example.com|*|oidc:abc-123" {
		t.Fatal(got)
	}
}

func TestSetStringListRepeatsAndOrder(t *testing.T) {
	t.Parallel()
	// what stays keeps the file's order; additions follow in the order given
	out, err := SetStringList([]byte("a:\n  b: [x, y, z]\n"), "a.b", []string{"z", "nn", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "a:\n  b: [x, z, nn]\n" {
		t.Fatalf("%q", out)
	}
	// repeats are counted
	out, err = SetStringList([]byte("a:\n  b:\n    - x\n    - x\n    - y\n"), "a.b", []string{"x", "yy"})
	if err != nil || string(out) != "a:\n  b:\n    - x\n    - yy\n" {
		t.Fatalf("%v %q", err, out)
	}
}

func TestSetStringListRefusesWhatItCannotKeepIntact(t *testing.T) {
	t.Parallel()
	for name, src := range map[string]string{
		"multi-line flow":      "a:\n  b: [x,\n    y]\n",
		"alias":                "a:\n  b: &l [x]\n  c: *l\n",
		"nested item":          "a:\n  b:\n    - {k: v}\n",
		"number item":          "a:\n  b: [1, 2]\n",
		"not a list":           "a:\n  b: text\n",
		"null written":         "a:\n  b: ~\n",
		"flow parent mapping":  "a: {b: [x]}\n",
		"parent is a scalar":   "a: 1\n",
		"literal block string": "a:\n  b:\n    - |\n      x\n",
	} {
		_, err := SetStringList([]byte(src), "a.b", []string{"q"})
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v (want ErrUnsupported)", name, err)
		}
	}
	if _, err := SetStringList([]byte("a: 1\n"), "nothere.b", []string{"q"}); !errors.Is(err, ErrNoEntry) {
		t.Errorf("%v", err)
	}
	// a document with a byte order mark and CRLF line endings
	out, err := SetStringList([]byte("\xef\xbb\xbfa:\r\n  b: [x]\r\n"), "a.b", []string{"x", "yy"})
	if err != nil || string(out) != "\xef\xbb\xbfa:\r\n  b: [x, yy]\r\n" {
		t.Fatalf("%v %q", err, out)
	}
}

func TestSetStringListWithoutTrailingNewline(t *testing.T) {
	t.Parallel()
	out, err := SetStringList([]byte("a:\n  b:\n    - x"), "a.b", []string{"x", "yy"})
	if err != nil || string(out) != "a:\n  b:\n    - x\n    - yy\n" {
		t.Fatalf("%v %q", err, out)
	}
	out, err = SetStringList([]byte("a:\n  b: [x]"), "a.c", []string{"yy"})
	if err != nil || string(out) != "a:\n  b: [x]\n  c: [yy]\n" {
		t.Fatalf("%v %q", err, out)
	}
}
