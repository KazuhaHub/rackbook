package yamledit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const services = `# 服务端口
# exposure 开放范围

- {device: all, service: Tailscale, port: UDP 41641, exposure: 公网}

# --- gw
- {device: gw, service: SSH, port: TCP 10511}  # keep me
- {device: gw, service: Web 后台, port: TCP 60000}

# --- web
- {device: web, service: SSH, port: TCP 10511, notes: 仅密钥}
- device: web
  service: 网络台账
  port: TCP 443
  managed: true
  notes: >-
    由配置仓库管理；编辑会提交到 Git；
    只有 Access 放行的人能打开
- {device: web, service: STUN, port: UDP 3478}

# --- nas
- {device: nas, service: SMB 共享, port: TCP 445}
`

const networks = `# 网段
tailscale:
  - {range: 100.88.0.0/16, purpose: big}
  - {range: 100.88.0.0/20, purpose: routers}

lan:
  - {range: 192.168.0.0/18, purpose: lan}

docker:
  rule: >-
    Docker rule
    second line
  ranges:
    - {range: 172.16.0.0/16, purpose: web}
    - {range: 172.18.0.0/16, purpose: standby}
`

// changed counts the lines that differ after trimming the common prefix and suffix.
func changed(a, b string) (removed, added []string) {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	i := 0
	for i < len(al) && i < len(bl) && al[i] == bl[i] {
		i++
	}
	j := 0
	for j < len(al)-i && j < len(bl)-i && al[len(al)-1-j] == bl[len(bl)-1-j] {
		j++
	}
	return al[i : len(al)-j], bl[i : len(bl)-j]
}

func records(t *testing.T, src, path string) []any {
	t.Helper()
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	l, err := d.Records(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []any
	for i := range l.Items {
		out = append(out, l.Value(i))
	}
	return out
}

func rec(t *testing.T, src, path string, i int) map[string]any {
	t.Helper()
	return records(t, src, path)[i].(map[string]any)
}

func clone(m map[string]any) map[string]any {
	c := map[string]any{}
	for k, v := range m {
		c[k] = v
	}
	return c
}

func TestSpans(t *testing.T) {
	d, _ := Parse([]byte(services))
	l, err := d.Records("")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 7 {
		t.Fatalf("items: %d", len(l.Items))
	}
	// The block record (index 5) covers 7 lines and stops before the blank line / next record.
	it := l.Items[4]
	got := string(d.Src[it.Start:it.End])
	if !strings.HasPrefix(got, "- device: web\n  service: 网络台账") || !strings.HasSuffix(got, "能打开\n") {
		t.Fatalf("span: %q", got)
	}
	// Trailing group comments are not part of the previous record.
	last := string(d.Src[l.Items[6].Start:l.Items[6].End])
	if last != "- {device: nas, service: SMB 共享, port: TCP 445}\n" {
		t.Fatalf("last: %q", last)
	}
}

func TestNoopEditIsByteIdentical(t *testing.T) {
	files, _ := filepath.Glob("../../examples/homelab/docs/ledger/*.yml")
	if len(files) == 0 {
		t.Fatal("no example files")
	}
	paths := map[string][]string{"networks.yml": {"tailscale", "lan", "docker.ranges"}, "sites.yml": {"sites"}}
	for _, f := range files {
		src, _ := os.ReadFile(f)
		ps := paths[filepath.Base(f)]
		if ps == nil {
			ps = []string{""}
		}
		for _, p := range ps {
			for i, r := range records(t, string(src), p) {
				out, err := Edit(src, p, i, clone(r.(map[string]any)), Opts{})
				if err != nil {
					t.Fatalf("%s %q #%d: %v", f, p, i, err)
				}
				if string(out) != string(src) {
					t.Fatalf("%s %q #%d changed:\n%s", f, p, i, out)
				}
			}
		}
	}
	for i, r := range records(t, services, "") {
		out, err := Edit([]byte(services), "", i, clone(r.(map[string]any)), Opts{})
		if err != nil || string(out) != services {
			t.Fatalf("services #%d: %v\n%s", i, err, out)
		}
	}
}

func TestEditFlowRow(t *testing.T) {
	r := rec(t, services, "", 1)
	r["port"] = "TCP 20000"
	r["exposure"] = "公网 + Tailscale"
	out, err := Edit([]byte(services), "", 1, r, Opts{Order: []string{"device", "service", "port", "exposure", "managed", "notes"}})
	if err != nil {
		t.Fatal(err)
	}
	rm, ad := changed(services, string(out))
	if len(rm) != 1 || len(ad) != 1 {
		t.Fatalf("diff: %q -> %q", rm, ad)
	}
	want := "- {device: gw, service: SSH, port: TCP 20000, exposure: 公网 + Tailscale}  # keep me"
	if ad[0] != want {
		t.Fatalf("got %q", ad[0])
	}
}

func TestEditBlockKeepsFoldedNotes(t *testing.T) {
	r := rec(t, services, "", 4)
	r["port"] = "TCP 8443"
	r["managed"] = false
	out, err := Edit([]byte(services), "", 4, r, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	rm, ad := changed(services, string(out))
	if len(rm) != 2 || len(ad) != 2 {
		t.Fatalf("expected 2 changed lines, got\n%q\n%q", rm, ad)
	}
	if !strings.Contains(string(out), "  notes: >-\n    由配置仓库管理；编辑会提交到 Git；\n    只有 Access 放行的人能打开\n") {
		t.Fatalf("folded notes changed:\n%s", out)
	}
	// Changing the notes themselves re-renders them.
	r = rec(t, services, "", 4)
	r["notes"] = "short"
	out, err = Edit([]byte(services), "", 4, r, Opts{})
	if err != nil || !strings.Contains(string(out), "  notes: short\n- {device: web, service: STUN") {
		t.Fatalf("%v\n%s", err, out)
	}
	// Removing a field.
	r = rec(t, services, "", 4)
	delete(r, "managed")
	out, err = Edit([]byte(services), "", 4, r, Opts{})
	if err != nil || strings.Contains(string(out), "managed") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestEditMultilineValue(t *testing.T) {
	r := rec(t, services, "", 4)
	r["notes"] = "line one\nline two\n"
	out, err := Edit([]byte(services), "", 4, r, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "  notes: |\n    line one\n    line two\n- {device") {
		t.Fatalf("\n%s", out)
	}
	r = rec(t, services, "", 3)
	r["notes"] = "a\nb"
	out, err = Edit([]byte(services), "", 3, r, Opts{})
	if err != nil || !strings.Contains(string(out), `notes: "a\nb"}`) {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestNestedPath(t *testing.T) {
	r := rec(t, networks, "docker.ranges", 1)
	r["purpose"] = "standby: pool"
	out, err := Edit([]byte(networks), "docker.ranges", 1, r, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	rm, ad := changed(networks, string(out))
	if len(rm) != 1 || ad[0] != `    - {range: 172.18.0.0/16, purpose: "standby: pool"}` {
		t.Fatalf("%q %q", rm, ad)
	}
	// Add to the nested list (last list in the file), then to the middle list.
	out, err = Add([]byte(networks), "docker.ranges", map[string]any{"range": "172.20.0.0/16", "purpose": "new"}, Opts{Order: []string{"range", "purpose"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(out), "standby}\n    - {range: 172.20.0.0/16, purpose: new}\n") {
		t.Fatalf("\n%s", out)
	}
	out, err = Add([]byte(networks), "tailscale", map[string]any{"range": "100.88.16.0/20", "purpose": "x"}, Opts{Order: []string{"range", "purpose"}})
	if err != nil {
		t.Fatal(err)
	}
	rm, ad = changed(networks, string(out))
	if len(rm) != 0 || len(ad) != 1 || ad[0] != "  - {range: 100.88.16.0/20, purpose: x}" {
		t.Fatalf("%q %q", rm, ad)
	}
	// Delete the first, middle and last of a nested list.
	for _, idx := range []int{0, 1} {
		out, err = Delete([]byte(networks), "docker.ranges", idx, Opts{})
		if err != nil {
			t.Fatal(err)
		}
		if n := len(records(t, string(out), "docker.ranges")); n != 1 {
			t.Fatalf("left %d", n)
		}
	}
	// The sibling note (a mapping value) is untouched by everything above.
	if !strings.Contains(string(out), "  rule: >-\n    Docker rule\n    second line\n") {
		t.Fatalf("\n%s", out)
	}
}

func TestOnlyElementAndFirstLast(t *testing.T) {
	out, err := Delete([]byte(networks), "lan", 0, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(records(t, string(out), "lan")); n != 0 {
		t.Fatalf("lan not empty: %s", out)
	}
	if !strings.Contains(string(out), "lan:\n\ndocker:") {
		t.Fatalf("\n%s", out)
	}
	single := "- {a: 1}\n"
	out, err = Delete([]byte(single), "", 0, Opts{})
	if err != nil || string(out) != "" {
		t.Fatalf("%v %q", err, out)
	}
	out, err = Add(out, "", map[string]any{"a": "x"}, Opts{})
	if err != nil || string(out) != "- a: x\n" {
		t.Fatalf("%v %q", err, out)
	}
	// File without trailing newline.
	out, err = Add([]byte("- {a: 1}"), "", map[string]any{"a": 2}, Opts{})
	if err != nil || string(out) != "- {a: 1}\n- {a: 2}\n" {
		t.Fatalf("%v %q", err, out)
	}
	// First and last of the services file.
	out, err = Delete([]byte(services), "", 0, Opts{})
	if err != nil || len(records(t, string(out), "")) != 6 {
		t.Fatalf("%v", err)
	}
	out, err = Delete([]byte(services), "", 6, Opts{})
	if err != nil || len(records(t, string(out), "")) != 6 {
		t.Fatalf("%v", err)
	}
}

func TestAddGrouping(t *testing.T) {
	data := map[string]any{"device": "web", "service": "nginx", "port": "TCP 80"}
	order := Opts{GroupField: "device", Order: []string{"device", "service", "port"}}
	out, err := Add([]byte(services), "", data, order)
	if err != nil {
		t.Fatal(err)
	}
	rm, ad := changed(services, string(out))
	if len(rm) != 0 || len(ad) != 1 || ad[0] != "- {device: web, service: nginx, port: TCP 80}" {
		t.Fatalf("%q %q", rm, ad)
	}
	idx := strings.Index(string(out), "service: nginx")
	if idx < strings.Index(string(out), "service: STUN") || idx > strings.Index(string(out), "# --- nas") {
		t.Fatalf("not inserted after the last web record:\n%s", out)
	}
	// Unknown group: appended at the end of the list.
	data["device"] = "new"
	out, err = Add([]byte(services), "", data, order)
	if err != nil || !strings.HasSuffix(string(out), "SMB 共享, port: TCP 445}\n- {device: new, service: nginx, port: TCP 80}\n") {
		t.Fatalf("%v\n%s", err, out)
	}
	// A block-style outlier at the insertion point does not decide the style: the majority does.
	outlier := "- {a: 1}\n- {a: 2}\n- a: 3\n  b: x\n"
	out, err = Add([]byte(outlier), "", map[string]any{"a": 4, "b": "z"}, Opts{Order: []string{"a", "b"}})
	if err != nil || string(out) != outlier+"- {a: 4, b: z}\n" {
		t.Fatalf("%v\n%s", err, out)
	}
	// Adding after a block-style record uses its style and indentation.
	b := "items:\n  - name: a\n    kind: x\n"
	out, err = Add([]byte(b), "items", map[string]any{"name": "b", "kind": "z"}, Opts{Order: []string{"name", "kind"}})
	if err != nil || string(out) != b+"  - name: b\n    kind: z\n" {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestDeleteGroupComment(t *testing.T) {
	g := Opts{GroupField: "device"}
	// The only record of a group takes its "# ---" comment (and one blank line) along.
	out, err := Delete([]byte(services), "", 6, g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "# --- nas") || strings.HasSuffix(string(out), "\n\n") {
		t.Fatalf("\n%s", out)
	}
	// Other records of the group remain: the comment stays.
	out, err = Delete([]byte(services), "", 1, g)
	if err != nil || !strings.Contains(string(out), "# --- gw\n- {device: gw, service: Web") {
		t.Fatalf("%v\n%s", err, out)
	}
	// The first record of the file is its own group but has header comments, not "# ---".
	out, err = Delete([]byte(services), "", 0, g)
	if err != nil || !strings.HasPrefix(string(out), "# 服务端口\n# exposure 开放范围\n") {
		t.Fatalf("%v\n%s", err, out)
	}
	// Middle group: no doubled blank lines.
	out, err = Delete([]byte(services), "", 1+0, Opts{GroupField: "service"})
	if err != nil || strings.Contains(string(out), "\n\n\n") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestQuoting(t *testing.T) {
	cases := []struct {
		val, flow, block string
	}{
		{"plain text", "plain text", "plain text"},
		{"CJK 中文 / slash/名", "CJK 中文 / slash/名", "CJK 中文 / slash/名"},
		{"a: b", `"a: b"`, `"a: b"`},
		{"{braces}", `"{braces}"`, `"{braces}"`},
		{"x # y", `"x # y"`, `"x # y"`},
		{"#lead", `"#lead"`, `"#lead"`},
		{"true", `"true"`, `"true"`},
		{"yes", `"yes"`, `"yes"`},
		{"null", `"null"`, `"null"`},
		{"123", `"123"`, `"123"`},
		{"1.5", `"1.5"`, `"1.5"`},
		{"2026-11-01", `"2026-11-01"`, `"2026-11-01"`},
		{"2001:db8::1", `"2001:db8::1"`, `"2001:db8::1"`},
		{"127.0.0.1:20001", `"127.0.0.1:20001"`, `"127.0.0.1:20001"`},
		{"a, b", `"a, b"`, "a, b"},
		{"- dash", `"- dash"`, `"- dash"`},
		{"-5x", "-5x", "-5x"},
		{"", `""`, `""`},
		{" lead", `" lead"`, `" lead"`},
		{`say "hi"`, `say "hi"`, `say "hi"`},
		{"it's", "it's", "it's"},
		{"tab\there", `"tab\there"`, `"tab\there"`},
		{"*star", `"*star"`, `"*star"`},
		{"TCP 443（nginx → 127.0.0.1:20001）", "TCP 443（nginx → 127.0.0.1:20001）", "TCP 443（nginx → 127.0.0.1:20001）"},
	}
	for _, c := range cases {
		if got := scalar(c.val, true, 0); got != c.flow {
			t.Errorf("flow %q: got %s want %s", c.val, got, c.flow)
		}
		if got := scalar(c.val, false, 0); got != c.block {
			t.Errorf("block %q: got %s want %s", c.val, got, c.block)
		}
	}
	// Everything must round-trip through a real edit, flow and block, as the same string.
	for _, c := range cases {
		for _, base := range []string{"- {k: v, x: 1}\n", "- k: v\n  x: 1\n"} {
			data := map[string]any{"k": c.val, "x": 1}
			out, err := Edit([]byte(base), "", 0, data, Opts{})
			if err != nil {
				t.Errorf("%q in %q: %v", c.val, base, err)
				continue
			}
			if got := rec(t, string(out), "", 0)["k"]; got != c.val {
				t.Errorf("%q round-tripped to %#v", c.val, got)
			}
		}
	}
}

func TestTypedValues(t *testing.T) {
	data := map[string]any{"b": true, "i": 42, "f": 1.5, "n": nil, "l": []any{"a", "b: c"}, "m": map[string]any{"z": 1}, "w": float64(7)}
	for _, base := range []string{"- {k: v}\n", "- k: v\n"} {
		out, err := Edit([]byte(base), "", 0, data, Opts{})
		if err != nil {
			t.Fatal(err)
		}
		got := rec(t, string(out), "", 0)
		if got["b"] != true || got["i"] != 42 || got["f"] != 1.5 || got["n"] != nil || got["w"] != 7 {
			t.Fatalf("%#v\n%s", got, out)
		}
	}
}

func TestKeyWithSpecialCharsAndEmptyDoc(t *testing.T) {
	out, err := Add([]byte("# only a comment\n"), "", map[string]any{"名称": "a/b", "service": "x"}, Opts{Order: []string{"名称", "service"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "# only a comment\n- 名称: a/b\n  service: x\n" {
		t.Fatalf("%q", out)
	}
	if _, err := Add([]byte("a: 1\n"), "missing", map[string]any{"x": 1}, Opts{}); err == nil {
		t.Fatal("expected error adding to a missing list")
	}
	if _, err := Edit([]byte(services), "", 99, map[string]any{}, Opts{}); err == nil {
		t.Fatal("expected out of range")
	}
	if _, err := Parse([]byte("a: [unclosed")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestMultiLineFlowAndCRLFFreeBlankHandling(t *testing.T) {
	src := "- {a: 1,\n   b: 2}\n\n- {a: 3}\n"
	out, err := Edit([]byte(src), "", 0, map[string]any{"a": 1, "b": 5}, Opts{})
	if err != nil || string(out) != "- {a: 1, b: 5}\n\n- {a: 3}\n" {
		t.Fatalf("%v %q", err, out)
	}
}

// TestNoopOnExternalLedger round-trips every record of the YAML files in
// $RACKBOOK_TEST_LEDGER/docs/ledger when that variable is set.
func TestNoopOnExternalLedger(t *testing.T) {
	dir := os.Getenv("RACKBOOK_TEST_LEDGER")
	if dir == "" {
		t.Skip("RACKBOOK_TEST_LEDGER not set")
	}
	paths := map[string][]string{"networks.yml": {"tailscale", "lan", "docker.ranges"}, "sites.yml": {"sites"}}
	files, _ := filepath.Glob(filepath.Join(dir, "docs/ledger/*.yml"))
	n := 0
	for _, f := range files {
		src, _ := os.ReadFile(f)
		ps := paths[filepath.Base(f)]
		if ps == nil {
			ps = []string{""}
		}
		for _, p := range ps {
			for i, r := range records(t, string(src), p) {
				out, err := Edit(src, p, i, clone(r.(map[string]any)), Opts{})
				if err != nil {
					t.Fatalf("%s %q #%d: %v", f, p, i, err)
				}
				if string(out) != string(src) {
					rm, ad := changed(string(src), string(out))
					t.Fatalf("%s %q #%d changed:\n%q\n%q", f, p, i, rm, ad)
				}
				n++
			}
		}
	}
	t.Logf("%d records round-tripped byte-identically", n)
}

func TestMultiDocumentRefusedAndMarkersBoundSpans(t *testing.T) {
	if _, err := Parse([]byte("- {a: 1}\n---\n- {a: 2}\n")); !errors.Is(err, ErrMultiDocument) {
		t.Fatalf("multi-document: %v", err)
	}
	// A trailing document-end marker is not part of the last record.
	src := "- {a: 1}\n- a: 2\n  b: x\n...\n"
	out, err := Edit([]byte(src), "", 1, map[string]any{"a": 3, "b": "x"}, Opts{})
	if err != nil || string(out) != "- {a: 1}\n- a: 3\n  b: x\n...\n" {
		t.Fatalf("%v %q", err, out)
	}
	out, err = Delete([]byte(src), "", 1, Opts{})
	if err != nil || string(out) != "- {a: 1}\n...\n" {
		t.Fatalf("%v %q", err, out)
	}
	// An explicit leading marker is fine.
	if out, err = Add([]byte("---\n- {a: 1}\n"), "", map[string]any{"a": 2}, Opts{}); err != nil || string(out) != "---\n- {a: 1}\n- {a: 2}\n" {
		t.Fatalf("%v %q", err, out)
	}
}

func TestBlockEditKeepsComments(t *testing.T) {
	src := `- name: a  # keep me
  # about b
  b: 1
  c: >-
    folded
    text
  # about d
  d: x  # also keep

- name: z
`
	data := map[string]any{"name": "a2", "b": 2, "c": "short", "d": "w"}
	out, err := Edit([]byte(src), "", 0, data, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	want := `- name: a2  # keep me
  # about b
  b: 2
  c: short
  # about d
  d: w  # also keep

- name: z
`
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestPathErrors(t *testing.T) {
	d, _ := Parse([]byte("a:\n  - {x: 1}\nb: 3\nempty:\n"))
	for _, p := range []string{"missing", "a.nope", "b", "a.x"} {
		if _, err := d.Records(p); !errors.Is(err, ErrPath) {
			t.Errorf("%q: %v", p, err)
		}
	}
	if l, err := d.Records("empty"); err != nil || l.Exists {
		t.Errorf("null value must be an empty list: %v", err)
	}
	empty, _ := Parse([]byte("# nothing\n"))
	if _, err := empty.Records(""); err != nil {
		t.Errorf("empty top-level list: %v", err)
	}
	if _, err := empty.Records("x"); !errors.Is(err, ErrPath) {
		t.Errorf("empty file with a key path: %v", err)
	}
}

func TestDuplicateKeysReported(t *testing.T) {
	d, err := Parse([]byte("- name: a\n  name: b\n- {x: 1, x: 2}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Dups) != 2 || d.Dups[0].Key != "name" || d.Dups[0].Line != 2 || d.Dups[1].Line != 3 {
		t.Fatalf("%+v", d.Dups)
	}
}

func TestCRLFKeepsLineEndings(t *testing.T) {
	src := "# c\r\n- {a: 1}\r\n\r\n- a: 2\r\n  n: >-\r\n    x\r\n    y\r\n  b: 1\r\n"
	check := func(out []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ReplaceAll(string(out), "\r\n", ""), "\n") {
			t.Fatalf("bare LF in %q", out)
		}
	}
	check(Edit([]byte(src), "", 0, map[string]any{"a": 9}, Opts{}))
	check(Edit([]byte(src), "", 1, map[string]any{"a": 2, "n": "x y", "b": 5, "c": "new\nline"}, Opts{}))
	check(Add([]byte(src), "", map[string]any{"a": 3}, Opts{}))
	check(Delete([]byte(src), "", 0, Opts{}))
	out, _ := Edit([]byte(src), "", 1, map[string]any{"a": 2, "n": "x y", "b": 6}, Opts{})
	if !strings.Contains(string(out), "  n: >-\r\n    x\r\n    y\r\n  b: 6\r\n") {
		t.Fatalf("%q", out)
	}
}

func TestBOMIsPreserved(t *testing.T) {
	src := "\xEF\xBB\xBF# c\n- {a: 1}\n- a: 2\n  b: x\n"
	out, err := Edit([]byte(src), "", 0, map[string]any{"a": 5}, Opts{})
	if err != nil || string(out) != "\xEF\xBB\xBF# c\n- {a: 5}\n- a: 2\n  b: x\n" {
		t.Fatalf("%v %q", err, out)
	}
	out, err = Add([]byte(src), "", map[string]any{"a": 3}, Opts{})
	if err != nil || !strings.HasPrefix(string(out), "\xEF\xBB\xBF# c\n") || !strings.HasSuffix(string(out), "- a: 3\n") {
		t.Fatalf("%v %q", err, out)
	}
	out, err = Delete([]byte(src), "", 1, Opts{})
	if err != nil || string(out) != "\xEF\xBB\xBF# c\n- {a: 1}\n" {
		t.Fatalf("%v %q", err, out)
	}
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
}

func TestQuotingRoundTripsEverything(t *testing.T) {
	vals := []string{
		"https://x/d/abc?orgId=1", "https://h.example/a?b=1&c=2#frag", "a:b", "a: b", "a :b", "x#y", "x #y", "#x",
		" lead", "trail ", "-", "- x", "-x", "? x", "?x", "?", ": x", ":x", ":", "@x", "a@b", "`x", "%x", "!x", "!!str x", "*x", "&x", "|", "|x", ">", ">x",
		"{", "{x}", "x}", "[", "[x]", "x]", "a,b", ", x", "a, b", "'q'", `"q"`, `it's`, `say "hi"`, `back\slash`,
		"null", "~", "Null", "yes", "No", "on", "0x1", "1e3", "0o7", "1_000", ".inf", "-.5", "2026-11-17", "12:30", "2001:db8::1", "::1",
		"", "中文，标点：测试", "（括号）：x", "a\tb", "a\nb", "a\x01b", "<<", "---", "--- x", "...", "= x", "key: value: more",
		"TCP 443（nginx → 127.0.0.1:20001）", "https://x/d?a=b c", "x y", "a b",
	}
	for _, v := range vals {
		for _, base := range []string{"- {k: old, n: 1}\n", "- k: old\n  n: 1\n"} {
			out, err := Edit([]byte(base), "", 0, map[string]any{"k": v, "n": 1}, Opts{})
			if err != nil {
				t.Errorf("%q in %q: %v", v, base, err)
				continue
			}
			if got := rec(t, string(out), "", 0); got["k"] != v || got["n"] != 1 {
				t.Errorf("%q round-tripped to %#v in %q", v, got, out)
			}
		}
	}
	// Keys too.
	for _, k := range []string{"a b", "x:y", "? k", "# k", "{k}", "k,l", "名称：", "-", "yes", "- k", "k: v", "'", "", "on", "y", "1", "true", "="} {
		for _, base := range []string{"- {k: old}\n", "- k: old\n"} {
			out, err := Edit([]byte(base), "", 0, map[string]any{k: "v", "z": 2}, Opts{})
			if err != nil {
				t.Errorf("key %q in %q: %v", k, base, err)
				continue
			}
			if got := rec(t, string(out), "", 0); got[k] != "v" || got["z"] != 2 {
				t.Errorf("key %q round-tripped to %#v in %q", k, got, out)
			}
		}
	}
}

// A value ending in blank lines must not become a |+ block: keep chomping would
// absorb the blank line separating it from the next record, breaking later edits.
func TestTrailingBlankLinesValueKeepsFileEditable(t *testing.T) {
	src := "- name: a\n  notes: x\n\n- name: b\n"
	out, err := Edit([]byte(src), "", 0, map[string]any{"name": "a", "notes": "line\n\n"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rec(t, string(out), "", 0); got["notes"] != "line\n\n" {
		t.Fatalf("notes = %#v in %q", got["notes"], out)
	}
	out, err = Add(out, "", map[string]any{"name": "c"}, Opts{})
	if err != nil {
		t.Fatalf("add after it: %v\n%s", err, out)
	}
	out, err = Edit(out, "", 0, map[string]any{"name": "a", "notes": "line\n\n", "x": "1"}, Opts{})
	if err != nil {
		t.Fatalf("edit again: %v\n%s", err, out)
	}
	if got := rec(t, string(out), "", 1); got["name"] != "b" {
		t.Fatalf("record 1 = %#v in %q", got, out)
	}
}

// Line-break characters other than \n inside a value that would be single-quoted
// must be escaped, or line-based span lookups disagree with the YAML parser.
func TestUnicodeLineBreaksStayEscaped(t *testing.T) {
	for _, v := range []string{"say \"hi\"\u2028bye", "a\\b\u0085c", "x\u2029\"y"} {
		out, err := Add([]byte("- {k: a}\n"), "", map[string]any{"k": "b", "v": v}, Opts{})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		out, err = Add(out, "", map[string]any{"k": "c"}, Opts{})
		if err != nil {
			t.Fatalf("%q second add: %v", v, err)
		}
		out, err = Edit(out, "", 2, map[string]any{"k": "c", "n": "1"}, Opts{})
		if err != nil {
			t.Fatalf("%q edit: %v\n%s", v, err, out)
		}
		if got := rec(t, string(out), "", 1); got["v"] != v {
			t.Fatalf("%q round-tripped to %#v", v, got["v"])
		}
	}
}
