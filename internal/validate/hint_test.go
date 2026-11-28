package validate_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

const labelDevices = "data/devices.yml"

func schemaMessages(issues []ledger.Issue) []string {
	var out []string
	for _, i := range issues {
		if i.Rule == "schema" {
			out = append(out, i.Path+" "+i.Message)
		}
	}
	return out
}

func TestLabelFixtureIsValid(t *testing.T) {
	t.Parallel()
	if issues := run(t, testutil.CopyFixture(t, "labels")); len(issues) != 0 {
		t.Fatalf("%v", issues)
	}
}

func TestEnumHints(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, old, new string
		want           []string
	}{
		{"label in the default language", "ipv4_type: static", "ipv4_type: 静态", []string{`/ipv4_type "静态" is not allowed; use code "static"`}},
		{"label in zh-TW", "ipv4_type: dynamic", "ipv4_type: 動態", []string{`/ipv4_type "動態" is not allowed; use code "dynamic"`}},
		{"label in en-US", "ipv4_type: static", "ipv4_type: Static", []string{`/ipv4_type "Static" is not allowed; use code "static"`}},
		{"code in other case", "ipv4_type: static", "ipv4_type: NAT-x", []string{`/ipv4_type "NAT-x" is not one of: static, dynamic, nat`}},
		{"code in capitals", "ipv4_type: static", "ipv4_type: STATIC", []string{`/ipv4_type "STATIC" is not allowed; use code "static"`}},
		{"not a label or code", "ipv4_type: static", "ipv4_type: xyz", []string{`/ipv4_type "xyz" is not one of: static, dynamic, nat`}},
		{"not a string keeps the type message", "ipv4_type: static", "ipv4_type: 5", []string{`/ipv4_type got number, want string`}},
		{"legacy enum: code in other case", "status: up", "status: UP", []string{`/status "UP" is not allowed; use code "up"`}},
		{"legacy enum: unknown", "status: up", "status: sideways", []string{`/status "sideways" is not one of: up, down`}},
		{"array item label", "tags: [core]", "tags: [核心]", []string{`/tags/0 "核心" is not allowed; use code "core"`}},
		{"array item en-US label", "tags: [edge]", "tags: [Edge]", []string{`/tags/0 "Edge" is not allowed; use code "edge"`}},
		{"array item unknown", "tags: [core]", "tags: [core, nope]", []string{`/tags/1 "nope" is not one of: core, edge`}},
		{"row property label", "{proto: tcp, port: 22}", "{proto: 傳輸控制, port: 22}", []string{`/ports/0/proto "傳輸控制" is not allowed; use code "tcp"`}},
		{"row property unknown", "{proto: tcp, port: 22}", "{proto: icmp, port: 22}", []string{`/ports/0/proto "icmp" is not one of: tcp, udp`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := testutil.CopyFixture(t, "labels")
			testutil.Replace(t, dir, labelDevices, c.old, c.new)
			got := schemaMessages(run(t, dir))
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Fatalf("got %q\nwant %q", got, c.want)
			}
		})
	}
}

// Other failures keep their message.
func TestOtherSchemaFailuresKeepTheirMessage(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, labelDevices, "port: 22", "port: abc")
	got := schemaMessages(run(t, dir))
	if len(got) != 1 || !strings.Contains(got[0], "/ports/0/port") || !strings.Contains(got[0], "got string, want integer") {
		t.Fatalf("%q", got)
	}
	dir = testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, labelDevices, "country: US", "country: Narnia")
	got = schemaMessages(run(t, dir))
	if len(got) != 1 || !strings.Contains(got[0], "/country") || !strings.Contains(got[0], "not a country code") {
		t.Fatalf("%q", got)
	}
}

// The custom message is for the property's own enum/oneOf only. An enum in
// if/then or allOf is another list: it keeps the library's message, and the
// code list and hint of the property's own enum are not applied to it.
func TestEnumMessageOnlyForThePropertysOwnKeyword(t *testing.T) {
	t.Parallel()
	mk := func() string {
		dir := testutil.CopyFixture(t, "labels")
		testutil.Replace(t, dir, "schemas/device.json", `"required": ["name"],`, `"required": ["name"],
  "if": {"properties": {"name": {"const": "z"}}, "required": ["name"]},
  "then": {"properties": {"status": {"enum": ["up"]}}},`)
		return dir
	}
	// b is in the property's own list but not in the then-branch's
	dir := mk()
	testutil.Replace(t, dir, labelDevices, "- {name: gw, ipv4_type: static, status: up,", "- {name: z, ipv4_type: static, status: down,")
	got := schemaMessages(run(t, dir))
	if len(got) != 1 || strings.Contains(got[0], "is not one of: up, down") || !strings.Contains(got[0], "'up'") {
		t.Fatalf("then-branch enum must keep the library message: %q", got)
	}
	// the property's own enum still gets its hint, even next to the branch
	dir = mk()
	testutil.Replace(t, dir, labelDevices, "status: up, tags: [core]", "status: DOWN, tags: [core]")
	got = schemaMessages(run(t, dir))
	if len(got) != 1 || got[0] != `/status "DOWN" is not allowed; use code "down"` {
		t.Fatalf("%q", got)
	}
	// both keywords on one property: the codes come from the keyword that failed
	dir = testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, "schemas/device.json", `"title": "IPv4 类型",
      "oneOf"`, `"title": "IPv4 类型",
      "enum": ["static"],
      "oneOf"`)
	got = schemaMessages(run(t, dir))
	if len(got) != 1 || got[0] != `/ipv4_type "dynamic" is not one of: static` {
		t.Fatalf("%q", got)
	}
}

// Property names with a space, non-ASCII letters or a percent sign still get
// the hint: the validator's schema location is percent-encoded.
func TestEnumHintForUnusualPropertyNames(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, "schemas/device.json", `"owner": {"type": "string"}`, `"owner": {"type": "string"},
    "类型": {"type": "string", "oneOf": [{"const": "a", "title": "甲"}]},
    "my field": {"type": "string", "enum": ["a", "b"]},
    "p%20q": {"type": "string", "enum": ["a", "b"]},
    "a/b~c": {"type": "string", "enum": ["a", "b"]}`)
	testutil.Replace(t, dir, labelDevices, "country: US, owner: ann}", `country: US, owner: ann, 类型: 甲, my field: B, "p%20q": A, "a/b~c": B}`)
	got := schemaMessages(run(t, dir))
	want := []string{
		`/a~1b~0c "B" is not allowed; use code "b"`,
		`/my field "B" is not allowed; use code "b"`,
		`/p%20q "A" is not allowed; use code "a"`,
		`/类型 "甲" is not allowed; use code "a"`,
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
