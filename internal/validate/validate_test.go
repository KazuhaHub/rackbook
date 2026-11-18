package validate_test

import (
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/validate"
)

func run(t *testing.T, dir string) []ledger.Issue {
	t.Helper()
	return validate.Run(ledger.Load(testutil.LoadConfig(t, dir), nil))
}

func expect(t *testing.T, issues []ledger.Issue, rule, collection, contains string) {
	t.Helper()
	for _, i := range issues {
		if i.Rule == rule && i.Collection == collection && strings.Contains(i.Message, contains) {
			return
		}
	}
	t.Fatalf("no %s issue on %s containing %q in %v", rule, collection, contains, issues)
}

func TestExampleIsValid(t *testing.T) {
	if issues := run(t, testutil.CopyExample(t)); len(issues) != 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
}

func TestOldValidatorRules(t *testing.T) {
	const dev = "docs/ledger/devices.yml"
	const svc = "docs/ledger/services.yml"
	const adr = "docs/ledger/addresses.yml"
	cases := []struct {
		name       string
		mutate     func(t *testing.T, dir string)
		rule, coll string
		contains   string
	}{
		{"duplicate device name", func(t *testing.T, d string) {
			testutil.Replace(t, d, dev, "- name: laptop-me-pc\n", "- name: web-hostco-ashburn-va-us-dc\n")
		}, "unique", "devices", "duplicate key"},
		{"service of unknown device", func(t *testing.T, d string) {
			testutil.Replace(t, d, svc, "{device: nas-example-springfield-or-us-home, service: SMB", "{device: nope, service: SMB")
		}, "ref", "services", `unknown devices.name "nope"`},
		{"address of unknown device", func(t *testing.T, d string) {
			testutil.Replace(t, d, adr, "{device: laptop-me-pc, network", "{device: ghost, network")
		}, "ref", "addresses", `"ghost"`},
		{"device all in addresses", func(t *testing.T, d string) {
			testutil.Replace(t, d, adr, "{device: laptop-me-pc, network", "{device: all, network")
		}, "ref", "addresses", `"all"`},
		{"managed flipped on in devices", func(t *testing.T, d string) {
			testutil.Replace(t, d, dev, "  managed: false\n  notes: 站点网关", "  managed: true\n  notes: 站点网关")
		}, "same_set", "devices", "not in inventory/hosts.yml"},
		{"managed flipped off in devices", func(t *testing.T, d string) {
			testutil.Replace(t, d, dev, "  managed: true\n  notes: 主站", "  managed: false\n  notes: 主站")
		}, "same_set", "devices", "has no matching devices record"},
		{"schema: unknown field and wrong type", func(t *testing.T, d string) {
			testutil.Replace(t, d, dev, "  managed: false\n  notes: 站点网关", "  managed: \"no\"\n  color: red\n  notes: 站点网关")
		}, "schema", "devices", ""},
		{"schema: missing required", func(t *testing.T, d string) {
			testutil.Replace(t, d, "docs/ledger/todo.yml", "{item: 统一代理入站端口, scope: web + standby, status: 推迟}", "{item: 统一代理入站端口, scope: web + standby}")
		}, "schema", "todo", "status"},
		{"yaml syntax error", func(t *testing.T, d string) {
			testutil.Replace(t, d, "docs/ledger/ports.yml", "- {service: SSH,", "- {service: SSH")
		}, "yaml", "ports", "ports.yml"},
		{"duplicate service key", func(t *testing.T, d string) {
			testutil.Replace(t, d, svc, "service: Web 后台", "service: SSH")
		}, "unique", "services", "duplicate key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := testutil.CopyExample(t)
			c.mutate(t, dir)
			expect(t, run(t, dir), c.rule, c.coll, c.contains)
		})
	}
}

func TestSchemaErrorPaths(t *testing.T) {
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/devices.yml", "  managed: false\n  notes: 站点网关", "  managed: \"no\"\n  color: red\n  notes: 站点网关")
	var paths []string
	for _, i := range run(t, dir) {
		if i.Rule == "schema" {
			if i.ID != "gw-example-springfield-or-us-home" {
				t.Errorf("id: %q", i.ID)
			}
			paths = append(paths, i.Path)
		}
	}
	joined := strings.Join(paths, ",")
	if !strings.Contains(joined, "/managed") || !strings.Contains(joined, ",") {
		t.Fatalf("paths: %v", paths)
	}
}

func TestExplicitUniqueAndMany(t *testing.T) {
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "rackbook.yml", "rules:\n", "rules:\n  - unique: {collection: devices, fields: [domain]}\n")
	testutil.Replace(t, dir, "docs/ledger/devices.yml", "  domain: standby.vpsco.sanjose.ca.us.vps.example.com", "  domain: web.hostco.ashburn.va.us.dc.example.com")
	expect(t, run(t, dir), "unique", "devices", "duplicate values")
}

func TestIntroduced(t *testing.T) {
	a := []ledger.Issue{{Rule: "ref", Message: "x"}}
	b := []ledger.Issue{{Rule: "ref", Message: "x"}, {Rule: "schema", Message: "y"}}
	got := validate.Introduced(a, b)
	if len(got) != 1 || got[0].Message != "y" {
		t.Fatalf("%v", got)
	}
	if got := validate.Introduced(b, a); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestDuplicateYAMLKeyAndBadPath(t *testing.T) {
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "{item: 评估关闭路由器 WAN 上的 Web 后台, scope: gw, status: 待决定}", "{item: 评估关闭路由器 WAN 上的 Web 后台, scope: gw, status: 待决定, scope: dup}")
	expect(t, run(t, dir), "yaml", "todo", "line 2: duplicate mapping key \"scope\"")

	dir = testutil.CopyExample(t)
	testutil.Replace(t, dir, "rackbook.yml", "    path: tailscale\n", "    path: tailscale.nope\n")
	expect(t, run(t, dir), "config", "tailscale_ranges", "does not exist")
	dir = testutil.CopyExample(t)
	testutil.Replace(t, dir, "rackbook.yml", "    path: tailscale\n", "    path: docker.rule\n")
	expect(t, run(t, dir), "config", "tailscale_ranges", "not a list")
}

func TestMultilineKeyRejected(t *testing.T) {
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "{item: 统一代理入站端口,", `{item: "a\nb",`)
	expect(t, run(t, dir), "schema", "todo", "control characters")
}

func TestIntroducedMatchesByHashForShiftingIDs(t *testing.T) {
	before := []ledger.Issue{{Collection: "c", ID: "#3", Rule: "schema", Path: "/x", Message: "bad", Hash: "h1"}}
	after := []ledger.Issue{{Collection: "c", ID: "#2", Rule: "schema", Path: "/x", Message: "bad", Hash: "h1"}}
	if got := validate.Introduced(before, after); len(got) != 0 {
		t.Fatalf("shifted id must not count as new: %v", got)
	}
	after[0].Hash = "h2"
	if got := validate.Introduced(before, after); len(got) != 1 {
		t.Fatalf("a different record is new: %v", got)
	}
	// Line numbers of yaml issues are not part of the identity.
	b := []ledger.Issue{{Collection: "c", Rule: "yaml", Message: "f.yml: line 4: duplicate mapping key \"a\""}}
	a := []ledger.Issue{{Collection: "c", Rule: "yaml", Message: "f.yml: line 9: duplicate mapping key \"a\""}}
	if got := validate.Introduced(b, a); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestKeyValuesWithDotsOrControlCharsRejected(t *testing.T) {
	for _, bad := range []string{`"."`, `".."`, `"a\u0001b"`, `"a\u007fb"`, `"a\tb"`} {
		dir := testutil.CopyExample(t)
		testutil.Replace(t, dir, "docs/ledger/todo.yml", "{item: 统一代理入站端口,", "{item: "+bad+",")
		expect(t, run(t, dir), "schema", "todo", "control characters")
	}
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "{item: 统一代理入站端口,", "{item: .a..,")
	if issues := run(t, dir); len(issues) != 0 {
		t.Fatalf("dots inside a key are fine: %v", issues)
	}
}
