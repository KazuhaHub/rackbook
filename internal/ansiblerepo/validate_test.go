package ansiblerepo

import (
	"sort"
	"strings"
	"testing"
)

type memTree map[string]string

func (m memTree) Read(rel string) ([]byte, bool) {
	s, ok := m[rel]
	return []byte(s), ok
}

func (m memTree) List(dir string) []string {
	var out []string
	for p := range m {
		if strings.HasPrefix(p, dir+"/") && !strings.Contains(strings.TrimPrefix(p, dir+"/"), "/") {
			out = append(out, strings.TrimPrefix(p, dir+"/"))
		}
	}
	sort.Strings(out)
	return out
}

const featSpec = `name: demo
description: demo feature
type: package
settings:
  mode: {type: enum, enum: [websocket, listen], default: websocket}
  hub_url: {type: string, required_when: {mode: websocket}, pattern: "https://[a-z.]+"}
  port: {type: int, min: 1, max: 65535}
  verbose: {type: bool, default: false}
  token: {type: string, secret: true, required_when: {mode: websocket}}
  name: {type: string, required: true}
`

const goodInv = `all:
  children:
    managed:
      hosts:
        a:
        b:
    infra_agent:
      hosts:
        a:
        b:
    derp:
      hosts:
        a:
`

func goodTree() memTree {
	return memTree{
		"inventory/hosts.yml":          goodInv,
		"inventory/host_vars/a.yml":    "ip: 1.2.3.4\nfeatures:\n  demo:\n    name: x\n    hub_url: https://hub.example\n",
		"inventory/host_vars/b.yaml":   "ip: 1.2.3.5\n",
		"inventory/group_vars/all.yml": "ntp: pool\n",
		"secrets/a.sops.yaml":          "sops: {}\n",
		"secrets/b.sops.yaml":          "sops: {}\n",
		"features/demo/feature.yml":    featSpec,
		"features/broken/feature.yml":  "settings: [1]\n",
	}
}

func codes(is []Issue) []string {
	var out []string
	for _, i := range is {
		out = append(out, i.Code)
	}
	sort.Strings(out)
	return out
}

func TestValidateGoodTree(t *testing.T) {
	if is := Validate(goodTree(), DefaultRules(), nil); len(is) != 0 {
		t.Fatalf("%+v", is)
	}
}

func TestValidateTable(t *testing.T) {
	cases := []struct {
		name string
		edit func(m memTree)
		want []string // issue codes, sorted
		file string   // the file the first issue names (optional)
	}{
		{"invalid yaml", func(m memTree) { m["inventory/host_vars/b.yaml"] = "a: [1\n" }, []string{"yaml.invalid"}, "inventory/host_vars/b.yaml"},
		{"duplicate key", func(m memTree) { m["inventory/host_vars/b.yaml"] = "a: 1\nb: 2\na: 3\n" }, []string{"yaml.duplicate_key"}, ""},
		{"duplicate nested key", func(m memTree) { m["inventory/host_vars/b.yaml"] = "x:\n  a: 1\n  a: 2\n" }, []string{"yaml.duplicate_key"}, ""},
		{"top level a list", func(m memTree) { m["inventory/host_vars/b.yaml"] = "- 1\n- 2\n" }, []string{"yaml.not_mapping"}, ""},
		{"two documents", func(m memTree) { m["inventory/host_vars/b.yaml"] = "a: 1\n---\nb: 2\n" }, []string{"yaml.multi_document"}, ""},
		{"empty host vars is fine", func(m memTree) { m["inventory/host_vars/b.yaml"] = "" }, nil, ""},
		{"group_vars list", func(m memTree) { m["inventory/group_vars/all.yml"] = "- x\n" }, []string{"yaml.not_mapping"}, ""},
		{"inventory without all", func(m memTree) { m["inventory/hosts.yml"] = "managed:\n  hosts: {}\n" }, []string{"inventory.shape"}, "inventory/hosts.yml"},
		{"inventory group not a mapping", func(m memTree) {
			m["inventory/hosts.yml"] = strings.Replace(goodInv, "    derp:\n      hosts:\n        a:\n", "    derp: [a]\n", 1)
		}, []string{"inventory.shape"}, ""},
		{"inventory hosts a list", func(m memTree) {
			m["inventory/hosts.yml"] = strings.Replace(goodInv, "      hosts:\n        a:\n        b:\n    infra_agent", "      hosts: [a, b]\n    infra_agent", 1)
		}, nil, ""}, // checked below: shape issue plus missing groups; asserted loosely
		{"host in a group but not managed", func(m memTree) {
			m["inventory/hosts.yml"] = goodInv + "    web:\n      hosts:\n        z:\n"
		}, []string{"inventory.not_managed"}, ""},
		{"agent group missing a host", func(m memTree) {
			m["inventory/hosts.yml"] = strings.Replace(goodInv, "    infra_agent:\n      hosts:\n        a:\n        b:\n", "    infra_agent:\n      hosts:\n        a:\n", 1)
		}, []string{"inventory.agent_missing"}, ""},
		{"agent group with an extra host", func(m memTree) {
			m["inventory/hosts.yml"] = strings.Replace(goodInv, "    infra_agent:\n      hosts:\n        a:\n        b:\n", "    infra_agent:\n      hosts:\n        a:\n        b:\n        c:\n", 1)
		}, []string{"inventory.agent_extra", "inventory.not_managed"}, ""},
		{"no agent group = rule off", func(m memTree) {
			m["inventory/hosts.yml"] = "all:\n  children:\n    managed:\n      hosts:\n        a:\n        b:\n"
		}, nil, ""},
		{"managed host without host_vars", func(m memTree) { delete(m, "inventory/host_vars/b.yaml") }, []string{"inventory.no_host_vars"}, ""},
		{"managed host without secrets", func(m memTree) { delete(m, "secrets/b.sops.yaml") }, []string{"inventory.no_secrets"}, "secrets/b.sops.yaml"},
		{"host_vars with .yaml also counts", func(m memTree) {
			m["inventory/host_vars/b.yml"] = m["inventory/host_vars/b.yaml"]
			delete(m, "inventory/host_vars/b.yaml")
		}, nil, ""},
		{"unknown feature", func(m memTree) { m["inventory/host_vars/b.yaml"] = "features:\n  nope: {}\n" }, []string{"feature.unknown"}, ""},
		{"feature with a broken definition", func(m memTree) { m["inventory/host_vars/b.yaml"] = "features:\n  broken: {}\n" }, []string{"feature.unknown"}, ""},
		{"features not a mapping", func(m memTree) { m["inventory/host_vars/b.yaml"] = "features: [demo]\n" }, []string{"feature.not_mapping"}, ""},
		{"feature settings a scalar", func(m memTree) { m["inventory/host_vars/b.yaml"] = "features:\n  demo: 3\n" }, []string{"feature.settings_not_mapping"}, ""},
		{"unknown setting", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, hub_url: 'https://h.example', color: red}\n"
		}, []string{"feature.unknown_setting"}, ""},
		{"enum not listed", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, mode: tcp}\n"
		}, []string{"feature.bad_value"}, ""},
		{"int out of range", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, hub_url: 'https://h.example', port: 70000}\n"
		}, []string{"feature.bad_value"}, ""},
		{"int given a string", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, hub_url: 'https://h.example', port: '80'}\n"
		}, []string{"feature.bad_value"}, ""},
		{"bool given a string", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, hub_url: 'https://h.example', verbose: 'yes'}\n"
		}, []string{"feature.bad_value"}, ""},
		{"pattern mismatch (whole string)", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, hub_url: 'https://h.example/extra'}\n"
		}, []string{"feature.bad_value"}, ""},
		{"template marker", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: '{{ x }}', hub_url: 'https://h.example'}\n"
		}, []string{"feature.bad_value"}, ""},
		{"control character", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: \"a\\nb\", hub_url: 'https://h.example'}\n"
		}, []string{"feature.bad_value"}, ""},
		{"too long", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: " + strings.Repeat("x", 513) + ", hub_url: 'https://h.example'}\n"
		}, []string{"feature.bad_value"}, ""},
		{"missing required", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {hub_url: 'https://h.example'}\n"
		}, []string{"feature.missing_required"}, ""},
		{"required_when through the default", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x}\n" // mode defaults to websocket, so hub_url is required
		}, []string{"feature.missing_required"}, ""},
		{"required_when not met", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, mode: listen}\n"
		}, nil, ""},
		{"secret setting in host_vars", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "features:\n  demo: {name: x, hub_url: 'https://h.example', token: abcdefgh}\n"
		}, []string{"feature.secret_in_vars", "secret.found"}, ""},
		{"private key in host_vars", func(m memTree) {
			m["inventory/host_vars/b.yaml"] = "note: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n  b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n  -----END OPENSSH PRIVATE KEY-----\n"
		}, []string{"secret.found"}, ""},
		{"private key in group_vars", func(m memTree) {
			m["inventory/group_vars/all.yml"] = "k: |\n  -----BEGIN RSA PRIVATE KEY-----\n  MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n  -----END RSA PRIVATE KEY-----\n"
		}, []string{"secret.found"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := goodTree()
			c.edit(m)
			got := codes(Validate(m, DefaultRules(), nil))
			if c.name == "inventory hosts a list" {
				if len(got) == 0 {
					t.Fatal("a hosts list must be refused")
				}
				return
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("got %v, want %v\n%+v", got, c.want, Validate(m, DefaultRules(), nil))
			}
			if c.file != "" {
				if f := Validate(m, DefaultRules(), nil)[0].File; f != c.file {
					t.Errorf("first issue names %q, want %q", f, c.file)
				}
			}
		})
	}
}

func TestValidateRulesAreConfigurable(t *testing.T) {
	m := goodTree()
	delete(m, "secrets/b.sops.yaml")
	if len(Validate(m, Rules{ManagedGroup: "managed"}, nil)) != 0 {
		t.Fatal("no SecretsFile = no secrets rule")
	}
	r := DefaultRules()
	r.SecretsFile = "vault/{host}.enc.yaml"
	got := codes(Validate(m, r, nil))
	if strings.Join(got, ",") != "inventory.no_secrets,inventory.no_secrets" {
		t.Fatalf("%v", got)
	}
	r = DefaultRules()
	r.ManagedGroup = "fleet" // the repository has no such group: nothing is checked against it
	if is := Validate(m, r, nil); len(is) != 0 {
		t.Fatalf("%+v", is)
	}
}

func TestOldProblemsDoNotBlockAnEdit(t *testing.T) {
	before := goodTree()
	delete(before, "secrets/b.sops.yaml") // already broken
	after := goodTree()
	delete(after, "secrets/b.sops.yaml")
	after["inventory/host_vars/b.yaml"] = "ip: 9.9.9.9\n"
	iss := newIssues(Validate(before, DefaultRules(), nil), Validate(after, DefaultRules(), nil))
	if len(blocking(iss, false)) != 0 || len(iss) != 1 || iss[0].Severity != SevWarning {
		t.Fatalf("%+v", iss)
	}
	after["inventory/host_vars/b.yaml"] = "ip: [\n"
	iss = newIssues(Validate(before, DefaultRules(), nil), Validate(after, DefaultRules(), nil))
	if len(blocking(iss, false)) == 0 {
		t.Fatal("a new problem blocks")
	}
}

func TestSecretScanConfirmTier(t *testing.T) {
	m := goodTree()
	m["inventory/host_vars/b.yaml"] = "db_password: hunter2hunter2\n"
	iss := Validate(m, DefaultRules(), nil)
	if len(iss) == 0 {
		t.Fatal("a password in host_vars is found")
	}
	for _, i := range iss {
		if i.Code != "secret.found" || strings.Contains(i.Message, "hunter2") {
			t.Fatalf("%+v", i)
		}
	}
	if len(blocking(iss, false)) == 0 {
		t.Fatal("blocks without a confirmation")
	}
	for _, i := range iss {
		if i.Severity == SevConfirm && len(blocking(iss, true)) != 0 {
			t.Fatalf("a confirmed heuristic finding must pass: %+v", blocking(iss, true))
		}
	}
}

func TestParseFeatureSpec(t *testing.T) {
	f, err := ParseFeatureSpec([]byte(featSpec))
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "demo" || len(f.Settings) != 6 || f.Settings[0].Name != "mode" || f.Settings[4].Name != "token" || !f.Settings[4].Secret {
		t.Fatalf("%+v", f)
	}
	if *f.Settings[2].Min != 1 || *f.Settings[2].Max != 65535 {
		t.Fatalf("%+v", f.Settings[2])
	}
	for _, bad := range []string{"settings: [1]", "settings:\n  a: {type: nope}", "settings:\n  a: {type: string, pattern: '('}", "- x"} {
		if _, err := ParseFeatureSpec([]byte(bad)); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestSettingsFromInput(t *testing.T) {
	f, _ := ParseFeatureSpec([]byte(featSpec))
	f.Name = "demo"
	s, known, iss := f.SettingsFromInput(map[string]any{"name": "x", "port": float64(80), "mode": "", "verbose": true})
	if len(iss) != 0 || len(s) != 3 || s[0].Name != "name" && s[0].Name != "port" {
		t.Fatalf("%+v %+v", s, iss)
	}
	if strings.Join(known, ",") != "mode,hub_url,port,verbose,name" {
		t.Fatalf("secret settings are not controlled by the form: %v", known)
	}
	for _, c := range []struct {
		in   map[string]any
		code string
	}{
		{map[string]any{"token": "abc"}, "feature.secret_refused"},
		{map[string]any{"color": "red"}, "feature.unknown_setting"},
	} {
		if _, _, iss := f.SettingsFromInput(c.in); len(iss) != 1 || iss[0].Code != c.code {
			t.Errorf("%v: %+v", c.in, iss)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	a := "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\n"
	b := "l1\nl2\nL3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\n"
	d := unifiedDiff("f.yml", []byte(a), []byte(b))
	if d.Status != "modified" || !strings.Contains(d.Diff, "-l3\n+L3\n") || !strings.Contains(d.Diff, "+l13\n") || strings.Count(d.Diff, "@@ -") != 2 {
		t.Fatalf("%s", d.Diff)
	}
	if d := unifiedDiff("n.yml", nil, []byte("x\n")); d.Status != "added" || !strings.Contains(d.Diff, "--- /dev/null") {
		t.Fatalf("%+v", d)
	}
	if d := unifiedDiff("n.yml", []byte("x\n"), nil); d.Status != "removed" || !strings.Contains(d.Diff, "-x") {
		t.Fatalf("%+v", d)
	}
	// secret-looking values never appear in a diff
	d = unifiedDiff("v.yml", []byte("api_token: abc123secret\nip: 1\n"), []byte("api_token: zzz999other\nip: 2\n"))
	if strings.Contains(d.Diff, "abc123") || strings.Contains(d.Diff, "zzz999") || !strings.Contains(d.Diff, "api_token: (hidden)") {
		t.Fatalf("%s", d.Diff)
	}
}
