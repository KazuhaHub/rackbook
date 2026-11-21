package ansiblerepo

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/secretscan"
)

// Rules are the repository conventions the checks apply. Nothing about a
// particular repository is built in: a group that does not exist switches its
// rule off.
type Rules struct {
	// ManagedGroup lists every host that must have host variables and a
	// secrets file, and every host of any group must be in it (default "managed";
	// "" = no such rule).
	ManagedGroup string
	// AgentGroup, when the inventory has it, must list exactly the hosts of
	// ManagedGroup (default "infra_agent"; "" = no such rule).
	AgentGroup string
	// SecretsFile is where a managed host's SOPS file lives, {host} replaced
	// (default "secrets/{host}.sops.yaml").
	SecretsFile string
}

// DefaultRules are the conventions of the Ansible + SOPS repository layout.
func DefaultRules() Rules {
	return Rules{ManagedGroup: "managed", AgentGroup: "infra_agent", SecretsFile: "secrets/{host}.sops.yaml"}
}

const (
	inventoryFile = "inventory/hosts.yml"
	hostVarsDir   = "inventory/host_vars"
	groupVarsDir  = "inventory/group_vars"
	featuresDir   = "features"
)

func newIssue(code, sev, file, p, msg string, kv ...string) Issue {
	i := Issue{Code: code, Severity: sev, File: file, Path: p, Message: msg}
	if len(kv) > 0 {
		i.Params = map[string]string{}
		for j := 0; j+1 < len(kv); j += 2 {
			i.Params[kv[j]] = kv[j+1]
		}
	}
	return i
}

// parseMapFile parses a YAML file that must be one document whose top level is
// a mapping, with no duplicate keys. An empty file is an empty mapping.
func parseMapFile(file string, b []byte) (*yaml.Node, []Issue) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, []Issue{newIssue("yaml.invalid", SevError, file, "", "not valid YAML: "+firstLine(err.Error()))}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, []Issue{newIssue("yaml.multi_document", SevError, file, "", "more than one YAML document")}
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return nil, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, []Issue{newIssue("yaml.not_mapping", SevError, file, "", "the top level is not a mapping")}
	}
	if iss := dupKeys(file, root, ""); len(iss) > 0 {
		return root, iss
	}
	return root, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func dupKeys(file string, n *yaml.Node, at string) []Issue {
	var out []Issue
	switch n.Kind {
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.ScalarNode && k.Value != "<<" {
				if seen[k.Value] {
					out = append(out, newIssue("yaml.duplicate_key", SevError, file, join(at, k.Value), fmt.Sprintf("the key %q appears twice (line %d)", k.Value, k.Line), "name", k.Value))
				}
				seen[k.Value] = true
			}
			name := k.Value
			out = append(out, dupKeys(file, n.Content[i+1], join(at, name))...)
		}
	case yaml.SequenceNode, yaml.DocumentNode:
		for _, c := range n.Content {
			out = append(out, dupKeys(file, c, at)...)
		}
	}
	return out
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

// mapGet returns the value node of key in a mapping node.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func isNull(n *yaml.Node) bool { return n == nil || (n.Kind == yaml.ScalarNode && n.Tag == "!!null") }

// inventoryGroups is what the checks need from inventory/hosts.yml: the hosts
// listed directly in each group of all.children.
type inventoryGroups struct {
	order []string
	hosts map[string][]string
}

func (g *inventoryGroups) has(group string) bool { _, ok := g.hosts[group]; return ok }

func (g *inventoryGroups) in(group, host string) bool {
	for _, h := range g.hosts[group] {
		if h == host {
			return true
		}
	}
	return false
}

// parseInventoryShape checks the layout all.children.<group>.hosts.<host>.
func parseInventoryShape(b []byte) (*inventoryGroups, []Issue) {
	root, iss := parseMapFile(inventoryFile, b)
	if len(iss) > 0 {
		return nil, iss
	}
	bad := func(p, msg string, kv ...string) []Issue {
		return []Issue{newIssue("inventory.shape", SevError, inventoryFile, p, msg, kv...)}
	}
	all := mapGet(root, "all")
	if all == nil || all.Kind != yaml.MappingNode {
		return nil, bad("all", "the top level must be `all:` with `children:` below it")
	}
	g := &inventoryGroups{hosts: map[string][]string{}}
	var out []Issue
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "all" {
			out = append(out, bad(root.Content[i].Value, "only `all:` may be at the top level of the inventory")...)
		}
	}
	for i := 0; i+1 < len(all.Content); i += 2 {
		switch all.Content[i].Value {
		case "children", "hosts", "vars":
		default:
			out = append(out, bad("all."+all.Content[i].Value, "unknown key under all", "name", all.Content[i].Value)...)
		}
	}
	checkHosts := func(p string, h *yaml.Node) []string {
		if isNull(h) {
			return nil
		}
		if h.Kind != yaml.MappingNode {
			out = append(out, bad(p, "hosts must be a mapping of host names")...)
			return nil
		}
		var names []string
		for j := 0; j+1 < len(h.Content); j += 2 {
			v := h.Content[j+1]
			if !isNull(v) && v.Kind != yaml.MappingNode {
				out = append(out, bad(p+"."+h.Content[j].Value, "a host entry must be empty or a mapping of variables", "host", h.Content[j].Value)...)
			}
			names = append(names, h.Content[j].Value)
		}
		return names
	}
	checkHosts("all.hosts", mapGet(all, "hosts"))
	ch := mapGet(all, "children")
	if ch == nil || (ch.Kind != yaml.MappingNode && !isNull(ch)) {
		return nil, append(out, bad("all.children", "all.children must be a mapping of groups")...)
	}
	for i := 0; ch.Kind == yaml.MappingNode && i+1 < len(ch.Content); i += 2 {
		name, v := ch.Content[i].Value, ch.Content[i+1]
		p := "all.children." + name
		g.order = append(g.order, name)
		g.hosts[name] = nil
		if isNull(v) {
			continue
		}
		if v.Kind != yaml.MappingNode {
			out = append(out, bad(p, "a group must be a mapping", "group", name)...)
			continue
		}
		for j := 0; j+1 < len(v.Content); j += 2 {
			switch v.Content[j].Value {
			case "hosts":
				g.hosts[name] = checkHosts(p+".hosts", v.Content[j+1])
			case "children", "vars":
			default:
				out = append(out, bad(p+"."+v.Content[j].Value, "unknown key in a group", "group", name, "name", v.Content[j].Value)...)
			}
		}
	}
	return g, out
}

func hostVarsPath(t Tree, host string) (string, bool) {
	for _, ext := range []string{".yml", ".yaml"} {
		p := hostVarsDir + "/" + host + ext
		if _, ok := t.Read(p); ok {
			return p, true
		}
	}
	return "", false
}

func hostFileSafe(h string) bool { return hostNameRe.MatchString(h) }

// loadFeature reads and parses features/<name>/feature.yml.
func loadFeature(t Tree, name string) (*FeatureSpec, error) {
	if !ValidFeatureName(name) {
		return nil, fmt.Errorf("not a feature name")
	}
	b, ok := t.Read(featuresDir + "/" + name + "/feature.yml")
	if !ok {
		return nil, fmt.Errorf("no features/%s/feature.yml", name)
	}
	return ParseFeatureSpec(b)
}

// Validate runs every check on the tree and returns all problems it finds,
// sorted. scan may be nil (the default rules).
func Validate(t Tree, rules Rules, scan *secretscan.Scanner) []Issue {
	var out []Issue
	invBytes, ok := t.Read(inventoryFile)
	var inv *inventoryGroups
	if !ok {
		out = append(out, newIssue("inventory.missing", SevError, inventoryFile, "", "inventory/hosts.yml does not exist"))
	} else {
		var iss []Issue
		inv, iss = parseInventoryShape(invBytes)
		out = append(out, iss...)
	}

	specs := map[string]*FeatureSpec{}
	specErr := map[string]error{}
	spec := func(name string) (*FeatureSpec, error) {
		if s, ok := specs[name]; ok || specErr[name] != nil {
			return s, specErr[name]
		}
		s, err := loadFeature(t, name)
		specs[name], specErr[name] = s, err
		return s, err
	}

	for _, dir := range []string{hostVarsDir, groupVarsDir} {
		for _, name := range t.List(dir) {
			if !isYAMLName(name) {
				continue
			}
			file := dir + "/" + name
			b, _ := t.Read(file)
			root, iss := parseMapFile(file, b)
			out = append(out, iss...)
			if len(iss) > 0 {
				continue
			}
			for _, f := range scan.ScanYAML(file, b) {
				sev := SevError
				if f.Tier == secretscan.TierConfirm {
					sev = SevConfirm
				}
				out = append(out, newIssue("secret.found", sev, file, strings.TrimPrefix(strings.ReplaceAll(f.Path, "/", "."), "."),
					"possible secret ("+f.Rule+"): keep secrets in the SOPS files", "rule", f.Rule))
			}
			out = append(out, featureIssues(file, root, spec)...)
		}
	}

	if inv != nil {
		out = append(out, inventoryRuleIssues(t, inv, rules)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Code < b.Code
	})
	return out
}

func featureIssues(file string, root *yaml.Node, spec func(string) (*FeatureSpec, error)) []Issue {
	feats := mapGet(root, "features")
	if feats == nil {
		return nil
	}
	if feats.Kind != yaml.MappingNode {
		return []Issue{newIssue("feature.not_mapping", SevError, file, "features", "features must be a mapping of feature names")}
	}
	var out []Issue
	for i := 0; i+1 < len(feats.Content); i += 2 {
		name, v := feats.Content[i].Value, feats.Content[i+1]
		p := "features." + name
		fs, err := spec(name)
		if err != nil {
			out = append(out, newIssue("feature.unknown", SevError, file, p, "no usable features/"+name+"/feature.yml: "+firstLine(err.Error()), "feature", name))
			continue
		}
		var settings map[string]any
		switch {
		case isNull(v):
		case v.Kind != yaml.MappingNode:
			out = append(out, newIssue("feature.settings_not_mapping", SevError, file, p, "the settings of a feature must be a mapping", "feature", name))
			continue
		default:
			if err := v.Decode(&settings); err != nil {
				out = append(out, newIssue("feature.settings_not_mapping", SevError, file, p, "the settings of a feature must be a mapping with plain values", "feature", name))
				continue
			}
		}
		for _, is := range fs.checkSettings(settings) {
			is.File = file
			is.Message = featureMessage(is)
			out = append(out, is)
		}
	}
	return out
}

func featureMessage(i Issue) string {
	f, s := i.Params["feature"], i.Params["setting"]
	switch i.Code {
	case "feature.unknown_setting":
		return fmt.Sprintf("%s: %s is not a setting of this feature", f, s)
	case "feature.secret_in_vars":
		return fmt.Sprintf("%s: %s is a secret setting; it can only come from the SOPS file", f, s)
	case "feature.bad_value":
		return fmt.Sprintf("%s: the value of %s does not fit its definition (%s: %s)", f, s, i.Params["type"], i.Params["problem"])
	case "feature.missing_required":
		return fmt.Sprintf("%s: %s is required", f, s)
	}
	return i.Code
}

func inventoryRuleIssues(t Tree, inv *inventoryGroups, rules Rules) []Issue {
	var out []Issue
	managed := rules.ManagedGroup
	if managed != "" && inv.has(managed) {
		// every host of every group is managed
		for _, g := range inv.order {
			if g == managed {
				continue
			}
			for _, h := range inv.hosts[g] {
				if !inv.in(managed, h) {
					out = append(out, newIssue("inventory.not_managed", SevError, inventoryFile, "all.children."+g+".hosts."+h,
						fmt.Sprintf("%s is in %s but not in %s", h, g, managed), "host", h, "group", g, "managed", managed))
				}
			}
		}
		// every managed host has variables and a SOPS file
		for _, h := range inv.hosts[managed] {
			if !hostFileSafe(h) {
				continue
			}
			if _, ok := hostVarsPath(t, h); !ok {
				out = append(out, newIssue("inventory.no_host_vars", SevError, hostVarsDir+"/"+h+".yml", "", "managed host "+h+" has no host_vars file", "host", h))
			}
			if rules.SecretsFile != "" {
				sp := strings.ReplaceAll(rules.SecretsFile, "{host}", h)
				if _, ok := t.Read(sp); !ok {
					out = append(out, newIssue("inventory.no_secrets", SevError, sp, "", "managed host "+h+" has no "+path.Base(sp), "host", h))
				}
			}
		}
	}
	if a := rules.AgentGroup; a != "" && managed != "" && inv.has(a) && inv.has(managed) {
		for _, h := range inv.hosts[managed] {
			if !inv.in(a, h) {
				out = append(out, newIssue("inventory.agent_missing", SevError, inventoryFile, "all.children."+a, fmt.Sprintf("%s is managed but not in %s", h, a), "host", h, "group", a))
			}
		}
		for _, h := range inv.hosts[a] {
			if !inv.in(managed, h) {
				out = append(out, newIssue("inventory.agent_extra", SevError, inventoryFile, "all.children."+a+".hosts."+h, fmt.Sprintf("%s is in %s but not managed", h, a), "host", h, "group", a))
			}
		}
	}
	return out
}

// newIssues splits the issues of the edited tree: those the unedited tree did
// not have keep their severity; those it already had become warnings (an edit
// is not blocked by an old problem somewhere else).
func newIssues(before, after []Issue) []Issue {
	had := map[string]bool{}
	for _, i := range before {
		had[i.key()] = true
	}
	out := make([]Issue, 0, len(after))
	for _, i := range after {
		if had[i.key()] {
			i.Severity = SevWarning
		}
		out = append(out, i)
	}
	return out
}

// blocking returns the issues that stop a commit; confirmed lets the
// confirm-tier ones through.
func blocking(issues []Issue, confirmed bool) []Issue {
	var out []Issue
	for _, i := range issues {
		if i.Severity == SevError || (i.Severity == SevConfirm && !confirmed) {
			out = append(out, i)
		}
	}
	return out
}
