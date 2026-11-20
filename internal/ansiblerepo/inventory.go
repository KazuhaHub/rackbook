// Package ansiblerepo reads a clone of an Ansible + SOPS repository: the
// inventory (inventory/hosts.yml), each host's variables
// (inventory/host_vars/<host>.yml) and the commit log. It keeps the clone
// fresh by fetching and resetting it to origin, and never writes to it or to
// its remote. SOPS files are never opened.
package ansiblerepo

import (
	"fmt"
	"regexp"
	"sort"

	"go.yaml.in/yaml/v3"
)

// Host is one inventory host.
type Host struct {
	Name string `json:"name"`
	// Groups are every group the host is in, directly or through a parent
	// group, except the implicit "all".
	Groups []string `json:"groups"`
	// HasVars: inventory/host_vars has a file for the host.
	HasVars bool `json:"hasVars"`
}

var hostNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

type groupDef struct {
	Hosts    map[string]any `yaml:"hosts"`
	Children map[string]any `yaml:"children"`
}

// ParseInventory reads an Ansible YAML inventory. hasVars says whether a host
// has a host_vars file. The result is sorted by host name.
func ParseInventory(data []byte, hasVars func(host string) bool) ([]Host, error) {
	var top map[string]yaml.Node
	if err := yaml.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	direct := map[string][]string{}  // group -> hosts listed in it
	parents := map[string][]string{} // group -> groups that list it as a child
	hosts := map[string]bool{}
	var walk func(name string, n *yaml.Node, depth int) error
	walk = func(name string, n *yaml.Node, depth int) error {
		if depth > 32 {
			return fmt.Errorf("inventory: groups nested too deeply at %q", name)
		}
		var g groupDef
		if n.Kind == 0 || n.Tag == "!!null" {
			return nil
		}
		if err := n.Decode(&g); err != nil {
			return fmt.Errorf("inventory: group %q: %w", name, err)
		}
		for h := range g.Hosts {
			if !hostNameRe.MatchString(h) {
				continue // a range such as web[01:03], or a name that could not be a file name: not listed
			}
			hosts[h] = true
			direct[name] = append(direct[name], h)
		}
		for c, raw := range g.Children {
			parents[c] = append(parents[c], name)
			var node yaml.Node
			if raw != nil {
				if err := node.Encode(raw); err != nil {
					return err
				}
			}
			if err := walk(c, &node, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for name, n := range top {
		n := n
		if err := walk(name, &n, 0); err != nil {
			return nil, err
		}
	}
	member := map[string]map[string]bool{}
	var climb func(host, group string, seen map[string]bool)
	climb = func(host, group string, seen map[string]bool) {
		if seen[group] {
			return
		}
		seen[group] = true
		if group != "all" {
			member[host][group] = true
		}
		for _, p := range parents[group] {
			climb(host, p, seen)
		}
	}
	for g, hs := range direct {
		for _, h := range hs {
			if member[h] == nil {
				member[h] = map[string]bool{}
			}
			climb(h, g, map[string]bool{})
		}
	}
	out := make([]Host, 0, len(hosts))
	for h := range hosts {
		groups := make([]string, 0, len(member[h]))
		for g := range member[h] {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		out = append(out, Host{Name: h, Groups: groups, HasVars: hasVars != nil && hasVars(h)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var secretKeyRe = regexp.MustCompile(`(?i)(secret|token|passw|passphrase|private|credential|api[_-]?key)`)
var secretValueRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----|AGE-SECRET-KEY-|\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}`)

// Hidden replaces a value that may be a secret.
const Hidden = "(hidden)"

func commentSecret(c string) bool {
	return c != "" && (secretValueRe.MatchString(c) || commentAssignRe.MatchString(c))
}

var commentAssignRe = regexp.MustCompile(`(?i)(secret|token|passw|passphrase|private|credential|api[_-]?key)[A-Za-z0-9_-]*\s*[:=]`)

// hide returns the YAML of host variables with secret-looking content hidden
// in place: a scalar under a secret-looking key (also one that key reaches
// through an alias), a scalar that looks like a private key or token, and
// comments that carry either. Host variables are not supposed to hold secrets
// (they live in SOPS files); this is a guard, not the rule. It returns how
// many values and comments it hid.
func hide(doc *yaml.Node) int {
	secretAnchors := map[string]bool{}
	var collect func(n *yaml.Node, under bool)
	collect = func(n *yaml.Node, under bool) {
		switch n.Kind {
		case yaml.AliasNode:
			if under && n.Alias != nil {
				secretAnchors[n.Alias.Anchor] = true
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				collect(n.Content[i+1], under || secretKeyRe.MatchString(n.Content[i].Value))
			}
		default:
			for _, c := range n.Content {
				collect(c, under)
			}
		}
	}
	collect(doc, false)
	return redact(doc, false, secretAnchors)
}

func redact(n *yaml.Node, underSecretKey bool, anchors map[string]bool) int {
	hidden := 0
	for _, c := range []*string{&n.HeadComment, &n.LineComment, &n.FootComment} {
		if commentSecret(*c) {
			*c = "# " + Hidden
			hidden++
		}
	}
	if n.Anchor != "" && anchors[n.Anchor] {
		underSecretKey = true
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			hidden += redact(c, underSecretKey, anchors)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			hidden += redact(n.Content[i], false, anchors)
			hidden += redact(n.Content[i+1], underSecretKey || secretKeyRe.MatchString(n.Content[i].Value), anchors)
		}
	case yaml.ScalarNode:
		if (underSecretKey && n.Value != "" && n.Tag != "!!bool") || secretValueRe.MatchString(n.Value) {
			n.Value, n.Tag, n.Style = Hidden, "!!str", 0
			hidden++
		}
	}
	return hidden
}
