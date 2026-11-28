package ansiblerepo

import (
	"strings"
	"testing"
)

const hv = `# the box
tailscale_ip: 100.64.0.1

# features of this host
features:
  # the agent
  beszel-agent:
    mode: listen   # unix socket
    key: "ssh-ed25519 AAAA"
    run_as_root: true
  other:
    a: 1

after: keep   # trailing
`

func TestSetFeatureKeepsCommentsAndBlankLines(t *testing.T) {
	t.Parallel()
	out, err := SetFeature([]byte(hv), "beszel-agent", true, []Setting{{"mode", "websocket"}, {"key", "ssh-ed25519 AAAA"}, {"hub_url", "https://m.example"}}, []string{"mode", "key", "hub_url", "run_as_root", "listen"})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"# the box\n", "# features of this host\n", "  # the agent\n", "after: keep   # trailing\n", "tailscale_ip: 100.64.0.1\n\n# features", "    mode: websocket", "    hub_url: https://m.example", "  other:\n    a: 1\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "run_as_root") || strings.Contains(got, "listen") {
		t.Errorf("unset settings must go:\n%s", got)
	}
	// only the edited block differs
	if !strings.HasPrefix(got, hv[:strings.Index(hv, "    mode:")]) {
		t.Errorf("text before the block changed:\n%s", got)
	}
	if !strings.HasSuffix(got, "  other:\n    a: 1\n\nafter: keep   # trailing\n") {
		t.Errorf("text after the block changed:\n%s", got)
	}
}

func TestSetFeatureUnchangedValueKeepsItsComment(t *testing.T) {
	t.Parallel()
	out, err := SetFeature([]byte(hv), "beszel-agent", true, []Setting{{"mode", "listen"}, {"key", "ssh-ed25519 AAAA"}, {"run_as_root", true}}, []string{"mode", "key", "run_as_root"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "mode: listen   # unix socket") && !strings.Contains(string(out), "mode: listen # unix socket") {
		t.Errorf("line comment lost:\n%s", out)
	}
}

func TestSetFeatureAddAndRemove(t *testing.T) {
	t.Parallel()
	out, err := SetFeature([]byte(hv), "new-one", true, []Setting{{"x", 3}}, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "  new-one:\n    x: 3\n\nafter:") || !strings.Contains(s, "# the agent") {
		t.Errorf("add:\n%s", s)
	}
	out, err = SetFeature([]byte(hv), "beszel-agent", false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s = string(out)
	if strings.Contains(s, "beszel-agent") || strings.Contains(s, "# the agent") || !strings.Contains(s, "  other:\n    a: 1\n") {
		t.Errorf("remove:\n%s", s)
	}
	// removing the last one removes the section
	out, _ = SetFeature(out, "other", false, nil, nil)
	if strings.Contains(string(out), "features") || !strings.Contains(string(out), "after: keep") {
		t.Errorf("remove last:\n%s", out)
	}
	// no features section: appended
	out, err = SetFeature([]byte("a: 1\n"), "f", true, []Setting{{"s", "v"}}, []string{"s"})
	if err != nil || string(out) != "a: 1\n\nfeatures:\n  f:\n    s: v\n" {
		t.Errorf("append: %v\n%q", err, out)
	}
	out, err = SetFeature(nil, "f", true, nil, nil)
	if err != nil || !strings.Contains(string(out), "features:") {
		t.Errorf("empty file: %v %q", err, out)
	}
}

func TestSetFeatureStringsThatLookLikeOtherTypes(t *testing.T) {
	t.Parallel()
	out, err := SetFeature([]byte("a: 1\n"), "f", true, []Setting{{"s", "true"}, {"n", "123"}, {"w", "yes"}}, []string{"s", "n", "w"})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := yamlUnmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	f := v["features"].(map[string]any)["f"].(map[string]any)
	if f["s"] != "true" || f["n"] != "123" || f["w"] != "yes" {
		t.Errorf("strings must stay strings: %#v\n%s", f, out)
	}
}

func TestSetFeatureFallsBackWhenTheSpliceWouldBeWrong(t *testing.T) {
	t.Parallel()
	// flow style features cannot be spliced; the node edit still keeps the comment
	in := "# top\nfeatures: {a: {x: 1}}\n"
	out, err := SetFeature([]byte(in), "a", true, []Setting{{"x", 2}}, []string{"x"})
	if err != nil || !strings.Contains(string(out), "# top") || !strings.Contains(string(out), "x: 2") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := SetFeature([]byte("features: 3\n"), "a", true, nil, nil); err == nil {
		t.Fatal("a features value that is not a mapping is refused")
	}
}

const inv = `# hosts
all:
  children:
    # the fleet
    managed:
      hosts:
        a:
          ansible_host: 1.1.1.1   # tailnet
        b:
    derp:
      hosts:
        a:

    empty:
`

func TestSetMembership(t *testing.T) {
	t.Parallel()
	out, err := SetMembership([]byte(inv), []MembershipChange{{"b", "derp", true}, {"a", "managed", false}, {"a", "empty", true}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "# the fleet\n") || !strings.Contains(s, "# hosts\n") {
		t.Errorf("comments:\n%s", s)
	}
	m, err := MembershipOf(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Direct["b"], ","); got != "managed,derp" {
		t.Errorf("b: %s", got)
	}
	if got := strings.Join(m.Direct["a"], ","); got != "derp,empty" {
		t.Errorf("a: %s\n%s", got, s)
	}
	if strings.Contains(s, "ansible_host") {
		t.Errorf("a's entry in managed (with its vars) goes with it:\n%s", s)
	}
	// untouched text is byte-identical when the splice applies
	out2, _ := SetMembership([]byte(inv), []MembershipChange{{"b", "derp", true}})
	want := strings.Replace(inv, "    derp:\n      hosts:\n        a:\n", "    derp:\n      hosts:\n        a:\n        b:\n", 1)
	if string(out2) != want {
		t.Errorf("splice:\n%s\nwant\n%s", out2, want)
	}
	// no change = same bytes
	same, _ := SetMembership([]byte(inv), []MembershipChange{{"a", "managed", true}})
	if string(same) != inv {
		t.Error("a no-op changed the file")
	}
	if _, err := SetMembership([]byte(inv), []MembershipChange{{"a", "nogroup", true}}); err == nil {
		t.Error("unknown group")
	}
}

func yamlUnmarshal(b []byte, v any) error { return yamlV3Unmarshal(b, v) }
