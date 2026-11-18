package modules

import (
	"os/exec"
	"strings"
	"testing"
)

const mod = "github.com/kazuhahub/rackbook"

// deps lists the packages of this module that pkg imports, directly or not.
func deps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	var own []string
	for _, p := range strings.Fields(string(out)) {
		if p == mod || strings.HasPrefix(p, mod+"/") {
			own = append(own, p)
		}
	}
	return own
}

// The rackbook binary must not contain module code, and a module must reach
// Rackbook only through the public HTTP API, never through internal packages.
func TestBoundary(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("SKIPPED: the go command is not on PATH")
	}
	for _, p := range deps(t, mod+"/cmd/rackbook") {
		if strings.HasPrefix(p, mod+"/modules") || strings.HasPrefix(p, mod+"/cmd/rackbook-") {
			t.Errorf("cmd/rackbook imports module code: %s", p)
		}
	}
	for _, m := range []string{"cmd/rackbook-entra", "cmd/rackbook-notify"} {
		for _, p := range deps(t, mod+"/"+m) {
			if strings.HasPrefix(p, mod+"/internal") || p == mod+"/web" {
				t.Errorf("%s imports %s; modules use only the public HTTP API", m, p)
			}
		}
	}
}
