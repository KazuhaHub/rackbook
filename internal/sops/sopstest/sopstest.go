// Package sopstest builds a throw-away SOPS + age setup for tests: three age
// keys (the admin's, the server's and a host's), a .sops.yaml and files
// encrypted with the real sops binary.
package sopstest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Env is a directory with keys.
type Env struct {
	Dir string
	// Sops and AgeKeygen are the binaries.
	Sops, AgeKeygen string
	keys            map[string]string // name -> key file
	pubs            map[string]string
}

// New skips the test when sops or age-keygen is missing, unless
// RACKBOOK_REQUIRE_SOPS is set (CI sets it: there they must be installed).
func New(t *testing.T) *Env {
	t.Helper()
	sp, err1 := exec.LookPath("sops")
	ag, err2 := exec.LookPath("age-keygen")
	if err1 != nil || err2 != nil {
		if os.Getenv("RACKBOOK_REQUIRE_SOPS") != "" {
			t.Fatal("sops and age-keygen must be installed (RACKBOOK_REQUIRE_SOPS is set)")
		}
		t.Skip("sops and age-keygen are not installed")
	}
	e := &Env{Dir: t.TempDir(), Sops: sp, AgeKeygen: ag, keys: map[string]string{}, pubs: map[string]string{}}
	for _, n := range []string{"admin", "server", "host", "other"} {
		kf := filepath.Join(e.Dir, "key-"+n+".txt")
		if out, err := exec.Command(ag, "-o", kf).CombinedOutput(); err != nil {
			t.Fatalf("age-keygen: %v\n%s", err, out)
		}
		out, err := exec.Command(ag, "-y", kf).Output()
		if err != nil {
			t.Fatal(err)
		}
		e.keys[n], e.pubs[n] = kf, strings.TrimSpace(string(out))
	}
	return e
}

// KeyFile is the identity file of a key ("admin", "server", "host", "other").
func (e *Env) KeyFile(name string) string { return e.keys[name] }

// Pub is the recipient of a key.
func (e *Env) Pub(name string) string { return e.pubs[name] }

// Config is a .sops.yaml with one rule per file (rel path -> key names).
func (e *Env) Config(rules map[string][]string) string {
	var files []string
	for f := range rules {
		files = append(files, f)
	}
	sort.Strings(files)
	var sb strings.Builder
	sb.WriteString("creation_rules:\n")
	for _, f := range files {
		var pubs []string
		for _, k := range rules[f] {
			pubs = append(pubs, e.pubs[k])
		}
		sb.WriteString("  - path_regex: ^" + strings.NewReplacer(".", `\.`).Replace(f) + "$\n    age: \"" + strings.Join(pubs, ",") + "\"\n")
	}
	return sb.String()
}

// Encrypt makes the encrypted YAML file rel with the given plain values, as
// the admin, under the rules of conf.
func (e *Env) Encrypt(t *testing.T, conf, rel string, plain string) string {
	t.Helper()
	cf := filepath.Join(e.Dir, ".sops.yaml")
	if err := os.WriteFile(cf, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(e.Sops, "--config", cf, "encrypt", "--filename-override", filepath.Join(e.Dir, filepath.FromSlash(rel)), "--input-type", "json", "--output-type", "yaml")
	cmd.Env = []string{"HOME=" + e.Dir, "SOPS_AGE_KEY_FILE=" + e.keys["admin"]}
	cmd.Stdin = strings.NewReader(plain)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("sops encrypt: %v\n%s", err, errb.String())
	}
	return out.String()
}

// Wrapper writes a script that records every call of sops (its arguments, its
// environment and the content of every file named in the arguments) to log and
// then runs the real one. It returns the script's path.
func (e *Env) Wrapper(t *testing.T, log string) string {
	t.Helper()
	p := filepath.Join(e.Dir, "sops-wrapper")
	script := `#!/bin/sh
{
  echo "ARGV: $*"
  echo "ENV: $(env | sort | tr '\n' ' ')"
  for a in "$@"; do
    if [ -f "$a" ]; then echo "FILE $a:"; cat "$a"; fi
  done
  echo "DIR: $(ls -ld "$(dirname "$(for a in "$@"; do [ -f "$a" ] && echo "$a"; done | head -1)")" 2>/dev/null)"
} >> '` + log + `'
exec '` + e.Sops + `' "$@"
`
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}
