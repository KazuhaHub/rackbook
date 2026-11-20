// Package testutil holds helpers shared by tests.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/config"
)

// RepoRoot finds the module root.
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// CopyExample copies the test ledger into a fresh temp dir and returns it.
//
// The test ledger is testdata/homelab-legacy: examples/homelab as it was before
// configured text became translatable (plain enums with Chinese values, no
// x-rackbook-i18n, no i18n in rackbook.yml). Frozen on purpose: the tests built
// on it pin down behaviour, and it keeps every one of them exercising the
// legacy schema form, which must keep working. examples/homelab itself shows
// the current recommended form and is checked by the example tests.
func CopyExample(t testing.TB) string {
	t.Helper()
	return CopyFixture(t, "homelab-legacy")
}

// CopyFixture copies internal/testutil/testdata/<name> (a small ledger written
// for the tests that must not depend on the example) into a fresh temp dir.
func CopyFixture(t testing.TB, name string) string {
	t.Helper()
	return copyTree(t, filepath.Join(RepoRoot(t), "internal", "testutil", "testdata", name))
}

func copyTree(t testing.TB, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// LoadConfig loads dir/rackbook.yml.
func LoadConfig(t testing.TB, dir string) *config.Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join(dir, config.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Replace edits a file in dir: old must occur exactly once.
func Replace(t testing.TB, dir, rel, old, new string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), old); n != 1 {
		t.Fatalf("%s: %q occurs %d times", rel, old, n)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, new, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Symlink creates a symbolic link or skips the test with an explicit reason
// when the platform or the account cannot (Windows needs a privilege for it).
func Symlink(t testing.TB, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("SKIPPED: cannot create symbolic links here (%s): %v", runtime.GOOS, err)
	}
}

// SkipOnWindows skips the test, saying why, on Windows.
func SkipOnWindows(t testing.TB, why string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED on Windows: " + why)
	}
}
