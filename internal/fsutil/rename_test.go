package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenameReplacesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Rename(a, b); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(b); string(got) != "new" {
		t.Fatalf("got %q", got)
	}
	if _, err := os.Stat(a); !os.IsNotExist(err) {
		t.Fatalf("source still there: %v", err)
	}
}
