package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	for _, content := range []string{"one", "two"} {
		if err := WriteFileAtomic(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != content {
			t.Fatalf("got %q, want %q", b, content)
		}
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Fatalf("temporary files left behind: %v", es)
	}
}

func TestLockIsExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rackbook.lock")
	unlock, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	again, err := Lock(p)
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	again()
}
