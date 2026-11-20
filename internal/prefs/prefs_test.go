package prefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestMemoryOnly(t *testing.T) {
	var s Store
	if got := s.Locale("a@x"); got != "" {
		t.Fatalf("empty store: %q", got)
	}
	if got, err := s.SetLocale("a@x", "en"); err != nil || got != "en-US" {
		t.Fatalf("set: %q %v", got, err)
	}
	if got := s.Locale("a@x"); got != "en-US" {
		t.Fatalf("get: %q", got)
	}
	if got := s.Locale("b@x"); got != "" {
		t.Fatalf("other user: %q", got)
	}
}

func TestSetLocaleTable(t *testing.T) {
	for _, c := range []struct {
		name, id, in, want string
		err                error
	}{
		{"canonical", "a", "zh-TW", "zh-TW", nil},
		{"alias", "a", "zh-hk", "zh-TW", nil},
		{"clear", "a", "", "", nil},
		{"unsupported", "a", "fr-FR", "", ErrInvalidLocale},
		{"garbage", "a", "<script>", "", ErrInvalidLocale},
	} {
		t.Run(c.name, func(t *testing.T) {
			var s Store
			got, err := s.SetLocale(c.id, c.in)
			if !errors.Is(err, c.err) || got != c.want {
				t.Fatalf("got %q, %v; want %q, %v", got, err, c.want, c.err)
			}
			if c.err != nil && s.Locale(c.id) != "" {
				t.Fatal("unsupported value was stored")
			}
		})
	}
	var s Store
	if _, err := s.SetLocale("", "en"); err == nil {
		t.Error("empty identity accepted")
	}
}

func TestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "preferences.json")
	s := &Store{Path: p}
	if _, err := s.SetLocale("a@x", "en-US"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetLocale("b@x", "zh-TW"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	want := `{"version":1,"users":{"a@x":{"locale":"en-US"},"b@x":{"locale":"zh-TW"}}}`
	if string(b) != want {
		t.Fatalf("file = %s", b)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix modes
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	s2 := &Store{Path: p}
	if s2.Locale("a@x") != "en-US" || s2.Locale("b@x") != "zh-TW" {
		t.Fatal("not reloaded")
	}
	if _, err := s2.SetLocale("a@x", ""); err != nil {
		t.Fatal(err)
	}
	if s3 := (&Store{Path: p}); s3.Locale("a@x") != "" || s3.Locale("b@x") != "zh-TW" {
		t.Fatal("clear not persisted")
	}
}

func TestLoadDropsUnsupportedValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "preferences.json")
	os.WriteFile(p, []byte(`{"version":1,"users":{"a":{"locale":"xx"},"b":{"locale":"en"}}}`), 0o600)
	s := &Store{Path: p}
	if s.Locale("a") != "" || s.Locale("b") != "en-US" {
		t.Fatalf("a=%q b=%q", s.Locale("a"), s.Locale("b"))
	}
}

func TestCorruptFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "preferences.json")
	os.WriteFile(p, []byte(`{not json`), 0o600)
	s := &Store{Path: p}
	if s.Locale("a") != "" {
		t.Fatal("corrupt file not treated as empty")
	}
	if b, _ := os.ReadFile(p); string(b) != "{not json" {
		t.Fatalf("file touched by a read: %s", b)
	}
	if _, err := s.SetLocale("a", "en-US"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p + ".corrupt"); string(b) != "{not json" {
		t.Fatalf("corrupt file not kept: %q", b)
	}
	if s2 := (&Store{Path: p}); s2.Locale("a") != "en-US" {
		t.Fatal("new file not written")
	}
}

func TestCap(t *testing.T) {
	var s Store
	for i := 0; i < MaxUsers; i++ {
		if _, err := s.SetLocale(fmt.Sprint("u", i), "en-US"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetLocale("extra", "en-US"); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.SetLocale("u0", "zh-CN"); err != nil {
		t.Fatalf("existing user refused: %v", err)
	}
	if _, err := s.SetLocale("u1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetLocale("extra", "en-US"); err != nil {
		t.Fatalf("after clearing: %v", err)
	}
}

func TestWriteFailureRollsBack(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "missing", "preferences.json")}
	if _, err := s.SetLocale("a", "en-US"); err == nil {
		t.Fatal("expected a write error")
	}
	if s.Locale("a") != "" {
		t.Fatal("not rolled back")
	}
}

func TestConcurrent(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "p.json")}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.SetLocale(fmt.Sprint("u", i), "en-US")
			s.Locale("u0")
		}()
	}
	wg.Wait()
	if s.Locale("u7") != "en-US" {
		t.Fatal("lost write")
	}
}

// A file that exists but cannot be read is not treated as corrupt: nothing is
// written over it, and the store reads it once it becomes readable.
func TestUnreadableFileIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "preferences.json")
	// a directory at the path: ReadFile fails with an error other than "not found"
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Store{Path: path}
	if got := s.Locale("a"); got != "" {
		t.Fatalf("Locale = %q, want empty", got)
	}
	if _, err := s.SetLocale("a", "en-US"); err == nil {
		t.Fatal("SetLocale succeeded while the file could not be read")
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Fatalf("the unreadable path was replaced: %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the unreadable file was moved aside: %v", err)
	}

	// readable again: the saved preferences come back and writes work
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"users":{"b":{"locale":"zh-TW"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.Locale("b"); got != "zh-TW" {
		t.Fatalf("Locale(b) = %q, want zh-TW", got)
	}
	if _, err := s.SetLocale("a", "en-US"); err != nil {
		t.Fatal(err)
	}
	if got := s.Locale("b"); got != "zh-TW" {
		t.Fatalf("after a write, Locale(b) = %q, want zh-TW", got)
	}
}
