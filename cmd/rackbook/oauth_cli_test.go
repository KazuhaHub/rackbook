package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// The built-in authorization server keeps its grants and its signing key in the
// state directory and names itself by --base-url: it refuses to start without both.
func TestServeBuiltinIssuerNeedsStateDirAndBaseURL(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	b, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, append(b, []byte("\nauth:\n  mcp:\n    resource: http://localhost:8080/mcp\n    builtin_issuer: {enabled: true}\n")...), 0o644)
	state := filepath.Join(t.TempDir(), "state")
	for name, args := range map[string][]string{
		"nothing":        {},
		"no base url":    {"--state-dir", state},
		"no state dir":   {"--base-url", "http://localhost:8080"},
		"base url path":  {"--state-dir", state, "--base-url", "http://localhost:8080/x"},
		"http not local": {"--state-dir", state, "--base-url", "http://ledger.example.com"},
	} {
		_, err := run(t, append([]string{"serve", "--listen", "127.0.0.1:0", "--config", cfg, "--no-git"}, args...)...)
		if err == nil || (!strings.Contains(err.Error(), "--base-url") && !strings.Contains(err.Error(), "--state-dir")) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A second server on the same state directory stops with a clear message.
func TestServeStateDirIsLocked(t *testing.T) {
	t.Parallel()
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := fsutil.Lock(filepath.Join(state, "rackbook.lock"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = run(t, "serve", "--listen", "127.0.0.1:0", "--config", cfg, "--no-git", "--state-dir", state)
	if err == nil || !strings.Contains(err.Error(), "already using --state-dir") {
		t.Fatalf("second server: %v", err)
	}
	unlock()
	// With the lock free the directory can be used again (the run then stops at the TLS flags, after the lock).
	_, err = run(t, "serve", "--listen", "127.0.0.1:0", "--config", cfg, "--no-git", "--state-dir", state, "--tls-cert", "x.pem")
	if err == nil || strings.Contains(err.Error(), "already using") {
		t.Fatalf("after unlock: %v", err)
	}
}

// An existing state directory with loose permissions is made private; if that
// is not possible the built-in server refuses to use it.
func TestSecureStateDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := secureStateDir(dir, true, logger); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if os.Getuid() == 0 {
		t.Skip("root can change any mode")
	}
	// A directory owned by someone else cannot be changed: refused when strict, tolerated otherwise.
	if err := secureStateDir("/", true, logger); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("strict: %v", err)
	}
	if err := secureStateDir("/", false, logger); err != nil {
		t.Fatalf("not strict: %v", err)
	}
}
