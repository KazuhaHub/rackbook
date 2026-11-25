package gitstore

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/secretscan"
)

func TestStateFileLabelsAreScannedButPublicKeysAreNot(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	secret := "gh" + "p_" + strings.Repeat("a1B2", 9)
	head := sh(t, e.bare, "rev-parse", "main")
	file := func(name string) []byte {
		return []byte("users:\n  - identity: a@example.com\n    handle: " + strings.Repeat("A", 43) + "\n    credentials:\n      - id: " + strings.Repeat("B", 90) +
			"\n        name: " + name + "\n        public_key: " + strings.Repeat("C", 120) + "\n")
	}
	_, err := s.MutateStateFile(ctx, ".rackbook/passkeys.yml", "rackbook(auth): add passkey", editor, func([]byte, bool) ([]byte, error) { return file(secret), nil })
	var se *secretscan.Error
	if err == nil || !asErr(err, &se) || se.Findings[0].Path != "/users/0/credentials/0/name" {
		t.Fatalf("%v", err)
	}
	if sh(t, e.bare, "rev-parse", "main") != head {
		t.Fatal("a refused state file was committed")
	}
	if _, err := os.Stat(filepath.Join(e.server, ".rackbook", "passkeys.yml")); err == nil {
		t.Fatal("a refused state file was written")
	}
	if _, err := s.MutateStateFile(ctx, ".rackbook/passkeys.yml", "rackbook(auth): add passkey", editor, func([]byte, bool) ([]byte, error) { return file("laptop"), nil }); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledScanWarnsAtStartup(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	for _, c := range []struct {
		yml  string
		warn bool
	}{{"", false}, {"\nsecret_scan:\n  enabled: false\n", true}} {
		e := newEnv(t)
		f, _ := os.OpenFile(filepath.Join(e.server, "rackbook.yml"), os.O_APPEND|os.O_WRONLY, 0o644)
		f.WriteString(c.yml)
		f.Close()
		sh(t, e.server, "commit", "-qam", "cfg", "--allow-empty")
		buf.Reset()
		open(t, e.server, func(o *Options) { o.Logger = slog.New(slog.NewTextHandler(&buf, nil)) })
		if got := strings.Contains(buf.String(), "secret_scan.enabled is false"); got != c.warn {
			t.Fatalf("warn=%v want %v: %s", got, c.warn, buf.String())
		}
	}
}

func asErr(err error, target **secretscan.Error) bool { return errors.As(err, target) }
