package sops_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/sops"
	"github.com/kazuhahub/rackbook/internal/sops/sopstest"
)

func setup(t *testing.T) (*sopstest.Env, *sops.Runner, string, string) {
	t.Helper()
	e := sopstest.New(t)
	conf := e.Config(map[string][]string{"secrets/a.sops.yaml": {"admin", "server", "host"}, "secrets/b.sops.yaml": {"admin", "host"}})
	enc := e.Encrypt(t, conf, "secrets/a.sops.yaml", `{"feature_x-y_token":"first-value"}`)
	tmp := t.TempDir()
	r, err := sops.New(context.Background(), sops.Options{KeyFile: e.KeyFile("server"), Sops: e.Sops, AgeKeygen: e.AgeKeygen, Tmp: tmp})
	if err != nil {
		t.Fatal(err)
	}
	return e, r, enc, tmp
}

func TestRoundTrip(t *testing.T) {
	e, r, enc, tmp := setup(t)
	ctx := context.Background()
	if r.PublicKey() != e.Pub("server") {
		t.Fatalf("public key %q", r.PublicKey())
	}
	v, err := r.Decrypt(ctx, []byte(enc), "feature_x-y_token")
	if err != nil || strings.TrimSpace(string(v)) != "first-value" {
		t.Fatalf("%q %v", v, err)
	}
	// a multi-line value survives
	next, err := r.Set(ctx, []byte(enc), "pem_key", "line1\nline2")
	if err != nil {
		t.Fatal(err)
	}
	v, _ = r.Decrypt(ctx, next, "pem_key")
	if string(v) != "line1\nline2" {
		t.Fatalf("%q", v)
	}
	if strings.Contains(string(next), "line1") || strings.Contains(string(next), "first-value") {
		t.Fatal("plaintext in the file")
	}
	next, err = r.Unset(ctx, next, "pem_key")
	if err != nil || strings.Contains(string(next), "pem_key") {
		t.Fatalf("%v", err)
	}
	if _, err := r.Decrypt(ctx, next, "pem_key"); !errors.Is(err, sops.ErrNoKey) {
		t.Fatalf("a missing key: %v", err)
	}
	// a file the key is no recipient of
	other := e.Encrypt(t, e.Config(map[string][]string{"secrets/b.sops.yaml": {"admin", "host"}}), "secrets/b.sops.yaml", `{"k":"v"}`)
	if _, err := r.Decrypt(ctx, []byte(other), "k"); !errors.Is(err, sops.ErrCannotDecrypt) {
		t.Fatalf("not a recipient: %v", err)
	}
	// a new file takes its recipients from the rule
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(e.Config(map[string][]string{"secrets/a.sops.yaml": {"admin", "server"}})), 0o600); err != nil {
		t.Fatal(err)
	}
	made, err := r.Encrypt(ctx, dir, "secrets/a.sops.yaml", "new_key", "new-value")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := r.Decrypt(ctx, made, "new_key"); strings.TrimSpace(string(v)) != "new-value" || !strings.Contains(string(made), e.Pub("admin")) || strings.Contains(string(made), e.Pub("host")) {
		t.Fatalf("%q\n%s", v, made)
	}
	if _, err := r.Encrypt(ctx, dir, "secrets/zzz.sops.yaml", "k", "v"); err == nil {
		t.Fatal("no creation rule matches: it must fail")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("scratch left behind: %v", left)
	}
}

// A value is never an argument, never in a file handed to sops, and the child
// has nothing of the parent's environment but the key file.
func TestNoValueInArgvFilesOrEnvironment(t *testing.T) {
	e, _, enc, tmp := setup(t)
	log := filepath.Join(t.TempDir(), "calls.log")
	t.Setenv("SOPS_AGE_RECIPIENTS", "age1leak")
	t.Setenv("AGE_SECRET", "leak")
	r, err := sops.New(context.Background(), sops.Options{KeyFile: e.KeyFile("server"), Sops: e.Wrapper(t, log), AgeKeygen: e.AgeKeygen, Tmp: tmp})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const secret = "TOP-SECRET-VALUE-123"
	next, err := r.Set(ctx, []byte(enc), "k1", secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Decrypt(ctx, next, "k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Unset(ctx, next, "k1"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	calls := string(b)
	if !strings.Contains(calls, "ARGV: set --value-stdin") || !strings.Contains(calls, "ARGV: decrypt") || !strings.Contains(calls, "ARGV: unset") {
		t.Fatalf("the calls were not recorded:\n%s", calls)
	}
	if strings.Contains(calls, secret) || strings.Contains(calls, "first-value") {
		t.Fatalf("a value reached argv, a file or the environment:\n%s", calls)
	}
	for _, bad := range []string{"SOPS_AGE_RECIPIENTS", "AGE_SECRET", "age1leak"} {
		if strings.Contains(calls, bad) {
			t.Errorf("%s leaked into the child's environment", bad)
		}
	}
	if !strings.Contains(calls, "SOPS_AGE_KEY_FILE="+e.KeyFile("server")) {
		t.Error("the key file is missing from the environment")
	}
	if !strings.Contains(calls, "drwx------") {
		t.Errorf("the scratch directory is not 0700:\n%s", calls)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("scratch left behind: %v", left)
	}
}

func TestNewRefusesBadInput(t *testing.T) {
	e := sopstest.New(t)
	if _, err := sops.New(context.Background(), sops.Options{KeyFile: filepath.Join(t.TempDir(), "nope"), Sops: e.Sops, AgeKeygen: e.AgeKeygen}); err == nil {
		t.Error("a missing key file")
	}
	bad := filepath.Join(t.TempDir(), "k")
	_ = os.WriteFile(bad, []byte("not a key\n"), 0o600)
	if _, err := sops.New(context.Background(), sops.Options{KeyFile: bad, Sops: e.Sops, AgeKeygen: e.AgeKeygen}); err == nil {
		t.Error("a file that is no key")
	}
}

// Only the listed subcommands are started: every call of run in sops.go names
// one of them, and nothing else in the package starts a process.
func TestOnlyAllowListedCommands(t *testing.T) {
	src, err := os.ReadFile("sops.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sops.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"decrypt": true, "set": true, "unset": true, "encrypt": true, "-y": true}
	seen := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "run" && len(call.Args) >= 5 {
			// run(ctx, dir, stdin, bin, args...): the first string literal argument is the subcommand
			for _, a := range call.Args[4:] {
				if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					name := strings.Trim(lit.Value, `"`)
					if name == "--config" {
						continue
					}
					seen[name] = true
					if !allowed[name] {
						t.Errorf("sops.go:%d starts %q, which is not allow-listed", fset.Position(call.Pos()).Line, name)
					}
					break
				}
			}
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "exec" && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") && fset.Position(call.Pos()).Line > 0 {
				// the one place a process is built
				if fn := enclosingFunc(f, call.Pos()); fn != "run" {
					t.Errorf("sops.go:%d builds a command outside run (%s)", fset.Position(call.Pos()).Line, fn)
				}
			}
		}
		return true
	})
	for name := range allowed {
		if !seen[name] {
			t.Errorf("the allow-list names %q but no call uses it", name)
		}
	}
}

func enclosingFunc(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Pos() <= pos && pos <= fd.End() {
			return fd.Name.Name
		}
	}
	return ""
}
