package gitstore

// Decision 6 (docs/design-v0.2.md): Rackbook never force-pushes, deletes or
// rewrites anything on the remote. These tests prove it three ways:
//
//  1. TestMain routes every git command of this package's whole test suite
//     (edit, replay on a moved remote, PR mode, failure paths, rewritten
//     history, CLI commits) through a recorder and fails the run if any
//     recorded command is destructive;
//  2. unit tests of the checker and of the runtime guard in safegit.go;
//  3. static tests that keep the dangerous words, and every push command line,
//     out of every other non-test source file.
//
// The checker below is written independently of the guard in safegit.go.

import (
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kazuhahub/rackbook/internal/testutil"
)

type recorded struct {
	Cmd
	workTree bool // Dir had a .git when the command ran (not a bare repository)
}

type recorder struct {
	mu   sync.Mutex
	cmds []recorded
	next Runner
}

func (r *recorder) Run(ctx context.Context, c Cmd) (string, string, error) {
	// Dir may be a subdirectory of the work tree, so look upwards for .git.
	inTree := false
	for d := c.Dir; d != "" && d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			inTree = true
			break
		}
	}
	r.mu.Lock()
	r.cmds = append(r.cmds, recorded{Cmd: Cmd{Dir: c.Dir, Args: append([]string{}, c.Args...)}, workTree: inTree})
	r.mu.Unlock()
	return r.next.Run(ctx, c)
}

func (r *recorder) all() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded{}, r.cmds...)
}

var rec *recorder

func TestMain(m *testing.M) {
	rec = &recorder{next: execRunner{}}
	defaultRunner = rec
	code := m.Run()
	if bad := destructive(rec.all()); len(bad) > 0 {
		fmt.Fprintln(os.Stderr, "FAIL: destructive git commands were run:")
		for _, b := range bad {
			fmt.Fprintln(os.Stderr, "  ", b)
		}
		code = 1
	}
	os.Exit(code)
}

// destructive lists the commands that must never run.
func destructive(cmds []recorded) []string {
	var out []string
	for _, c := range cmds {
		for _, why := range problems(c) {
			out = append(out, why+": git "+strings.Join(c.Args, " "))
		}
	}
	return out
}

func problems(c recorded) []string {
	var out []string
	sub, rest := "", []string(nil)
	for i := 0; i < len(c.Args); i++ {
		a := c.Args[i]
		if a == "-c" || a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" || a == "--config-env" {
			i++
			continue
		}
		if !strings.HasPrefix(a, "-") {
			sub, rest = a, c.Args[i+1:]
			break
		}
	}
	for _, a := range c.Args {
		if strings.HasPrefix(a, "--force") || a == "--mirror" || a == "--prune" {
			out = append(out, "force/mirror/prune flag "+a)
		}
	}
	switch sub {
	case "push":
		for _, a := range rest {
			switch {
			case a == "--delete":
				out = append(out, "push --delete")
			case !strings.HasPrefix(a, "--") && strings.HasPrefix(a, "-") && strings.ContainsAny(a[1:], "fd"):
				out = append(out, "push short flag "+a+" (force or delete)")
			case strings.HasPrefix(a, "+") || strings.HasPrefix(a, ":") || strings.Contains(a, ":+"):
				out = append(out, "push refspec "+a+" forces or deletes")
			}
		}
		if len(rest) != 3 || rest[0] != "--quiet" || rest[1] != "origin" || !strings.HasPrefix(rest[2], "HEAD:refs/heads/") {
			out = append(out, "push is not `push --quiet origin HEAD:refs/heads/<branch>`")
		}
	case "branch", "tag":
		for _, a := range rest {
			if a == "-d" || a == "-D" || a == "--delete" {
				out = append(out, sub+" deletion")
			}
		}
	case "update-ref":
		for _, a := range rest {
			if a == "-d" || a == "--delete" {
				out = append(out, "update-ref -d")
			}
		}
	case "reset":
		if !c.workTree {
			out = append(out, "reset outside a work tree (bare/remote repository)")
		}
	}
	return out
}

func TestCheckerCatchesDestructiveCommands(t *testing.T) {
	wt := func(a ...string) recorded { return recorded{Cmd: Cmd{Args: a}, workTree: true} }
	bad := []recorded{
		wt("push", "--force", "origin", "HEAD:refs/heads/main"),
		wt("push", "-f", "origin", "HEAD:refs/heads/main"),
		wt("push", "-fu", "origin", "HEAD:refs/heads/main"),
		wt("push", "--force-with-lease", "origin", "HEAD:refs/heads/main"),
		wt("push", "--force-with-lease=main:abc", "origin", "HEAD:refs/heads/main"),
		wt("push", "--mirror", "origin"),
		wt("push", "--delete", "origin", "x"),
		wt("push", "-d", "origin", "x"),
		wt("push", "--quiet", "origin", "+HEAD:refs/heads/main"),
		wt("push", "--quiet", "origin", ":refs/heads/main"),
		wt("push", "--quiet", "origin", "HEAD:refs/heads/main", "main"),
		wt("push", "origin", "main"),
		wt("branch", "-D", "x"),
		wt("branch", "--delete", "x"),
		wt("tag", "-d", "v1"),
		wt("update-ref", "-d", "refs/heads/main"),
		wt("-c", "x=y", "push", "-f", "origin"),
		wt("--git-dir", "x", "push", "-f", "origin"),
		wt("--namespace", "n", "--work-tree", "w", "push", "--delete", "origin", "x"),
		wt("--git-dir=x", "--work-tree=y", "branch", "-D", "x"),
		{Cmd: Cmd{Args: []string{"reset", "--hard", "x"}}, workTree: false},
	}
	for _, c := range bad {
		if len(problems(c)) == 0 {
			t.Errorf("not caught: git %s", strings.Join(c.Args, " "))
		}
	}
	good := []recorded{
		wt("push", "--quiet", "origin", "HEAD:refs/heads/main"),
		wt("push", "--quiet", "origin", "HEAD:refs/heads/rackbook/ann/20261118-120000"),
		wt("reset", "--quiet", "--hard", "origin/main"),
		wt("-c", "commit.gpgsign=false", "commit", "--quiet", "--no-verify", "-F", "-", "--only", "--", "a.yml"),
		wt("fetch", "--quiet", "origin"),
		wt("branch", "--list"),
	}
	for _, c := range good {
		if p := problems(c); len(p) > 0 {
			t.Errorf("false positive for git %s: %v", strings.Join(c.Args, " "), p)
		}
	}
}

func TestRuntimeGuardRefusesDestructiveCommands(t *testing.T) {
	for _, args := range [][]string{
		{"push", "--force", "origin", "HEAD:refs/heads/main"},
		{"push", "-f", "origin", "HEAD:refs/heads/main"},
		{"push", "--force-with-lease", "origin", "HEAD:refs/heads/main"},
		{"push", "--quiet", "origin", "+HEAD:refs/heads/main"},
		{"push", "--quiet", "origin", ":refs/heads/main"},
		{"push", "--quiet", "origin", "HEAD:refs/heads/-x"},
		{"push", "--delete", "origin", "main"},
		{"push", "--mirror"},
		{"push", "origin", "main"},
		{"branch", "-D", "main"},
		{"-c", "a=b", "tag", "-d", "v1"},
		{"update-ref", "-d", "refs/heads/main"},
		{"remote", "prune", "origin"},
		{"--git-dir", "x", "push", "--force", "origin"},
		{"--git-dir=x", "push", "-f", "origin"},
		{"--work-tree", "x", "--namespace", "n", "push", "--delete", "origin", "main"},
		{"--exec-path=/x", "--config-env", "a=B", "branch", "-D", "main"},
		{"-C", "d", "--git-dir", "g", "update-ref", "-d", "refs/heads/main"},
		{"update-ref", "refs/heads/main", "0000000000000000000000000000000000000000"},
		{"send-pack", "origin", "--force"},
		{"receive-pack", "x"},
		{"-c", "alias.p=push", "p", "--force", "origin"},
		{"--no-pager", "-c", "x=y", "--git-dir", "g", "tag", "-d", "v1"},
		{"gc", "--prune=now"},
		{"--attr-source", "HEAD", "status"},
		{"--super-prefix", "x", "status"},
		{"--list-cmds=main"},
		{"--literal-pathspecs", "status"},
		{"--foo", "x", "status"},
		{"--exec-path", "status"},
		{"-c", "alias.s=status", "s"},
		{"-c", "core.hooksPath=/tmp/x", "status"},
		{"-c", "core.sshCommand=evil", "fetch", "origin"},
		{"-ccommit.gpgsign=false", "status"},
		{"-C"},
		// Options that run a program or write somewhere, per subcommand.
		{"fetch", "--quiet", "--upload-pack=evil", "origin"},
		{"fetch", "--quiet", "-u", "origin"},
		{"fetch", "--quiet", "--receive-pack=evil", "origin"},
		{"fetch", "--quiet", "--exec=evil", "origin"},
		{"log", "-n", "1", "--output=/tmp/x"},
		{"log", "-n", "1", "--ext-diff"},
		{"log", "--since", "yesterday"},
		{"log", "--since=1.day"}, // time limits stop the walk at a skewed commit: filtered in Go instead
		{"log", "--until=1.day"},
		{"log", "--skip", "5"},
		{"log", "--max-count=5"},
		{"log", "--name-status"},
		{"log", "--stat"},
		{"log", "--date=iso"},
		{"log", "--author=x"},
		{"log", "--all"},
		{"log", "--since=1.day", "--output=/tmp/x"},
		{"diff-tree", "--patch", "--output=/tmp/x", "HEAD"},
		{"diff-tree", "--ext-diff", "HEAD"},
		{"diff-tree", "--textconv", "-p", "HEAD"},
		{"diff-tree", "--stat", "HEAD"},
		{"diff-tree", "-p", "HEAD"},
		{"diff-tree", "--no-patch", "--ext-diff", "HEAD"},
		{"log", "-n", "1", "--textconv"},
		// cat-file reads one blob, and only that (a record at a commit)
		{"cat-file", "-p", "HEAD:rackbook.yml"},
		{"cat-file", "--batch"},
		{"cat-file", "--batch-all-objects"},
		{"cat-file", "--textconv", "HEAD:a.yml"},
		{"cat-file", "--filters", "HEAD:a.yml"},
		{"cat-file", "-e", "HEAD"},
		{"cat-file", "blob"},
		{"cat-file", "blob", "a", "b"},
		{"cat-file", "blob", "--textconv"},
		{"cat-file", "blob", "-x"},
		{"cat-file", "commit", "HEAD"},
		{"cat-file", "--path=x", "blob", "HEAD:a.yml"},
		{"merge", "--quiet", "--ff-only", "-o", "x", "origin/main"},
		{"reset", "--quiet", "--hard", "--push-option=x", "origin/main"},
		{"status", "--porcelain", "-uall", "--output=x"},
		{"commit", "--quiet", "-m", "x"},
		{"commit", "--quiet", "--amend", "-F", "-"},
		{"rev-parse", "--git-dir", "--exec-path"},
		{"config", "user.name", "evil"},
		{"config", "--global", "user.name"},
		{"config", "core.hooksPath", "/tmp"},
		{"remote", "get-url", "origin", "--push"},
		{"remote", "set-url", "origin", "x"},
		{"push", "--quiet", "--push-option=x", "origin", "HEAD:refs/heads/main"},
	} {
		if _, _, err := (execRunner{}).Run(context.Background(), Cmd{Dir: t.TempDir(), Args: args}); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("git %v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"fetch", "--quiet", "origin"}, {"reset", "--quiet", "--hard", "origin/main"}, {"-C", "d", "log", "-n", "1"}, {"-c", "commit.gpgsign=false", "-C", "d", "status"}, {"-c", "core.autocrlf=false", "status"}, {"--no-pager", "log"}, {"config", "user.name"}, {"remote", "get-url", "origin"}, {"log", "-n", "5", "--format=%h", "--fixed-strings", "--grep=Record: x", "--", "--weird-file"}, {"commit", "--quiet", "--no-verify", "-F", "-", "--only", "--", "-f"},
		{"log", "--date-order", "--skip=10", "-n", "5", "--name-only", "--format=%H", "HEAD", "--", ".", ":(exclude).rackbook"},
		{"diff-tree", "--patch", "--no-ext-diff", "--no-color", "--no-commit-id", "-r", "--root", "--no-renames", "abc1234", "--", ":(top,literal)a.yml"},
		{"cat-file", "blob", "0123456789abcdef0123456789abcdef01234567:./data/a.yml"}, {"cat-file", "blob", "HEAD:./a.yml"},
		{"log", "--format=%H", "--date-order", "--skip=1", "-n", "5", "0123456789abcdef0123456789abcdef01234567", "^0123456789abcdef0123456789abcdef01234568", "--", "data/a.yml"}} {
		if err := refuseDestructive(args); err != nil {
			t.Errorf("%v refused: %v", args, err)
		}
	}
}

func TestPushArgsIsTheOnlyPushShape(t *testing.T) {
	args, err := pushArgs("main")
	if err != nil || strings.Join(args, " ") != "push --quiet origin HEAD:refs/heads/main" {
		t.Fatalf("%v %v", args, err)
	}
	if args, err = pushArgs("rackbook/ann/20261118-120000"); err != nil || args[3] != "HEAD:refs/heads/rackbook/ann/20261118-120000" {
		t.Fatalf("%v %v", args, err)
	}
	for _, b := range []string{"", "+main", ":main", "-f", "a b", "a..b", "x/", "x.lock", "a:b", "a\nb", "main^", "a~1"} {
		if _, err := pushArgs(b); err == nil {
			t.Errorf("branch %q accepted", b)
		}
	}
}

func TestRecorderSeesTheSuitesPushes(t *testing.T) {
	before := len(rec.all())
	e := newEnv(t)
	s := open(t, e.server, nil)
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	pushes := 0
	for _, c := range rec.all()[before:] {
		if sub, _ := subcommand(c.Args); sub == "push" {
			pushes++
			if strings.Join(c.Args, " ") != "push --quiet origin HEAD:refs/heads/main" {
				t.Errorf("unexpected push: %v", c.Args)
			}
		}
	}
	if pushes != 1 {
		t.Fatalf("expected exactly one push, saw %d", pushes)
	}
}

// Static checks --------------------------------------------------------------

// nonTestSources lists the Go files under cmd and internal that are not tests.
func nonTestSources(t *testing.T) []string {
	t.Helper()
	root := testutil.RepoRoot(t)
	var files []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 20 {
		t.Fatalf("found only %d sources", len(files))
	}
	return files
}

func TestStaticNoForcePushAnywhereButSafegit(t *testing.T) {
	words := []string{"--force", "force-with-lease", "--mirror", "--delete", "--prune", "update-ref",
		`"-f"`, `"-d"`, `"-D"`, `"+refs`, `"+HEAD`, `"+"+`, "HEAD:refs/"}
	for _, f := range nonTestSources(t) {
		if filepath.Base(f) == "safegit.go" && filepath.Base(filepath.Dir(f)) == "gitstore" {
			continue
		}
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			for _, w := range words {
				if strings.Contains(line, w) {
					t.Errorf("%s:%d mentions %q; only gitstore/safegit.go may build or refuse such commands", f, i+1, w)
				}
			}
		}
	}
}

func TestStaticOnlyOneGitRunnerAndOnePushBuilder(t *testing.T) {
	// A string literal "push" is a git subcommand unless the line is about the
	// write mode or a CLI flag.
	benign := func(line string) bool { return strings.Contains(line, "Mode") || strings.Contains(line, "Flags()") }
	for _, f := range nonTestSources(t) {
		src, _ := os.ReadFile(f)
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			// the tests' sops helper starts processes; no production code may import it
			if p, _ := strconv.Unquote(imp.Path.Value); strings.HasSuffix(p, "/internal/sops/sopstest") {
				t.Errorf("%s imports sopstest, which is for tests only", f)
			}
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" && !strings.HasSuffix(f, filepath.Join("gitstore", "git.go")) && !strings.HasSuffix(f, filepath.Join("sops", "sops.go")) && !strings.HasSuffix(f, filepath.Join("sopstest", "sopstest.go")) {
				t.Errorf("%s imports os/exec: git must only be started by gitstore's Runner (and sops and age-keygen by internal/sops; sopstest is the tests' helper)", f)
			}
		}
		if strings.HasSuffix(f, filepath.Join("gitstore", "safegit.go")) {
			continue
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, `"push"`) && !benign(line) {
				t.Errorf("%s:%d: a push command line must be built by pushArgs in safegit.go", f, i+1)
			}
		}
	}
}

func TestEveryCommandRunsWithoutHooksAndSystemConfig(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "hooks")
	os.MkdirAll(hook, 0o755)
	marker := filepath.Join(dir, "ran")
	os.WriteFile(filepath.Join(hook, "post-commit"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)
	sh(t, dir, "init", "-b", "main")
	sh(t, dir, "config", "core.hooksPath", hook)
	sh(t, dir, "config", "user.name", "T")
	sh(t, dir, "config", "user.email", "t@e.com")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644)
	r := &Repo{Dir: dir}
	if _, err := r.Commit(context.Background(), []string{"a.txt"}, "x\n", Identity{"T", "t@e.com"}, Identity{"T", "t@e.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a repository hook ran")
	}
	// The server ignores the user's global config; the CLI keeps it.
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[user]\n\tname = Global Name\n"), 0o644)
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".gitconfig"))
	sh2 := &Repo{Dir: t.TempDir()}
	exec.Command("git", "-C", sh2.Dir, "init").Run()
	if got, _ := sh2.git(context.Background(), "config", "user.name"); got != "Global Name" {
		t.Fatalf("the CLI must keep the user's config: %q", got)
	}
	sh2.IgnoreUserConfig = true
	if got, _ := sh2.git(context.Background(), "config", "user.name"); got != "" {
		t.Fatalf("the server must ignore the user's global config: %q", got)
	}
}

func TestOnlyTheServerIgnoresSystemAndGlobalConfig(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	sys := filepath.Join(home, "system.gitconfig")
	os.WriteFile(sys, []byte("[user]\n\tname = System Name\n"), 0o644)
	t.Setenv("GIT_CONFIG_SYSTEM", sys)
	t.Setenv("GIT_CONFIG_GLOBAL", "")
	t.Setenv("HOME", home)
	exec.Command("git", "-C", dir, "init").Run()
	cli := &Repo{Dir: dir}
	if got, _ := cli.git(context.Background(), "config", "user.name"); got != "System Name" {
		t.Fatalf("the CLI keeps the system config (credential helpers live there): %q", got)
	}
	srv := &Repo{Dir: dir, IgnoreUserConfig: true}
	if got, _ := srv.git(context.Background(), "config", "user.name"); got != "" {
		t.Fatalf("the server ignores it: %q", got)
	}
}

func TestCommitsAreByteForByteWhateverAutocrlfSays(t *testing.T) {
	home := t.TempDir()
	gc := filepath.Join(home, ".gitconfig")
	os.WriteFile(gc, []byte("[core]\n\tautocrlf = true\n"), 0o644)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_GLOBAL", gc)
	dir := t.TempDir()
	sh(t, dir, "init", "-b", "main")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a\r\nb\r\n"), 0o644)
	want := "a\r\nb\r\n"
	for _, ignore := range []bool{false, true} {
		r := &Repo{Dir: dir, IgnoreUserConfig: ignore}
		if _, err := r.Commit(context.Background(), []string{"a.txt"}, "x\n", Identity{"T", "t@e.com"}, Identity{"T", "t@e.com"}); err != nil {
			t.Fatal(err)
		}
		if got := sh2raw(t, dir, "cat-file", "blob", "HEAD:a.txt"); got != want {
			t.Fatalf("ignore=%v: the blob was converted: %q", ignore, got)
		}
		want += "c\r\n"
		os.WriteFile(filepath.Join(dir, "a.txt"), []byte(want), 0o644)
	}
}

func sh2raw(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}
