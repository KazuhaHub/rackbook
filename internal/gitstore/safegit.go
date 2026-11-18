package gitstore

// Rackbook never rewrites or deletes anything on the remote. Every push is a
// fast-forward push of HEAD to one branch, and this file is the only place
// that knows what such a command line looks like: pushArgs builds it, and
// refuseDestructive (which runs in front of every real git call) refuses
// anything that could force, delete or mirror. The static test in
// safegit_test.go keeps these words out of every other non-test source file.

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var branchRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}._/-]*$`)

func validBranch(b string) error {
	if !branchRe.MatchString(b) || strings.Contains(b, "..") || strings.Contains(b, "//") ||
		strings.HasSuffix(b, "/") || strings.HasSuffix(b, ".lock") || strings.HasSuffix(b, ".") {
		return fmt.Errorf("refusing to push to unusable branch name %q", b)
	}
	return nil
}

// pushArgs is the only builder of push command lines. The result is always
// `push --quiet origin HEAD:refs/heads/<branch>`: no force, no "+" or ":"
// refspec, no deletion. Pull request branches use it too.
func pushArgs(branch string) ([]string, error) {
	if err := validBranch(branch); err != nil {
		return nil, err
	}
	return []string{"push", "--quiet", "origin", "HEAD:refs/heads/" + branch}, nil
}

var errDestructive = errors.New("refusing a git command that could rewrite or delete history")

// allowedConfigKeys are the only "-c key=value" settings Rackbook passes.
var allowedConfigKeys = map[string]bool{"commit.gpgsign": true, "safe.directory": true, "core.quotepath": true, "core.autocrlf": true}

// subcommand returns the git subcommand and its arguments. Only the global
// options Rackbook itself uses may precede it: -C <dir>, -c <allowed key>=<value>
// and --no-pager. For anything else (--git-dir, --attr-source, --foo x, ...) it
// returns "", which refuseDestructive refuses.
func subcommand(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-C" && i+1 < len(args):
			i++
		case a == "-c" && i+1 < len(args):
			key, _, ok := strings.Cut(args[i+1], "=")
			if !ok || !allowedConfigKeys[strings.ToLower(key)] {
				return "", nil
			}
			i++
		case a == "--no-pager":
		case strings.HasPrefix(a, "-"):
			return "", nil
		default:
			return a, args[i+1:]
		}
	}
	return "", nil
}

// allowedOptions lists, for every subcommand Rackbook runs, the only option
// tokens it may be given (a trailing "*" matches a prefix). Anything else that
// starts with "-" is refused, which keeps out --upload-pack, --receive-pack,
// --exec, --output, -u, -o/--push-option, --ext-diff, --textconv and every
// other option that runs a program or writes somewhere. Everything after a bare
// "--" is a path. A new need has to be added here on purpose. push, remote and
// config are checked exactly below instead.
var allowedOptions = map[string][]string{
	"add":        {"--"},
	"cat-file":   {},
	"checkout":   {"--quiet", "--"},
	"commit":     {"--quiet", "--no-verify", "-F", "-", "--only", "--"},
	"fetch":      {"--quiet"},
	"log":        {"-n", "--format=*", "--fixed-strings", "--grep=*", "--"},
	"merge":      {"--quiet", "--ff-only"},
	"merge-base": {"--is-ancestor"},
	"push":       {},
	"remote":     {},
	"config":     {},
	"reset":      {"--quiet", "--hard"},
	"rev-list":   {"--count", "--not", "--remotes"},
	"rev-parse":  {"--is-inside-work-tree", "--abbrev-ref", "--absolute-git-dir", "--show-prefix", "--verify", "--quiet", "--short"},
	"status":     {"--porcelain", "-z", "--untracked-files=no", "--untracked-files=all", "--ignored=matching"},
}

func optionAllowed(sub, opt string) bool {
	for _, a := range allowedOptions[sub] {
		if a == opt || (strings.HasSuffix(a, "*") && strings.HasPrefix(opt, strings.TrimSuffix(a, "*"))) {
			return true
		}
	}
	return false
}

// refuseDestructive is a last line of defence in the real runner. A push must
// be exactly what pushArgs builds, only the subcommands of allowedOptions may
// run, and each may only use its own options.
func refuseDestructive(args []string) error {
	sub, rest := subcommand(args)
	if _, ok := allowedOptions[sub]; !ok {
		return fmt.Errorf("%w: git %s (only -C, -c <known key>, --no-pager may precede the subcommand; subcommands: see allowedOptions)", errDestructive, sub)
	}
	switch sub {
	case "push":
		if len(rest) != 3 || rest[0] != "--quiet" || rest[1] != "origin" || !strings.HasPrefix(rest[2], "HEAD:refs/heads/") ||
			validBranch(strings.TrimPrefix(rest[2], "HEAD:refs/heads/")) != nil {
			return fmt.Errorf("%w: push %s", errDestructive, strings.Join(rest, " "))
		}
	case "remote": // read only: get-url origin
		if len(rest) != 2 || rest[0] != "get-url" || rest[1] != "origin" {
			return fmt.Errorf("%w: remote %s", errDestructive, strings.Join(rest, " "))
		}
	case "config": // read only, fixed keys
		if len(rest) != 1 || (rest[0] != "user.name" && rest[0] != "user.email") {
			return fmt.Errorf("%w: config %s", errDestructive, strings.Join(rest, " "))
		}
	default:
		for _, a := range rest {
			if a == "--" {
				break
			}
			if strings.HasPrefix(a, "-") && !optionAllowed(sub, a) {
				return fmt.Errorf("%w: git %s %s (option not allowed)", errDestructive, sub, a)
			}
		}
	}
	return nil
}
