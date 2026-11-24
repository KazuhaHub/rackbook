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
	"diff-tree":  {"--no-commit-id", "--name-status", "-r", "-z", "--root", "--no-renames", "--patch", "--no-ext-diff", "--no-color"},
	"commit":     {"--quiet", "--no-verify", "-F", "-", "--only", "--"},
	"fetch":      {"--quiet"},
	"ls-tree":    {"-z", "--"},
	"log":        {"-n", "--format=*", "--fixed-strings", "--grep=*", "--skip=*", "--name-only", "--date-order", "--full-history", "--"},
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

// anchorsPath is the one state file that ls-tree may name: the daily audit anchors, whose history
// is checked. Every other state file (tokens, passkeys) stays out of reach of what reads the history.
const anchorsPath = ".rackbook/audit-anchors"

func plainStatePath(p string) bool { return p == anchorsPath }

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
	case "cat-file": // read only: one blob by its object id, or "--batch" with the names on stdin; no other option
		if !(len(rest) == 1 && rest[0] == "--batch") && (len(rest) != 2 || rest[0] != "blob" || !blobIDRe.MatchString(rest[1])) {
			return fmt.Errorf("%w: cat-file %s (only \"cat-file blob <object id>\" and \"cat-file --batch\")", errDestructive, strings.Join(rest, " "))
		}
	case "ls-tree": // read only: "-z <commit> -- <up to 4 plain paths>"
		if len(rest) < 4 || len(rest) > 7 || rest[0] != "-z" || !fullRevRe.MatchString(rest[1]) || rest[2] != "--" {
			return fmt.Errorf("%w: ls-tree %s", errDestructive, strings.Join(rest, " "))
		}
		for _, p := range rest[3:] {
			if _, err := safeHistPath(p); (err != nil && !plainStatePath(p)) || strings.HasPrefix(p, "-") || strings.HasPrefix(p, ":") {
				return fmt.Errorf("%w: ls-tree path %q", errDestructive, p)
			}
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

// networkCommand reports whether args is a command that talks to the remote
// (fetch or the single push shape), which is where a GitHub App credential is
// attached.
func networkCommand(args []string) bool {
	sub, _ := subcommand(args)
	return sub == "fetch" || sub == "push"
}

var envKeyRe = regexp.MustCompile(`^GIT_CONFIG_(KEY|VALUE)_[0-9]+$`)

// refuseEnv is the allow-list for the extra environment a command may carry:
// the commit identity, GIT_SSH_COMMAND, and the GIT_CONFIG_COUNT/KEY/VALUE
// triples that attach a GitHub App token (an http.<url>.extraheader), turn off
// redirects (http.followRedirects) or point an ssh remote at https
// (url.<base>.insteadOf). Any other variable or config key in that extra
// environment is refused. (The environment the process itself inherits is
// separate: execRunner removes the variables that could trace, weaken or
// redirect a command that carries a token, see inheritedEnv.)
func refuseEnv(env []string) error {
	for _, kv := range env {
		name, val, _ := strings.Cut(kv, "=")
		switch {
		case name == "GIT_SSH_COMMAND", name == "GIT_CONFIG_COUNT",
			name == "GIT_AUTHOR_NAME", name == "GIT_AUTHOR_EMAIL", name == "GIT_COMMITTER_NAME", name == "GIT_COMMITTER_EMAIL":
		case envKeyRe.MatchString(name):
			if strings.HasPrefix(name, "GIT_CONFIG_KEY_") {
				k := strings.ToLower(val)
				ok := (strings.HasPrefix(k, "http.") && strings.HasSuffix(k, ".extraheader")) || k == "http.followredirects" ||
					(strings.HasPrefix(k, "url.") && strings.HasSuffix(k, ".insteadof"))
				if !ok {
					return fmt.Errorf("%w: environment config key %q", errDestructive, val)
				}
			}
		default:
			return fmt.Errorf("%w: environment variable %s", errDestructive, name)
		}
	}
	return nil
}

// scrubbedEnv lists the inherited variables that are dropped from every git
// command: they could print the Authorization header (GIT_TRACE*, curl
// verbose), weaken TLS, add configuration behind the allow-list
// (GIT_CONFIG_PARAMETERS, GIT_CONFIG_COUNT and its keys are re-set by us when
// needed) or run a program to ask for credentials.
func scrubbedEnv(name string) bool {
	switch {
	case strings.HasPrefix(name, "GIT_TRACE"), strings.HasPrefix(name, "GIT_CONFIG_KEY_"), strings.HasPrefix(name, "GIT_CONFIG_VALUE_"):
		return true
	}
	switch name {
	case "GIT_CURL_VERBOSE", "GIT_SSL_NO_VERIFY", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
		"GIT_ASKPASS", "SSH_ASKPASS":
		return true
	}
	return false
}

// inheritedEnv is the process environment without the scrubbedEnv variables.
func inheritedEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !scrubbedEnv(name) {
			out = append(out, kv)
		}
	}
	return out
}
