// Package sops runs the sops and age-keygen binaries for the infra secrets
// editor. It is the only place besides gitstore that starts a process, and it
// starts only the commands listed here:
//
//	sops decrypt --extract '["key"]'        one value, to standard output
//	sops set --value-stdin FILE '["key"]'   the value arrives on standard input
//	sops unset FILE '["key"]'
//	sops rotate -i [--add-age A,B] [--rm-age C] FILE   a new data key, recipients added or removed
//	sops --config C encrypt --filename-override F -   a new file, from standard input
//	age-keygen -y KEYFILE                   the public key of the private key file
//
// A secret value is never an argument of any of them (a process list is
// readable by everybody on the host): it travels on standard input and
// standard output. The files handed to sops hold only ciphertext and live in a
// private (0700) directory that is removed afterwards. The environment of a
// child is built from nothing: the key file and a scratch HOME, no inherited
// SOPS_* or AGE_* variable.
package sops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Errors a caller can tell apart. None carries output of the tools: their
// messages are never passed on.
var (
	// ErrNoKey: the file has no such key.
	ErrNoKey = errors.New("no such key in the file")
	// ErrCannotDecrypt: the key file is not a recipient of the file (or the file is damaged).
	ErrCannotDecrypt = errors.New("this server's key cannot decrypt the file")
	// ErrFailed: sops failed for another reason.
	ErrFailed = errors.New("sops failed")
)

const timeout = 30 * time.Second

// Options configures a Runner.
type Options struct {
	// KeyFile is the age identity file (SOPS_AGE_KEY_FILE of the children).
	KeyFile string
	// Sops and AgeKeygen are the binaries (empty = looked up on PATH once, now).
	Sops, AgeKeygen string
	// Tmp is the directory scratch directories are made in (empty = /dev/shm
	// when it exists, else the system temporary directory).
	Tmp string
}

// Runner starts the allow-listed commands.
type Runner struct {
	o      Options
	pubKey string
}

// New checks the binaries and the key file and derives the public key.
func New(ctx context.Context, o Options) (*Runner, error) {
	if o.KeyFile == "" {
		return nil, errors.New("no age key file")
	}
	abs, err := filepath.Abs(o.KeyFile)
	if err != nil {
		return nil, err
	}
	o.KeyFile = abs
	if st, err := os.Stat(o.KeyFile); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("--sops-age-key-file %s is not a readable file", o.KeyFile)
	}
	if o.Sops == "" {
		if o.Sops, err = exec.LookPath("sops"); err != nil {
			return nil, errors.New("the sops binary is not on PATH")
		}
	}
	if o.AgeKeygen == "" {
		if o.AgeKeygen, err = exec.LookPath("age-keygen"); err != nil {
			return nil, errors.New("the age-keygen binary is not on PATH")
		}
	}
	if o.Tmp == "" {
		o.Tmp = os.TempDir()
		if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
			o.Tmp = "/dev/shm"
		}
	}
	r := &Runner{o: o}
	out, err := r.run(ctx, "", nil, o.AgeKeygen, "-y", o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("age-keygen could not read %s", o.KeyFile)
	}
	r.pubKey = strings.TrimSpace(string(out))
	if !strings.HasPrefix(r.pubKey, "age1") || strings.ContainsAny(r.pubKey, " \n") {
		return nil, errors.New("age-keygen returned no public key")
	}
	return r, nil
}

// PublicKey is the age recipient of this server's key.
func (r *Runner) PublicKey() string { return r.pubKey }

// run starts one process with a clean environment. dir is the working
// directory ("" = none); stdin may be nil.
func (r *Runner) run(ctx context.Context, dir string, stdin []byte, bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	home, err := os.MkdirTemp(r.o.Tmp, "rackbook-home-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + home, "TMPDIR=" + home, "SOPS_AGE_KEY_FILE=" + r.o.KeyFile, "PATH=/usr/bin:/bin"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, classify(stderr.String(), err)
	}
	return stdout.Bytes(), nil
}

// classify turns a failure into one of the errors above; the text of the tool
// is looked at, never returned.
func classify(stderr string, err error) error {
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "not found") && strings.Contains(s, "component"):
		return ErrNoKey
	case strings.Contains(s, "failed to get the data key") || strings.Contains(s, "no master key") || strings.Contains(s, "failed to load age identities"):
		return ErrCannotDecrypt
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("%w (exit status %d)", ErrFailed, ee.ExitCode())
	}
	return ErrFailed
}

// indexOf is sops' tree path of a top-level key.
func indexOf(key string) (string, error) {
	b, err := json.Marshal([]string{key})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// workFile puts the ciphertext into a private directory and returns its path
// and the cleanup.
func (r *Runner) workFile(enc []byte) (string, func(), error) {
	dir, err := os.MkdirTemp(r.o.Tmp, "rackbook-sops-")
	if err != nil {
		return "", nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	p := filepath.Join(dir, "file.sops.yaml")
	if err := os.WriteFile(p, enc, 0o600); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return p, func() { os.RemoveAll(dir) }, nil
}

// Decrypt returns the value of one top-level key of an encrypted YAML file.
func (r *Runner) Decrypt(ctx context.Context, enc []byte, key string) ([]byte, error) {
	idx, err := indexOf(key)
	if err != nil {
		return nil, err
	}
	p, done, err := r.workFile(enc)
	if err != nil {
		return nil, err
	}
	defer done()
	return r.run(ctx, filepath.Dir(p), nil, r.o.Sops, "decrypt", "--input-type", "yaml", "--output-type", "yaml", "--extract", idx, p)
}

// Set returns the file with the key set to the string value. The value goes
// to sops on standard input, as the JSON string it expects.
func (r *Runner) Set(ctx context.Context, enc []byte, key, value string) ([]byte, error) {
	idx, err := indexOf(key)
	if err != nil {
		return nil, err
	}
	js, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	p, done, err := r.workFile(enc)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err := r.run(ctx, filepath.Dir(p), js, r.o.Sops, "set", "--value-stdin", "--input-type", "yaml", "--output-type", "yaml", p, idx); err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// Unset returns the file without the key.
func (r *Runner) Unset(ctx context.Context, enc []byte, key string) ([]byte, error) {
	idx, err := indexOf(key)
	if err != nil {
		return nil, err
	}
	p, done, err := r.workFile(enc)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err := r.run(ctx, filepath.Dir(p), nil, r.o.Sops, "unset", "--input-type", "yaml", "--output-type", "yaml", p, idx); err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// Encrypt creates the file at rel (slash-separated, relative to repoDir) with
// one key. The recipients come from the repository's .sops.yaml creation rule
// for rel; sops matches rel against the rules, so it is passed as an absolute
// path under repoDir.
func (r *Runner) Encrypt(ctx context.Context, repoDir, rel, key, value string) ([]byte, error) {
	js, err := json.Marshal(map[string]string{key: value})
	if err != nil {
		return nil, err
	}
	conf := filepath.Join(repoDir, ".sops.yaml")
	name := filepath.Join(repoDir, filepath.FromSlash(rel))
	out, err := r.run(ctx, repoDir, js, r.o.Sops, "--config", conf, "encrypt", "--filename-override", name, "--input-type", "json", "--output-type", "yaml", "/dev/stdin")
	if err != nil {
		return nil, err
	}
	return out, nil
}

var ageRecipientRe = regexp.MustCompile(`^age1[02-9ac-hj-np-z]{58}$`)

// ValidRecipient reports whether s is an age public key (X25519 recipient).
func ValidRecipient(s string) bool { return ageRecipientRe.MatchString(s) }

// Rotate returns the file encrypted with a fresh data key (every value and
// the MAC change) for its recipients plus add minus remove. The recipients are
// public keys and become arguments, so each one is checked first.
func (r *Runner) Rotate(ctx context.Context, enc []byte, add, remove []string) ([]byte, error) {
	args := []string{"rotate", "-i", "--input-type", "yaml", "--output-type", "yaml"}
	for _, f := range []struct {
		flag string
		keys []string
	}{{"--add-age", add}, {"--rm-age", remove}} {
		if len(f.keys) == 0 {
			continue
		}
		for _, k := range f.keys {
			if !ValidRecipient(k) {
				return nil, fmt.Errorf("%w: not an age recipient", ErrFailed)
			}
		}
		args = append(args, f.flag, strings.Join(f.keys, ","))
	}
	p, done, err := r.workFile(enc)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err := r.run(ctx, filepath.Dir(p), nil, r.o.Sops, append(args, p)...); err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}
