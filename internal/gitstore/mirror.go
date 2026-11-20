package gitstore

// Mirror is a clone Rackbook only reads: it fetches and resets to origin on
// request and never writes, commits or pushes. It exists so a second
// repository (the Ansible + SOPS repository of /infra) can be kept fresh with
// the same guarded git runner as the ledger, and with its own SSH key.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Mirror is a read-only clone of one branch of its origin.
type Mirror struct {
	Dir    string // the work tree
	Branch string // the branch followed
	// SSHKey is the private key used for this clone only (empty = whatever
	// git's own configuration says). KnownHosts is its known_hosts file
	// (empty = git's default). They reach git through GIT_SSH_COMMAND in the
	// environment of each command, never in a command line.
	SSHKey     string
	KnownHosts string
	Runner     Runner // nil = the real git
}

// MirrorCommit is one commit of the log.
type MirrorCommit struct {
	Hash    string    `json:"hash"`
	Author  string    `json:"author"`
	Time    time.Time `json:"time"`
	Subject string    `json:"subject"`
}

func (m *Mirror) repo() *Repo {
	return &Repo{Dir: m.Dir, Runner: m.Runner, IgnoreUserConfig: true}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (m *Mirror) env() []string {
	if m.SSHKey == "" {
		// Never inherit the GIT_SSH_COMMAND of the process: in the container it holds the ledger's write key.
		return []string{"GIT_SSH_COMMAND=ssh -o BatchMode=yes"}
	}
	cmd := "ssh -i " + shellQuote(m.SSHKey) + " -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes"
	if m.KnownHosts != "" {
		cmd += " -o UserKnownHostsFile=" + shellQuote(m.KnownHosts)
	}
	return []string{"GIT_SSH_COMMAND=" + cmd}
}

func (m *Mirror) check(ctx context.Context) (*Repo, error) {
	if m.Dir == "" || m.Branch == "" {
		return nil, errors.New("mirror needs a directory and a branch")
	}
	if err := validBranch(m.Branch); err != nil {
		return nil, fmt.Errorf("unusable branch name %q", m.Branch)
	}
	r := m.repo()
	if !r.IsRepo(ctx) {
		return nil, fmt.Errorf("%s is not a Git work tree (clone it once first)", m.Dir)
	}
	return r, nil
}

// Fetch fetches origin. It does not touch the work tree.
func (m *Mirror) Fetch(ctx context.Context) error {
	r, err := m.check(ctx)
	if err != nil {
		return err
	}
	_, err = r.run(ctx, m.env(), "", "fetch", "--quiet", "origin")
	return err
}

// Checkout moves the work tree to the fetched origin/<Branch>, discarding
// anything local, and returns the commit it is now at.
func (m *Mirror) Checkout(ctx context.Context) (string, error) {
	r, err := m.check(ctx)
	if err != nil {
		return "", err
	}
	if cur, err := r.Branch(ctx); err != nil {
		return "", err
	} else if cur != m.Branch {
		if _, err := r.git(ctx, "checkout", "--quiet", m.Branch); err != nil {
			return "", err
		}
	}
	if _, err := r.git(ctx, "reset", "--quiet", "--hard", "origin/"+m.Branch); err != nil {
		return "", err
	}
	return r.Head(ctx)
}

// Sync is Fetch and Checkout. It changes nothing on the remote.
func (m *Mirror) Sync(ctx context.Context) (string, error) {
	if err := m.Fetch(ctx); err != nil {
		return "", err
	}
	return m.Checkout(ctx)
}

// Head is the commit the work tree is at.
func (m *Mirror) Head(ctx context.Context) (string, error) { return m.repo().Head(ctx) }

// Log returns the newest n commits, newest first.
func (m *Mirror) Log(ctx context.Context, n int) ([]MirrorCommit, error) {
	if n < 1 {
		n = 1
	}
	out, err := m.repo().git(ctx, "log", "-n", strconv.Itoa(n), "--format=%H%x1f%an%x1f%aI%x1f%s")
	if err != nil {
		return nil, err
	}
	commits := []MirrorCommit{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(line, "\x1f", 4)
		if len(f) != 4 {
			continue
		}
		t, _ := time.Parse(time.RFC3339, f[2])
		commits = append(commits, MirrorCommit{Hash: f[0], Author: f[1], Time: t, Subject: f[3]})
	}
	return commits, nil
}
