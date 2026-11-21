package ansiblerepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/secretscan"
)

const maxFile = 1 << 20

// Options configures a Repo.
type Options struct {
	Dir        string
	Branch     string
	SSHKey     string
	KnownHosts string
	// Auth fetches over https with a GitHub App token (read-only) instead of SSH.
	Auth *gitstore.GitAuth
	// Interval is how often the clone is refreshed (0 = every minute).
	Interval time.Duration
	Logger   *slog.Logger
	Runner   gitstore.Runner // nil = the real git; for tests
	Now      func() time.Time

	// WriteAuth makes the repository writable: commits go to Branch with this
	// credential (a GitHub App token with contents: write). Nil = read only.
	WriteAuth *gitstore.GitAuth
	// Committer is the committer identity of every commit (the author is the
	// person who made the edit).
	Committer gitstore.Identity
	// Rules are the repository conventions the checks apply (zero = DefaultRules).
	Rules Rules
	// Scanner is the secret scan for host and group variables (nil = built-in rules).
	Scanner *secretscan.Scanner
	// Audit receives the actions that did not end in a commit (nil = none).
	Audit Auditor
	// Sops edits the hosts' SOPS files with Rackbook's own age key (nil = the
	// secrets editor is off).
	Sops Sopser
}

// Repo is the read-only clone.
type Repo struct {
	o      Options
	mirror *gitstore.Mirror
	log    *slog.Logger

	writeMu  sync.Mutex   // one edit at a time
	mu       sync.RWMutex // held for writing while the work tree is reset or committed to
	syncedAt time.Time
	syncErr  string
	head     string
}

// New prepares a Repo. It does not touch the disk.
func New(o Options) (*Repo, error) {
	if o.Dir == "" || o.Branch == "" {
		return nil, errors.New("the repository needs a directory and a branch")
	}
	if o.Interval <= 0 {
		o.Interval = time.Minute
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rules == (Rules{}) {
		o.Rules = DefaultRules()
	}
	return &Repo{o: o, log: o.Logger, mirror: &gitstore.Mirror{Dir: o.Dir, Branch: o.Branch, SSHKey: o.SSHKey, KnownHosts: o.KnownHosts, Auth: o.Auth, WriteAuth: o.WriteAuth, Runner: o.Runner}}, nil
}

// State is how fresh the clone is.
type State struct {
	Branch   string    `json:"branch"`
	Head     string    `json:"head,omitempty"`
	SyncedAt time.Time `json:"syncedAt"` // the last successful refresh; zero if none yet
	Error    string    `json:"error,omitempty"`
}

// State returns the current freshness.
func (r *Repo) State() State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return State{Branch: r.o.Branch, Head: r.head, SyncedAt: r.syncedAt, Error: r.syncErr}
}

// Refresh fetches origin and resets the work tree to it. The fetch (the slow
// part) runs without blocking readers.
func (r *Repo) Refresh(ctx context.Context) error {
	err := r.mirror.Fetch(ctx)
	var head string
	if err == nil {
		r.mu.Lock()
		head, err = r.mirror.Checkout(ctx)
		r.mu.Unlock()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.syncErr = err.Error()
		return err
	}
	r.head, r.syncedAt, r.syncErr = head, r.o.Now(), ""
	return nil
}

// Run refreshes now and then every Interval until ctx ends. A failure is
// logged (once per change) and retried at the next tick.
func (r *Repo) Run(ctx context.Context) {
	last := ""
	tick := func() {
		if err := r.Refresh(ctx); err != nil {
			if ctx.Err() == nil && err.Error() != last {
				r.log.Warn("infra repository refresh failed", "err", err)
			}
			last = err.Error()
			return
		}
		if last != "" {
			r.log.Info("infra repository refresh works again")
		}
		last = ""
	}
	tick()
	t := time.NewTicker(r.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// Commits returns the newest n commits of the branch.
func (r *Repo) Commits(ctx context.Context, n int) ([]gitstore.MirrorCommit, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mirror.Log(ctx, n)
}

// readFile reads a regular file inside the clone (a symlink is refused).
func (r *Repo) readFile(rel string) ([]byte, error) {
	p := filepath.Join(r.o.Dir, filepath.FromSlash(rel))
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	// a directory on the way may be a committed symlink: the real path must stay inside the clone
	if real, err := filepath.EvalSymlinks(p); err != nil {
		return nil, err
	} else if root, err := filepath.EvalSymlinks(r.o.Dir); err != nil {
		return nil, err
	} else if rel, err := filepath.Rel(root, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s leaves the repository", p)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s is too large", rel)
	}
	return b, nil
}

func varsPath(host string) []string {
	return []string{"inventory/host_vars/" + host + ".yml", "inventory/host_vars/" + host + ".yaml"}
}

func (r *Repo) hasVars(host string) bool {
	for _, rel := range varsPath(host) {
		if _, err := r.readFile(rel); err == nil {
			return true
		}
	}
	return false
}

// hostsLocked reads the inventory; the caller holds the read lock.
func (r *Repo) hostsLocked() ([]Host, error) {
	b, err := r.readFile("inventory/hosts.yml")
	if err != nil {
		return nil, fmt.Errorf("inventory/hosts.yml: %w", err)
	}
	return ParseInventory(b, r.hasVars)
}

// Hosts lists the hosts of inventory/hosts.yml.
func (r *Repo) Hosts() ([]Host, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hostsLocked()
}

// ErrNoHost is returned for a host that is not in the inventory.
var ErrNoHost = errors.New("no such host")

// Feature is one entry of a host's `features:` map.
type Feature struct {
	Name string `json:"name"`
	// Enabled is false only when the entry is `false` or has `enabled: false`.
	Enabled  bool           `json:"enabled"`
	Settings map[string]any `json:"settings,omitempty"`
}

// HostDetail is one host as the console shows it.
type HostDetail struct {
	Host
	// Vars is the host_vars file as YAML, with secret-looking values hidden.
	Vars     string    `json:"vars,omitempty"`
	Features []Feature `json:"features"`
	// Hidden counts the values and comments replaced by "(hidden)".
	Hidden int `json:"hidden"`
}

// detailLocked reads the host_vars of h; the caller holds the read lock.
func (r *Repo) detailLocked(h Host) (*HostDetail, error) {
	d := &HostDetail{Host: h, Features: []Feature{}}
	if !h.HasVars {
		return d, nil
	}
	var raw []byte
	for _, rel := range varsPath(h.Name) {
		if b, err := r.readFile(rel); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		return d, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("host_vars of %s: %w", h.Name, err)
	}
	d.Hidden = hide(&doc)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if doc.Kind != 0 {
		if err := enc.Encode(&doc); err != nil {
			return nil, err
		}
	}
	d.Vars = buf.String()
	d.Features = featuresOf(&doc)
	return d, nil
}

// Host returns one inventory host with its variables.
func (r *Repo) Host(name string) (*HostDetail, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hosts, err := r.hostsLocked()
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.Name == name {
			return r.detailLocked(h)
		}
	}
	return nil, ErrNoHost
}

// HostDetails returns every host with its variables, reading the inventory
// once. A host whose host_vars cannot be read is returned without them.
func (r *Repo) HostDetails() ([]*HostDetail, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hosts, err := r.hostsLocked()
	if err != nil {
		return nil, err
	}
	out := make([]*HostDetail, 0, len(hosts))
	for _, h := range hosts {
		d, err := r.detailLocked(h)
		if err != nil {
			d = &HostDetail{Host: h, Features: []Feature{}}
		}
		out = append(out, d)
	}
	return out, nil
}

func featuresOf(doc *yaml.Node) []Feature {
	out := []Feature{}
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "features" || n.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		m := n.Content[i+1]
		for j := 0; j+1 < len(m.Content); j += 2 {
			f := Feature{Name: m.Content[j].Value, Enabled: true}
			v := m.Content[j+1]
			switch {
			case v.Kind == yaml.ScalarNode && v.Tag == "!!bool" && v.Value == "false":
				f.Enabled = false
			case v.Kind == yaml.MappingNode:
				var s map[string]any
				if v.Decode(&s) == nil {
					f.Settings = s
					if e, ok := s["enabled"].(bool); ok && !e {
						f.Enabled = false
					}
				}
			}
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
