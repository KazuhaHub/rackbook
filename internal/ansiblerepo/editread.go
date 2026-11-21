package ansiblerepo

import (
	"context"
	"go.yaml.in/yaml/v3"
	"os"
	"sort"
)

// FileState is a file as an editor loads it.
type FileState struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	// Base is the object ID to send back with the edit ("" = the file does not exist).
	Base    string `json:"base"`
	Content string `json:"content"`
	// Hidden counts the values that look like secrets. A file that has any is
	// not offered to the raw editor (the console never shows such a value).
	Hidden int `json:"hidden"`
}

func (r *Repo) fileState(ctx context.Context, rel string) (*FileState, error) {
	b, ok := dirTree{r}.Read(rel)
	fs := &FileState{Path: rel, Exists: ok}
	if !ok {
		return fs, nil
	}
	id, err := r.mirror.BlobID(ctx, "HEAD", rel)
	if err != nil {
		return nil, err
	}
	fs.Base = id
	if _, root, err := parseDoc(b); err == nil && root != nil {
		n := *root
		fs.Hidden = hide(&n)
	}
	if fs.Hidden == 0 {
		fs.Content = string(b)
	}
	return fs, nil
}

// HostFile is the host_vars file of a host as the raw editor loads it. A host
// without one gets the path a new file would have.
func (r *Repo) HostFile(ctx context.Context, host string) (*FileState, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hosts, err := r.hostsLocked()
	if err != nil {
		return nil, err
	}
	found := false
	for _, h := range hosts {
		found = found || h.Name == host
	}
	if !found {
		return nil, ErrNoHost
	}
	rel := hostVarsDir + "/" + host + ".yml"
	if p, ok := hostVarsPath(dirTree{r}, host); ok {
		rel = p
	}
	return r.fileState(ctx, rel)
}

// HostVarsPath is the file the host's variables are (or would be) written to.
func (r *Repo) HostVarsPath(host string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := hostVarsPath(dirTree{r}, host); ok {
		return p
	}
	return hostVarsDir + "/" + host + ".yml"
}

// InventoryFile is inventory/hosts.yml as the groups editor loads it, with the memberships.
type InventoryFile struct {
	Base       string      `json:"base"`
	Membership *Membership `json:"membership"`
}

// Inventory reads the groups and who is listed in each.
func (r *Repo) Inventory(ctx context.Context) (*InventoryFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := dirTree{r}.Read(inventoryFile)
	if !ok {
		return nil, ErrNoHost
	}
	m, err := MembershipOf(b)
	if err != nil {
		return nil, err
	}
	id, err := r.mirror.BlobID(ctx, "HEAD", inventoryFile)
	if err != nil {
		return nil, err
	}
	return &InventoryFile{Base: id, Membership: m}, nil
}

// Features lists the features that have a usable features/<name>/feature.yml,
// sorted by name. Broken ones are returned by name in invalid.
func (r *Repo) Features() (specs []*FeatureSpec, invalid []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t := dirTree{r}
	for _, d := range r.featureDirs() {
		fs, err := loadFeature(t, d)
		if err != nil {
			invalid = append(invalid, d)
			continue
		}
		fs.Name = d
		specs = append(specs, fs)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	return specs, invalid
}

// Feature returns one feature's definition.
func (r *Repo) Feature(name string) (*FeatureSpec, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fs, err := loadFeature(dirTree{r}, name)
	if err != nil {
		return nil, err
	}
	fs.Name = name
	return fs, nil
}

func (r *Repo) featureDirs() []string {
	return dirNames(r.o.Dir + "/" + featuresDir)
}

func dirNames(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// HiddenIn counts the values of a host or group variables file that look like
// secrets (the ones the console hides).
func HiddenIn(content []byte) int {
	_, root, err := parseDoc(content)
	if err != nil || root == nil {
		return 0
	}
	n := *root
	return hide(&n)
}

// HasFeature reports whether the file enables the feature.
func HasFeature(content []byte, name string) bool {
	_, root, err := parseDoc(content)
	if err != nil || root == nil {
		return false
	}
	f := mapGet(root, "features")
	return f != nil && f.Kind == yaml.MappingNode && mapKeyIndex(f, name) >= 0
}
