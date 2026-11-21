package ansiblerepo

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Tree is a read-only view of the repository's files, as they are now or as
// they would be after an edit. Paths are slash-separated and relative to the
// repository root.
type Tree interface {
	// Read returns a file's content; ok is false when it does not exist.
	Read(rel string) (b []byte, ok bool)
	// List returns the names of the regular files directly inside dir.
	List(dir string) []string
}

// dirTree is the work tree of the clone.
type dirTree struct{ r *Repo }

func (t dirTree) Read(rel string) ([]byte, bool) {
	b, err := t.r.readFile(rel)
	return b, err == nil
}

func (t dirTree) List(dir string) []string {
	ents, err := os.ReadDir(filepath.Join(t.r.o.Dir, filepath.FromSlash(dir)))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// overlay is a Tree with some files replaced (a nil value = removed).
type overlay struct {
	base Tree
	over map[string][]byte
}

func (o overlay) Read(rel string) ([]byte, bool) {
	if b, ok := o.over[rel]; ok {
		return b, b != nil
	}
	return o.base.Read(rel)
}

func (o overlay) List(dir string) []string {
	set := map[string]bool{}
	for _, n := range o.base.List(dir) {
		set[n] = true
	}
	for p, b := range o.over {
		if path.Dir(p) != dir {
			continue
		}
		if b == nil {
			delete(set, path.Base(p))
		} else {
			set[path.Base(p)] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func isYAMLName(n string) bool { return strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") }
