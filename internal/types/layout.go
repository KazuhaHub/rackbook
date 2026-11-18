package types

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// This file is the only place in the package that knows how a collection's
// records are stored: today a list inside one YAML file (`file:` and `path:`).
// Per-record layouts (a directory with one file per record) will arrive as
// another layout behind these functions; the planner and the console never
// look at files, paths or YAML lists themselves.

// newCollectionFiles returns the default data file and schema file of a new
// collection.
func newCollectionFiles(cfg *config.Config, name string) (data, schema string) {
	return path.Join(cfg.Types.DataDir, name+".yml"), path.Join(cfg.Types.SchemaDir, name+".json")
}

// seedData is the content of a data file created with a collection: an empty
// document (the first record is added through the console).
func seedData(title string) []byte {
	return []byte("# " + strings.NewReplacer("\n", " ", "\r", " ").Replace(title) + "\n")
}

// checkNewData says whether file (and the list at p inside it) can hold the
// records of a new collection. exists is true when the file is already there;
// it is then left alone.
func checkNewData(l *ledger.Ledger, file, p string) (exists bool, err error) {
	if ext := strings.ToLower(path.Ext(file)); ext != ".yml" && ext != ".yaml" {
		return false, errors.New("the data file must end in .yml or .yaml")
	}
	if _, err := l.Config.Resolve(file); err != nil {
		return false, err
	}
	for _, c := range l.Config.Collections {
		if c.File == file && c.Path == p {
			return false, fmt.Errorf("collection %q already stores its records in %s%s", c.Name, file, atPath(p))
		}
	}
	b, err := l.ReadFile(file)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if p != "" {
			return false, errors.New("a path inside the data file needs an existing file")
		}
		return false, nil
	case err != nil:
		return false, err
	}
	doc, err := yamledit.Parse(b)
	if err != nil {
		return true, fmt.Errorf("%s: %w", file, err)
	}
	if _, err := doc.Records(p); err != nil {
		return true, fmt.Errorf("%s: %w", file, err)
	}
	return true, nil
}

func atPath(p string) string {
	if p == "" {
		return ""
	}
	return " at " + p
}

// rewriteRecords replaces whole records of col (by position) in the overlay
// (config-relative file -> content), starting from the overlay's or the
// ledger's current text. Edits do not move records, so they can be chained.
func rewriteRecords(l *ledger.Ledger, col *ledger.Collection, edits map[int]map[string]any, newOrder []string, overlay map[string][]byte) error {
	if len(edits) == 0 {
		return nil
	}
	src, ok := overlay[col.File]
	if !ok {
		var err error
		if src, err = l.ReadFile(col.File); err != nil {
			return err
		}
	}
	opts := yamledit.Opts{Order: newOrder}
	if len(col.Key) > 0 {
		opts.GroupField = col.Key[0]
	}
	for _, rec := range col.Records { // file order keeps the result deterministic
		data, ok := edits[rec.Index]
		if !ok {
			continue
		}
		var err error
		if src, err = yamledit.Edit(src, col.Path, rec.Index, data, opts); err != nil {
			return err
		}
	}
	overlay[col.File] = src
	return nil
}
