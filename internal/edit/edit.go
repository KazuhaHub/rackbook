// Package edit applies one semantic change (add, edit or delete a record) to
// the YAML files of a ledger: it checks the base hash, splices the file,
// validates the whole ledger and only then writes.
package edit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/validate"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// Kind is the type of change.
type Kind string

const (
	Add    Kind = "add"
	Edit   Kind = "edit"
	Delete Kind = "delete"
)

// Op is a semantic edit. It carries no file positions, so it can be replayed
// on a newer checkout.
type Op struct {
	Kind       Kind
	Collection string
	ID         string         // edit, delete: the record being changed
	Hash       string         // edit, delete: base hash; empty skips the check
	Data       map[string]any // add, edit: the full new record
	// ClearReferences (delete): remove the references to the record from the
	// records that hold them, in the same change. Without it a record that is
	// still referenced is not deleted (*ReferencedError).
	ClearReferences bool
	// MayUpdate says whether the caller may update records of a collection. It is
	// asked for every collection whose records ClearReferences would edit; nil
	// means yes. A "no" refuses the delete with a *ForbiddenError.
	MayUpdate func(collection string) bool
}

// Result describes a successful change.
type Result struct {
	Kind       Kind
	Collection string
	ID         string // id after the change (the old id for delete)
	Hash       string
	Data       map[string]any
	Files      []string // config-relative files that were written; empty when nothing changed
	// SubjectID is the id shown in the commit subject and the Record trailer: ID,
	// or its redacted form when the key fields hold a secret.
	SubjectID string

	// SubjectText and RecordText replace the commit subject and the Record
	// trailer for changes that are not record edits (data type changes).
	SubjectText string
	RecordText  string
	// Cleared lists the references removed by a delete with ClearReferences.
	Cleared []ledger.Reference
}

// Changed reports whether any file was written.
func (r *Result) Changed() bool { return len(r.Files) > 0 }

// Subject is the commit subject for the change.
func (r *Result) Subject() string {
	if r.SubjectText != "" {
		return r.SubjectText
	}
	return fmt.Sprintf("ledger(%s): %s %s", r.Collection, r.Kind, sanitizeSubject(r.shownID()))
}

// Record is the value of the "Record:" commit trailer for this change.
func (r *Result) Record() string {
	if r.SubjectText != "" {
		return r.RecordText
	}
	return RecordRef(r.Collection, r.shownID())
}

func (r *Result) shownID() string {
	if r.SubjectID != "" {
		return r.SubjectID
	}
	return r.ID
}

// maxRecordID is how many characters of an id the trailer keeps.
const maxRecordID = 100

// RecordRef is the one definition of the "Record:" trailer value:
// "<collection>/<id>" on a single line. Control characters in the id become
// spaces; an id longer than 100 characters is cut to 100 and gets "~" and the
// first 8 hex digits of the SHA-256 of the whole id, so long ids stay stable
// and distinct. Both the commit trailer and the history search call this.
func RecordRef(collection, id string) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, id)
	if r := []rune(clean); len(r) > maxRecordID {
		sum := sha256.Sum256([]byte(id))
		clean = string(r[:maxRecordID]) + "~" + hex.EncodeToString(sum[:4])
	}
	return strings.TrimSpace(collection + "/" + clean)
}

// sanitizeSubject keeps ids from injecting extra lines or trailers into a
// commit message: control characters become spaces and the length is capped.
func sanitizeSubject(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120]) + "…"
	}
	return s
}

// Errors returned by Apply.
var (
	ErrUnknownCollection = errors.New("unknown collection")
	ErrBadRequest        = errors.New("bad request")
)

// ConflictError means the record changed (or exists, or vanished) since the base hash.
type ConflictError struct {
	Message string
	Current *ledger.Record // nil when the record no longer exists
}

func (e *ConflictError) Error() string { return e.Message }

// ForbiddenError means a change would edit records the caller may not edit:
// clearing references touches the collections that hold them.
type ForbiddenError struct{ Collection string }

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("clearing the references would edit records in %s, which you may not update", e.Collection)
}

// ReferencedError means other records still point at the record to delete.
type ReferencedError struct {
	Collection string
	ID         string
	Refs       []ledger.Reference
}

func (e *ReferencedError) Error() string {
	parts := make([]string, 0, len(e.Refs))
	for i, r := range e.Refs {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("and %d more", len(e.Refs)-5))
			break
		}
		parts = append(parts, fmt.Sprintf("%s/%s (%s)", r.Collection, r.ID, r.Field))
	}
	return fmt.Sprintf("%s %q is still referenced by %s", e.Collection, e.ID, strings.Join(parts, ", "))
}

// InvalidError carries the check errors a write would introduce.
type InvalidError struct{ Issues []ledger.Issue }

func (e *InvalidError) Error() string {
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		parts[i] = is.String()
	}
	return "the change would make the ledger invalid: " + strings.Join(parts, "; ")
}

// Normalize makes request data safe to write: json.Number becomes int64 or
// float64, and null values are dropped (an unset field is an absent key).
func Normalize(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if v == nil {
			continue
		}
		out[k] = normValue(v)
	}
	return out
}

func normValue(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normValue(e)
		}
		return out
	case map[string]any:
		return Normalize(x)
	}
	return v
}

// Apply performs op on the files under cfg.Dir.
func Apply(cfg *config.Config, op Op) (*Result, error) {
	base := ledger.Load(cfg, nil)
	c := base.Collection(op.Collection)
	if c == nil {
		return nil, fmt.Errorf("%w %q", ErrUnknownCollection, op.Collection)
	}
	src, err := base.ReadFile(c.File)
	if err != nil {
		return nil, err
	}
	opts := yamledit.Opts{Order: c.Schema.Order()}
	if len(c.Key) > 0 {
		opts.GroupField = c.Key[0]
	}
	if op.Kind != Delete {
		if len(op.Data) == 0 {
			return nil, fmt.Errorf("%w: data must not be empty", ErrBadRequest)
		}
		op.Data = Normalize(op.Data)
		// Before anything is read further or written: Rackbook runs Git without
		// hooks, so no pre-commit scanner would see this record.
		id := op.ID
		if op.Kind == Add {
			id = ledger.ID(c.Collection, len(c.Records), op.Data)
		}
		sc := cfg.SecretScanner()
		ann := secretscan.AnnotationsOf(c.SchemaRaw)
		bad := sc.ScanRecordWith(c.Name, ledger.SafeID(cfg, c.Name, id), op.Data, ann)
		if op.Kind == Edit && len(bad) > 0 {
			// A secret the record already holds is for `rackbook check` to report;
			// refusing every edit of such a record would also lock out the fix.
			if cur, err := findRecord(c, Op{Kind: Edit, ID: op.ID}); err == nil {
				bad = secretscan.Introduced(sc.ScanRecordWith(c.Name, ledger.SafeID(cfg, c.Name, id), cur.Data, ann), bad)
			}
		}
		if len(bad) > 0 {
			return nil, &secretscan.Error{Findings: bad}
		}
	}

	var out []byte
	var cur *ledger.Record
	newID := op.ID
	files := map[string][]byte{} // other files changed by the operation
	var cleared []ledger.Reference
	switch op.Kind {
	case Add:
		newID = ledger.ID(c.Collection, len(c.Records), op.Data)
		if ex := c.Get(newID); ex != nil && len(c.Key) > 0 {
			return nil, &ConflictError{Message: fmt.Sprintf("%s %q already exists", c.Name, ledger.SafeID(cfg, c.Name, newID)), Current: ex}
		}
		out, err = yamledit.Add(src, c.Path, op.Data, opts)
	case Edit, Delete:
		if cur, err = findRecord(c, op); err != nil {
			return nil, err
		}
		if op.Kind == Edit {
			newID = ledger.ID(c.Collection, cur.Index, op.Data)
			if ex := c.Get(newID); ex != nil && ex != cur && len(c.Key) > 0 {
				return nil, &ConflictError{Message: fmt.Sprintf("%s %q already exists", c.Name, ledger.SafeID(cfg, c.Name, newID)), Current: ex}
			}
			out, err = yamledit.Edit(src, c.Path, cur.Index, op.Data, opts)
		} else {
			delSrc := src
			if refs := base.ReferencesTo(c.Name, cur); len(refs) > 0 {
				if !op.ClearReferences {
					return nil, &ReferencedError{Collection: c.Name, ID: cur.ID, Refs: refs}
				}
				for _, r := range refs {
					if op.MayUpdate != nil && !op.MayUpdate(r.Collection) {
						return nil, &ForbiddenError{Collection: r.Collection}
					}
				}
				if files, err = clearReferences(base, refs, cfg.SecretScanner()); err != nil {
					return nil, err
				}
				cleared = refs
				if b, ok := files[c.File]; ok {
					delSrc = b // the record's own file also holds references to it
					delete(files, c.File)
				}
			}
			out, err = yamledit.Delete(delSrc, c.Path, cur.Index, opts)
		}
	default:
		return nil, fmt.Errorf("%w: unknown operation %q", ErrBadRequest, op.Kind)
	}
	if err != nil {
		return nil, err
	}
	res := &Result{Kind: op.Kind, Collection: op.Collection, ID: newID, Data: op.Data, Cleared: cleared, SubjectID: ledger.SafeID(cfg, op.Collection, newID)}
	if string(out) == string(src) && len(files) == 0 {
		res.Hash = ledger.Hash(op.Data)
		return res, nil
	}

	overlay := map[string][]byte{c.File: out}
	for f, b := range files {
		overlay[f] = b
	}
	after := ledger.Load(cfg, overlay)
	if bad := validate.Introduced(validate.Run(base), validate.Run(after)); len(bad) > 0 {
		return nil, &InvalidError{Issues: bad}
	}
	for f, b := range overlay {
		if err := writeFile(filepath.Join(cfg.Dir, filepath.FromSlash(f)), b); err != nil {
			return nil, err
		}
		res.Files = append(res.Files, f)
	}
	sort.Strings(res.Files)
	if op.Kind != Delete {
		if ac := after.Collection(op.Collection); ac != nil {
			if r := ac.Get(newID); r != nil {
				res.Hash, res.Data = r.Hash, r.Data
			} else if op.Kind == Add && len(ac.Records) > 0 {
				r := ac.Records[len(ac.Records)-1]
				res.ID, res.Hash, res.Data = r.ID, r.Hash, r.Data
			}
		}
	}
	return res, nil
}

// clearReferences removes the references refs from the records that hold them
// and returns the new content of every file it changed (config-relative path).
// Record positions do not move, so the references of one file are applied one
// after the other on the evolving text.
func clearReferences(l *ledger.Ledger, refs []ledger.Reference, sc *secretscan.Scanner) (map[string][]byte, error) {
	type recKey struct{ coll, id string }
	targets := map[recKey]map[string]map[string]bool{} // record -> field -> referenced values
	var order []recKey
	for _, r := range refs {
		k := recKey{r.Collection, r.ID}
		if targets[k] == nil {
			targets[k] = map[string]map[string]bool{}
			order = append(order, k)
		}
		if targets[k][r.Field] == nil {
			targets[k][r.Field] = map[string]bool{}
		}
		targets[k][r.Field][r.Value] = true
	}
	files := map[string][]byte{}
	var bad []secretscan.Finding
	for _, k := range order {
		c := l.Collection(k.coll)
		rec := c.Get(k.id)
		if rec == nil {
			continue
		}
		data := map[string]any{}
		for f, v := range rec.Data {
			data[f] = v
		}
		for field, values := range targets[k] {
			delete(data, field)
			if list, ok := rec.Data[field].([]any); ok { // a many-reference keeps its other values
				keep := []any{}
				for _, v := range list {
					if !values[ledger.Str(v)] {
						keep = append(keep, v)
					}
				}
				if len(keep) > 0 {
					data[field] = keep
				}
			}
		}
		ann := secretscan.AnnotationsOf(c.SchemaRaw)
		// Rewriting a record must not slip a secret in; one that was already
		// there is for `rackbook check` to report, not a reason to refuse.
		bad = append(bad, secretscan.Introduced(sc.ScanRecordWith(k.coll, ledger.SafeID(l.Config, k.coll, k.id), rec.Data, ann), sc.ScanRecordWith(k.coll, ledger.SafeID(l.Config, k.coll, k.id), data, ann))...)
		src, ok := files[c.File]
		if !ok {
			var err error
			if src, err = l.ReadFile(c.File); err != nil {
				return nil, err
			}
		}
		opts := yamledit.Opts{Order: c.Schema.Order()}
		if len(c.Key) > 0 {
			opts.GroupField = c.Key[0]
		}
		out, err := yamledit.Edit(src, c.Path, rec.Index, data, opts)
		if err != nil {
			return nil, err
		}
		files[c.File] = out
	}
	if len(bad) > 0 {
		return nil, &secretscan.Error{Findings: bad}
	}
	return files, nil
}

func findRecord(c *ledger.Collection, op Op) (*ledger.Record, error) {
	var rec *ledger.Record
	if len(c.Key) == 0 {
		if n, err := strconv.Atoi(strings.TrimPrefix(op.ID, "#")); err == nil {
			for _, r := range c.Records {
				if r.Index == n {
					rec = r
				}
			}
		}
	} else {
		rec = c.Get(op.ID)
	}
	if rec == nil {
		return nil, &ConflictError{Message: fmt.Sprintf("%s %q no longer exists", c.Name, op.ID)}
	}
	if op.Hash != "" && op.Hash != rec.Hash {
		return nil, &ConflictError{Message: fmt.Sprintf("%s %q was changed by someone else", c.Name, op.ID), Current: rec}
	}
	return rec, nil
}

// WriteFile replaces path atomically, keeping its permissions (0644 for a new file).
func WriteFile(path string, data []byte) error { return writeFile(path, data) }

func writeFile(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rackbook-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
