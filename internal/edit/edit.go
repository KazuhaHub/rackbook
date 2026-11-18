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
	"strconv"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
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
}

// Result describes a successful change.
type Result struct {
	Kind       Kind
	Collection string
	ID         string // id after the change (the old id for delete)
	Hash       string
	Data       map[string]any
	Files      []string // config-relative files that were written; empty when nothing changed
}

// Changed reports whether any file was written.
func (r *Result) Changed() bool { return len(r.Files) > 0 }

// Subject is the commit subject for the change.
func (r *Result) Subject() string {
	return fmt.Sprintf("ledger(%s): %s %s", r.Collection, r.Kind, sanitizeSubject(r.ID))
}

// Record is the value of the "Record:" commit trailer for this change.
func (r *Result) Record() string { return RecordRef(r.Collection, r.ID) }

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
	}

	var out []byte
	var cur *ledger.Record
	newID := op.ID
	switch op.Kind {
	case Add:
		newID = ledger.ID(c.Collection, len(c.Records), op.Data)
		if ex := c.Get(newID); ex != nil && len(c.Key) > 0 {
			return nil, &ConflictError{Message: fmt.Sprintf("%s %q already exists", c.Name, newID), Current: ex}
		}
		out, err = yamledit.Add(src, c.Path, op.Data, opts)
	case Edit, Delete:
		if cur, err = findRecord(c, op); err != nil {
			return nil, err
		}
		if op.Kind == Edit {
			newID = ledger.ID(c.Collection, cur.Index, op.Data)
			if ex := c.Get(newID); ex != nil && ex != cur && len(c.Key) > 0 {
				return nil, &ConflictError{Message: fmt.Sprintf("%s %q already exists", c.Name, newID), Current: ex}
			}
			out, err = yamledit.Edit(src, c.Path, cur.Index, op.Data, opts)
		} else {
			out, err = yamledit.Delete(src, c.Path, cur.Index, opts)
		}
	default:
		return nil, fmt.Errorf("%w: unknown operation %q", ErrBadRequest, op.Kind)
	}
	if err != nil {
		return nil, err
	}
	res := &Result{Kind: op.Kind, Collection: op.Collection, ID: newID, Data: op.Data}
	if string(out) == string(src) {
		res.Hash = ledger.Hash(op.Data)
		return res, nil
	}

	after := ledger.Load(cfg, map[string][]byte{c.File: out})
	if bad := validate.Introduced(validate.Run(base), validate.Run(after)); len(bad) > 0 {
		return nil, &InvalidError{Issues: bad}
	}
	if err := writeFile(filepath.Join(cfg.Dir, filepath.FromSlash(c.File)), out); err != nil {
		return nil, err
	}
	res.Files = []string{c.File}
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

// writeFile replaces path atomically, keeping its permissions.
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
