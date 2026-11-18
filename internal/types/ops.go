package types

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// KindTypes is the edit.Result kind of a type change.
const KindTypes edit.Kind = "types"

// ---- create --------------------------------------------------------------

func planCreate(base *ledger.Ledger, req Request, p *Plan) error {
	cfg := base.Config
	if req.Type == nil {
		return errors.New("type is required")
	}
	nt := normalizeIncoming(*req.Type, nil)
	if nt.Name == "" {
		nt.Name = req.Name
	}
	if req.Name != "" && nt.Name != req.Name {
		p.refuse("invalid", "", "the name in the body (%q) differs from the name in the URL (%q)", nt.Name, req.Name)
	}
	p.Name = nt.Name
	if nt.Title == "" {
		nt.Title = nt.Name
	}
	if !nameRe.MatchString(nt.Name) {
		p.refuse("invalid", "", "the name %q must be 1-40 characters: lowercase letters, digits and _, starting with a letter", nt.Name)
	}
	if base.Collection(nt.Name) != nil {
		p.refuse("exists", "", "a data type named %q already exists", nt.Name)
	}
	dataFile, schemaFile := newCollectionFiles(cfg, nt.Name)
	if nt.File == "" {
		nt.File = dataFile
	}
	if nt.SchemaFile == "" {
		nt.SchemaFile = schemaFile
	}
	p.Type = nt
	checkType(base, nil, nt, p)
	if _, err := cfg.Resolve(nt.SchemaFile); err != nil {
		p.refuse("invalid", "", "schema file: %v", err)
	} else if ext := strings.ToLower(filepath.Ext(nt.SchemaFile)); ext != ".json" {
		p.refuse("invalid", "", "the schema file must end in .json")
	} else if _, err := base.ReadFile(nt.SchemaFile); err == nil {
		p.refuse("exists", "", "the schema file %s already exists", nt.SchemaFile)
	}
	if err := checkNewPaths(base, nt); err != nil {
		p.refuse("invalid", "", "%v", err)
	}
	dataExists, err := checkNewData(base, nt.File, nt.Path)
	if err != nil {
		p.refuse("invalid", "", "data file: %v", err)
	}
	if len(p.Refusals) > 0 {
		return nil
	}
	schema, err := applySchema(nil, nil, nt)
	if err != nil {
		return err
	}
	cfgSrc, err := readConfig(cfg)
	if err != nil {
		return err
	}
	newCfg, err := yamledit.AddEntry(cfgSrc, "collections", nt.Name, newEntry(nt))
	if err != nil {
		return fmt.Errorf("rackbook.yml: %w", err)
	}
	if newCfg, err = spliceRules(newCfg, cfg, nt.Name, nt.Rules()); err != nil {
		return err
	}
	overlay := map[string][]byte{nt.SchemaFile: schema}
	p.files[configRel(cfg)] = newCfg
	p.files[nt.SchemaFile] = schema
	if !dataExists {
		seed := seedData(nt.Title)
		overlay[nt.File] = seed
		p.files[nt.File] = seed
	}
	p.subject = "ledger(types): add " + nt.Name
	return p.validateAfter(base, newCfg, overlay, nil, nt)
}

// ---- delete --------------------------------------------------------------

func planDelete(base *ledger.Ledger, req Request, p *Plan) error {
	cfg := base.Config
	col := base.Collection(req.Name)
	if col == nil {
		return fmt.Errorf("%w %q", ErrUnknownType, req.Name)
	}
	old, err := Load(base, req.Name)
	if err != nil {
		return err
	}
	if err := checkVersion(req, old); err != nil {
		return err
	}
	p.Type = old
	if n := len(col.Records); n > 0 {
		ids := []string{}
		for _, r := range col.Records {
			if len(ids) == 20 {
				break
			}
			ids = append(ids, r.ID)
		}
		p.Refusals = append(p.Refusals, Refusal{Code: "not-empty", Count: n, Records: ids,
			Message: fmt.Sprintf("%s still has %d record(s); delete them first", req.Name, n)})
	}
	for _, r := range cfg.Rules {
		switch {
		case r.Ref != nil:
			tc, tf, _ := config.SplitRef(r.Ref.To)
			if fc, ff, _ := config.SplitRef(r.Ref.From); tc == req.Name && fc != req.Name {
				p.refuse("referenced", tf, "%s.%s still references %s.%s; remove that reference first", fc, ff, tc, tf)
			}
		case r.SameSet != nil:
			if r.SameSet.Left.Collection == req.Name {
				p.refuse("same-set", "", "a same_set rule in rackbook.yml uses %s; remove the rule first", req.Name)
			}
		}
	}
	for _, n := range cfg.Notes {
		if n.Collection == req.Name {
			p.refuse("notes", "", "the note %q belongs to %s; remove it from rackbook.yml first", n.Title, req.Name)
		}
	}
	if len(p.Refusals) > 0 {
		return nil
	}
	cfgSrc, err := readConfig(cfg)
	if err != nil {
		return err
	}
	newCfg, err := yamledit.RemoveEntry(cfgSrc, "collections", req.Name)
	if err != nil {
		return fmt.Errorf("rackbook.yml: %w", err)
	}
	if newCfg, err = spliceRules(newCfg, cfg, req.Name, nil); err != nil {
		return err
	}
	p.files[configRel(cfg)] = newCfg
	if len(sharedSchema(cfg, req.Name, col.Collection.Schema)) == 0 {
		p.files[col.Collection.Schema] = nil
	}
	p.subject = "ledger(types): remove " + req.Name
	p.Type = nil
	if err := p.validateAfter(base, newCfg, map[string][]byte{}, nil, nil); err != nil {
		return err
	}
	p.Backrefs = backrefChanges(old, nil)
	return nil
}

// ---- apply ---------------------------------------------------------------

// Apply plans req on the files under cfg.Dir and, when the plan is clean,
// writes it: schema, rackbook.yml and, for a new type, its data file. The
// result names the files so that the caller commits them as one commit. An
// unclean plan returns *PlanError and writes nothing.
func Apply(cfg *config.Config, req Request) (*edit.Result, error) {
	p, err := Build(cfg, req)
	if err != nil {
		return nil, err
	}
	// A default, an example or a fill value typed into a data type is data too.
	// Checked before the plan's verdict, so the answer is secret_detected.
	if bad, _ := secretscan.Split(scanRequest(cfg, req, p)); len(bad) > 0 {
		// only block-tier findings: a schema or config has no console flow to confirm a heuristic one
		return nil, &secretscan.Error{Findings: bad}
	}
	if !p.Clean {
		return nil, &PlanError{Plan: p}
	}
	res := &edit.Result{Kind: KindTypes, Collection: req.Name, ID: req.Name}
	if len(p.files) == 0 {
		return res, nil
	}
	rels := make([]string, 0, len(p.files))
	for f := range p.files {
		rels = append(rels, f)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		abs, err := cfg.Resolve(rel)
		if err != nil {
			return nil, err
		}
		if p.files[rel] == nil {
			if err := os.Remove(abs); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, err
		}
		if err := edit.WriteFile(abs, p.files[rel]); err != nil {
			return nil, err
		}
	}
	res.Files = rels
	res.SubjectText = p.subject
	res.RecordText = ""
	return res, nil
}

// scanRequest scans what a type change would write: the defaults, examples,
// constants and enum values of every schema file, and the values of the chosen
// fill-default migrations.
func scanRequest(cfg *config.Config, req Request, p *Plan) []secretscan.Finding {
	sc := cfg.SecretScanner()
	var out []secretscan.Finding
	rels := make([]string, 0, len(p.files))
	for rel := range p.files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		b := p.files[rel]
		if b == nil {
			continue
		}
		var old []byte
		if abs, err := cfg.Resolve(rel); err == nil {
			old, _ = os.ReadFile(abs)
		}
		// What a file already held is for `rackbook check` to report. The schema
		// is scanned as a schema; rackbook.yml (the type's entry: title,
		// description, rules) and data files (a new type's seed, migrated records)
		// as YAML.
		if strings.HasSuffix(rel, ".json") {
			out = append(out, secretscan.Introduced(sc.ScanSchema(req.Name, old), sc.ScanSchema(req.Name, b))...)
		} else {
			out = append(out, secretscan.Introduced(sc.ScanYAML(rel, old), sc.ScanYAML(rel, b))...)
		}
	}
	for _, m := range req.Migrations {
		if m.Value != nil {
			out = append(out, sc.ScanRecord(req.Name, "", map[string]any{m.Field: m.Value})...)
		}
	}
	return out
}
