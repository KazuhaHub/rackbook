package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/yamledit"
	"github.com/kazuhahub/rackbook/modsettings"
)

// KindModules is the edit.Result kind of a settings change.
const KindModules edit.Kind = "modules"

// Errors of Apply.
var (
	ErrUnknownModule = errors.New("no such module")
	ErrNoSettings    = errors.New("this module has no settings in the console")
)

// InvalidError is a settings change that is refused with a reason.
type InvalidError struct{ Message string }

func (e *InvalidError) Error() string { return e.Message }

// VersionError means the settings changed since the version the editor read.
type VersionError struct {
	Current map[string]any
	Version string
}

func (e *VersionError) Error() string {
	return "the settings changed since you opened them; reload and apply your change again"
}

// ImpactError means the change retires or freezes records and the editor has
// not confirmed it.
type ImpactError struct{ Impact Impact }

func (e *ImpactError) Error() string {
	return "this change affects records of the module; confirm it (confirm_impact) after looking at the preview"
}

// Change replaces the settings of one module.
type Change struct {
	Name string
	// Version is the version of the settings the editor started from.
	Version string
	// Settings is the complete new set; keys that are left out are removed.
	Settings map[string]any
	// ConfirmImpact says the editor has seen the preview of a risky change.
	ConfirmImpact bool
}

// Current returns the module's settings as stored (only values that are set)
// and their version.
func Current(m *config.Module) (map[string]any, string) {
	if m == nil || m.ParsedSettings() == nil {
		return map[string]any{}, modsettings.Version(map[string]any{})
	}
	cur := modsettings.Map(m.ParsedSettings())
	return cur, modsettings.Version(cur)
}

// Apply checks the change against the current rackbook.yml and writes it:
// version check, validation of every value, the preview rule for risky
// changes, the secret scan, and an in-place edit that touches only the
// settings lines. The result names the file so the caller commits it.
func Apply(cfg *config.Config, ch Change) (*edit.Result, error) {
	m := cfg.Modules[ch.Name]
	if m == nil {
		return nil, fmt.Errorf("%w %q", ErrUnknownModule, ch.Name)
	}
	if m.Type == "" || m.ParsedSettings() == nil {
		return nil, ErrNoSettings
	}
	old, version := Current(m)
	if ch.Version == "" {
		return nil, &InvalidError{"version is required: send the version you read (GET /api/modules)"}
	}
	if ch.Version != version {
		return nil, &VersionError{Current: old, Version: version}
	}
	next, err := modsettings.DecodeAndValidate(m.Type, ch.Settings, func(c string) bool { return cfg.Collection(c) != nil })
	if err != nil {
		return nil, &InvalidError{err.Error()}
	}
	nextMap := modsettings.Map(next)
	changed := modsettings.ChangedKeys(old, nextMap)
	res := &edit.Result{Kind: KindModules, Collection: "modules", ID: ch.Name}
	if len(changed) == 0 {
		return res, nil
	}
	if imp := PreviewImpact(cfg, ch.Name, next); imp.Risky && len(imp.Records) > 0 && !ch.ConfirmImpact {
		return nil, &ImpactError{Impact: imp}
	}
	if strings.Contains(ch.Name, ".") {
		return nil, &InvalidError{fmt.Sprintf("the module name %q has a dot, which the console cannot edit; change modules.%s.settings in rackbook.yml by hand", ch.Name, ch.Name)}
	}
	src, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, err
	}
	out, err := splice(src, ch.Name, modsettings.Keys(m.Type), old, nextMap)
	if err != nil {
		return nil, &InvalidError{err.Error()}
	}
	// The result must load and say what was asked, whatever the file looked like.
	chk, err := config.Parse(out, cfg.Path)
	if err != nil {
		return nil, &InvalidError{"the new rackbook.yml would not load: " + err.Error()}
	}
	if cm := chk.Modules[ch.Name]; cm == nil || cm.ParsedSettings() == nil || !reflect.DeepEqual(canon(modsettings.Map(cm.ParsedSettings())), canon(nextMap)) {
		return nil, &InvalidError{"the edit would not give the settings you asked for; change modules." + ch.Name + ".settings in rackbook.yml by hand"}
	}
	rel := relConfig(cfg)
	sc := cfg.SecretScanner()
	if bad, _ := secretscan.Split(secretscan.Introduced(sc.ScanYAML(rel, src), sc.ScanYAML(rel, out))); len(bad) > 0 {
		return nil, &secretscan.Error{Findings: bad}
	}
	if err := edit.WriteFile(cfg.Path, out); err != nil {
		return nil, err
	}
	res.Files = []string{rel}
	res.SubjectText = fmt.Sprintf("modules(%s): change %s", ch.Name, strings.Join(changed, ", "))
	return res, nil
}

func canon(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func relConfig(cfg *config.Config) string {
	rel, err := filepath.Rel(cfg.Dir, cfg.Path)
	if err != nil {
		return filepath.Base(cfg.Path)
	}
	return filepath.ToSlash(rel)
}

// splice turns the settings of modules.<name> from old into next in the text
// of rackbook.yml, touching only the settings lines. order is the order of keys
// a new settings block gets.
func splice(src []byte, name string, order []string, old, next map[string]any) ([]byte, error) {
	path := "modules." + name
	hadSettings := len(old) > 0
	if doc, err := yamledit.Parse(src); err == nil {
		if _, ok := doc.Lookup(path + ".settings"); ok {
			hadSettings = true
		}
	}
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range next {
		keys[k] = true
	}
	var all []string
	for _, k := range order {
		if keys[k] {
			all = append(all, k)
		}
	}
	switch {
	case len(next) == 0:
		out, err := yamledit.RemoveEntry(src, path, "settings")
		return wrap(out, err, name)
	case !hadSettings:
		var fields []yamledit.EntryChange
		for _, k := range all {
			if _, ok := next[k]; ok {
				fields = append(fields, yamledit.EntryChange{Key: k, Value: next[k]})
			}
		}
		out, err := yamledit.AddEntry(src, path, "settings", fields)
		return wrap(out, err, name)
	}
	var changes []yamledit.EntryChange
	for _, k := range all {
		if v, ok := next[k]; ok {
			changes = append(changes, yamledit.EntryChange{Key: k, Value: v})
		} else {
			changes = append(changes, yamledit.EntryChange{Key: k, Remove: true})
		}
	}
	out, err := yamledit.SetEntry(src, path, "settings", changes, order)
	return wrap(out, err, name)
}

func wrap(out []byte, err error, name string) ([]byte, error) {
	if err == nil {
		return out, nil
	}
	if errors.Is(err, yamledit.ErrUnsupported) || errors.Is(err, yamledit.ErrNoEntry) {
		return nil, fmt.Errorf("the console cannot edit modules.%s in this form (%v); change its settings in rackbook.yml by hand", name, err)
	}
	return nil, err
}
