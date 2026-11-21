package ansiblerepo

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The setting types of features/<name>/feature.yml (the infra repository's
// docs/feature-spec.md).
const (
	TypeString = "string"
	TypeInt    = "int"
	TypeBool   = "bool"
	TypeEnum   = "enum"
)

const maxSettingLen = 512

// SettingSpec is one entry of a feature's `settings:`.
type SettingSpec struct {
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	Description  string         `json:"description,omitempty"`
	Enum         []string       `json:"enum,omitempty"`
	Default      any            `json:"default,omitempty"`
	Required     bool           `json:"required,omitempty"`
	RequiredWhen map[string]any `json:"requiredWhen,omitempty"`
	// Secret settings come from SOPS only; the editor refuses them.
	Secret  bool   `json:"secret,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Min     *int   `json:"min,omitempty"`
	Max     *int   `json:"max,omitempty"`

	re *regexp.Regexp
}

// FeatureSpec is a parsed feature.yml (only what the editors need).
type FeatureSpec struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Type        string        `json:"type,omitempty"`
	Settings    []SettingSpec `json:"settings"`
}

func (f *FeatureSpec) setting(name string) *SettingSpec {
	for i := range f.Settings {
		if f.Settings[i].Name == name {
			return &f.Settings[i]
		}
	}
	return nil
}

var featureNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidFeatureName reports whether s can be a directory name under features/.
func ValidFeatureName(s string) bool { return featureNameRe.MatchString(s) }

// ParseFeatureSpec reads a feature.yml. Settings keep their order in the file.
func ParseFeatureSpec(b []byte) (*FeatureSpec, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("feature.yml is not a mapping")
	}
	f := &FeatureSpec{Settings: []SettingSpec{}}
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		k, v := top.Content[i].Value, top.Content[i+1]
		switch k {
		case "name":
			f.Name = v.Value
		case "description":
			f.Description = v.Value
		case "type":
			f.Type = v.Value
		case "settings":
			if v.Kind != yaml.MappingNode {
				if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
					continue
				}
				return nil, fmt.Errorf("settings is not a mapping")
			}
			for j := 0; j+1 < len(v.Content); j += 2 {
				s, err := parseSetting(v.Content[j].Value, v.Content[j+1])
				if err != nil {
					return nil, fmt.Errorf("setting %s: %w", v.Content[j].Value, err)
				}
				f.Settings = append(f.Settings, *s)
			}
		}
	}
	return f, nil
}

func parseSetting(name string, n *yaml.Node) (*SettingSpec, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a mapping")
	}
	raw := map[string]any{}
	if err := n.Decode(&raw); err != nil {
		return nil, err
	}
	s := &SettingSpec{Name: name}
	s.Type, _ = raw["type"].(string)
	s.Description, _ = raw["description"].(string)
	s.Required, _ = raw["required"].(bool)
	s.Secret, _ = raw["secret"].(bool)
	s.Default = raw["default"]
	s.Pattern, _ = raw["pattern"].(string)
	if l, ok := raw["enum"].([]any); ok {
		for _, e := range l {
			s.Enum = append(s.Enum, fmt.Sprint(e))
		}
	}
	if m, ok := raw["required_when"].(map[string]any); ok {
		s.RequiredWhen = m
	}
	if v, ok := raw["min"].(int); ok {
		s.Min = &v
	}
	if v, ok := raw["max"].(int); ok {
		s.Max = &v
	}
	switch s.Type {
	case TypeString, TypeInt, TypeBool, TypeEnum:
	default:
		return nil, fmt.Errorf("unknown type %q", s.Type)
	}
	if s.Type == TypeString && s.Pattern != "" {
		re, err := regexp.Compile("^(?:" + s.Pattern + ")$") // the whole string must match
		if err != nil {
			return nil, fmt.Errorf("pattern: %w", err)
		}
		s.re = re
	}
	return s, nil
}

// settingProblem checks one value against its definition; "" = fine. The
// problem is a short code (type, enum, pattern, range, length, control,
// template).
func (s *SettingSpec) problem(v any) string {
	switch s.Type {
	case TypeBool:
		if _, ok := v.(bool); !ok {
			return "type"
		}
	case TypeInt:
		n, ok := asInt(v)
		if !ok {
			return "type"
		}
		if (s.Min != nil && n < *s.Min) || (s.Max != nil && n > *s.Max) {
			return "range"
		}
	case TypeEnum:
		str, ok := v.(string)
		if !ok {
			// an enum value that YAML read as a number or bool (on, 1, ...) still counts when its text is listed
			str = fmt.Sprint(v)
			if _, isMap := v.(map[string]any); isMap {
				return "type"
			}
		}
		for _, e := range s.Enum {
			if e == str {
				return ""
			}
		}
		return "enum"
	case TypeString:
		str, ok := v.(string)
		if !ok {
			return "type"
		}
		if len(str) > maxSettingLen {
			return "length"
		}
		for _, r := range str {
			if r < 0x20 || r == 0x7f {
				return "control"
			}
		}
		if strings.Contains(str, "{{") || strings.Contains(str, "{%") || strings.Contains(str, "{#") {
			return "template"
		}
		if s.re != nil && !s.re.MatchString(str) {
			return "pattern"
		}
	}
	return ""
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}

// effective is the value of a setting after defaults.
func (f *FeatureSpec) effective(settings map[string]any, name string) (any, bool) {
	if v, ok := settings[name]; ok && v != nil {
		return v, true
	}
	if s := f.setting(name); s != nil && s.Default != nil {
		return s.Default, true
	}
	return nil, false
}

// checkSettings validates one host's settings of this feature. The returned
// issues carry no file (the caller adds it).
func (f *FeatureSpec) checkSettings(settings map[string]any) []Issue {
	var out []Issue
	add := func(code, setting string, extra ...string) {
		p := map[string]string{"feature": f.Name, "setting": setting}
		for i := 0; i+1 < len(extra); i += 2 {
			p[extra[i]] = extra[i+1]
		}
		out = append(out, Issue{Code: code, Severity: SevError, Path: "features." + f.Name + "." + setting, Params: p})
	}
	names := make([]string, 0, len(settings))
	for k := range settings {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s := f.setting(k)
		if s == nil {
			add("feature.unknown_setting", k)
			continue
		}
		if s.Secret {
			add("feature.secret_in_vars", k)
			continue
		}
		if settings[k] == nil {
			continue
		}
		if p := s.problem(settings[k]); p != "" {
			extra := []string{"problem", p, "type", s.Type}
			add("feature.bad_value", k, extra...)
		}
	}
	for _, s := range f.Settings {
		if s.Secret {
			continue // required from SOPS; the repository's own check looks there
		}
		if _, have := f.effective(settings, s.Name); have {
			continue
		}
		need := s.Required
		for dep, want := range s.RequiredWhen {
			if cur, ok := f.effective(settings, dep); ok && fmt.Sprint(cur) == fmt.Sprint(want) {
				need = true
			}
		}
		if need {
			add("feature.missing_required", s.Name)
		}
	}
	return out
}

// SettingsFromInput turns the values of a form (JSON) into the settings to
// write, in the order of the feature's definition, and the names the form
// controls (every non-secret setting of the definition: the ones left out are
// reset to their default). A secret or unknown setting is refused: secret
// values come only from SOPS (a later phase), and an unknown one is a typing
// mistake. The values themselves are checked after the edit, with the rest.
func (f *FeatureSpec) SettingsFromInput(input map[string]any) (settings []Setting, known []string, issues []Issue) {
	names := make([]string, 0, len(input))
	for k := range input {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s := f.setting(k)
		switch {
		case s == nil:
			issues = append(issues, Issue{Code: "feature.unknown_setting", Severity: SevError, Path: "features." + f.Name + "." + k,
				Params: map[string]string{"feature": f.Name, "setting": k}, Message: fmt.Sprintf("%s: %s is not a setting of this feature", f.Name, k)})
		case s.Secret:
			issues = append(issues, Issue{Code: "feature.secret_refused", Severity: SevError, Path: "features." + f.Name + "." + k,
				Params: map[string]string{"feature": f.Name, "setting": k}, Message: fmt.Sprintf("%s: %s is a secret setting; secrets are edited in the SOPS file, not here", f.Name, k)})
		}
	}
	if len(issues) > 0 {
		return nil, nil, issues
	}
	for _, s := range f.Settings {
		if s.Secret {
			continue
		}
		known = append(known, s.Name)
		v, ok := input[s.Name]
		if !ok || v == nil {
			continue
		}
		if str, isStr := v.(string); isStr && str == Hidden {
			return nil, nil, []Issue{{Code: "feature.hidden_value", Severity: SevError, Path: "features." + f.Name + "." + s.Name,
				Params: map[string]string{"feature": f.Name, "setting": s.Name}, Message: fmt.Sprintf("%s: %s is hidden in the console and cannot be saved from it", f.Name, s.Name)}}
		}
		if n, isInt := asInt(v); isInt && s.Type == TypeInt {
			v = n
		}
		if str, isStr := v.(string); isStr && str == "" {
			continue // an empty box means "default"
		}
		settings = append(settings, Setting{Name: s.Name, Value: v})
	}
	return settings, known, nil
}
