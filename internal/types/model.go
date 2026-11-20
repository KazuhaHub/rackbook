// Package types manages the data types (collections) of a ledger: the fields
// of a collection, its relations and its checks. A Type is the console's view
// of one collection; it maps both ways onto the JSON Schema file, the
// collection's entry in rackbook.yml and the rules that involve it. Changes
// are planned in memory (Plan) and then applied as one commit (Apply).
package types

import (
	"encoding/json"

	"github.com/kazuhahub/rackbook/internal/config"
)

// Console field types. The type is stored as x-rackbook-type on the property;
// the JSON Schema keywords carry the meaning.
const (
	TText        = "text"
	TTextarea    = "textarea"
	TInteger     = "integer"
	TNumber      = "number"
	TIP          = "ip"
	TIPv4        = "ipv4"
	TIPv6        = "ipv6"
	TCIDR        = "cidr"
	TPort        = "port"
	TPortSpec    = "port-spec"
	THostname    = "hostname"
	TCountry     = "country"     // ISO 3166-1 alpha-2 code or tbd
	TSubdivision = "subdivision" // ISO 3166-2 code or tbd
	TURL         = "url"
	TEnum        = "enum"
	TBool        = "bool"
	TDate        = "date"
	TRef         = "ref"
	// TAdvanced is a property the console cannot express (nested objects,
	// oneOf, nullable types...). It is kept as it is and edited in YAML.
	TAdvanced = "advanced"
)

// FieldTypes lists the types in the order the console offers them.
var FieldTypes = []string{TText, TTextarea, TInteger, TNumber, TIP, TIPv4, TIPv6, TCIDR, TPort, TPortSpec, THostname, TCountry, TSubdivision, TURL, TEnum, TBool, TDate, TRef}

// Type is one collection as the console edits it.
type Type struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Group       string `json:"group,omitempty"`
	Icon        string `json:"icon,omitempty"`
	// I18n is title, description and group in the other languages, by locale tag
	// (the collection's i18n entry in rackbook.yml). The standard text above is in
	// the ledger's default language.
	I18n map[string]map[string]string `json:"i18n,omitempty"`

	// Where the records live. Set when a type is created and fixed afterwards.
	File       string `json:"file"`
	Path       string `json:"path,omitempty"`
	SchemaFile string `json:"schemaFile"`

	Key    []string       `json:"key"`
	Label  string         `json:"label,omitempty"`
	List   []string       `json:"list"`
	Facets []config.Facet `json:"facets"`

	Fields []Field `json:"fields"`
	// Unique holds the unique rules over several fields; a rule over one field
	// is Field.Unique.
	Unique [][]string `json:"unique"`

	// Read-only: parts of the schema and rules the console does not edit.
	Extras  []Extra   `json:"extras,omitempty"`  // other top-level schema keywords
	SameSet []SameSet `json:"sameSet,omitempty"` // same_set rules that mention this collection
	Count   int       `json:"count"`             // records (output only)

	// Version identifies the schema file and the collection entry this Type was
	// read from (a hash). A change or delete that carries a Version other than
	// the current one is refused with a *VersionError: somebody else changed the
	// type in between.
	Version string `json:"version,omitempty"`
}

// Field is one property of the collection's schema.
type Field struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Unique      bool   `json:"unique"`
	Default     any    `json:"default,omitempty"`
	// I18n is title and description in the other languages (x-rackbook-i18n).
	I18n map[string]map[string]string `json:"i18n,omitempty"`

	// Options by type.
	MinLength *int       `json:"minLength,omitempty"` // text
	MaxLength *int       `json:"maxLength,omitempty"`
	Pattern   string     `json:"pattern,omitempty"`
	Examples  []string   `json:"examples,omitempty"`
	Min       *float64   `json:"min,omitempty"` // integer, number
	Max       *float64   `json:"max,omitempty"`
	Enum      []EnumItem `json:"enum,omitempty"` // enum
	Ref       *Ref       `json:"ref,omitempty"`  // ref

	// Read-only. Advanced is true when keywords the console does not know are
	// present (Extras) or the property is not one of the console types.
	Advanced bool    `json:"advanced,omitempty"`
	Extras   []Extra `json:"extras,omitempty"`
}

// EnumItem is one allowed value, with an optional badge colour, icon and labels.
// Value is the stored code. Label is the default-language label (the oneOf
// title); Labels hold the other languages (x-rackbook-i18n.<locale>.enum).
type EnumItem struct {
	Value  string            `json:"value"`
	Color  string            `json:"color,omitempty"`
	Icon   string            `json:"icon,omitempty"` // lucide icon name, kebab-case
	Label  string            `json:"label,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Ref is a reference to a field of another collection (a ref rule in rackbook.yml).
type Ref struct {
	To      string   `json:"to"`      // target collection
	ToField string   `json:"toField"` // target field (default: its key)
	Allow   []string `json:"allow,omitempty"`
	Many    bool     `json:"many,omitempty"`
	Message string   `json:"message,omitempty"`
	// BackrefTitle and BackrefColumns shape the section on the target's detail page.
	BackrefTitle   string   `json:"backrefTitle,omitempty"`
	BackrefColumns []string `json:"backrefColumns,omitempty"`
	// I18n is message and backref_title in the other languages:
	// {"<locale>": {"message"?, "backref_title"?}}. A request that leaves it out
	// keeps what the rule has.
	I18n map[string]map[string]string `json:"i18n,omitempty"`
}

// Extra is a schema keyword the console keeps but does not edit.
type Extra struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// SameSet is a same_set rule, shown read-only (edit it in rackbook.yml).
type SameSet struct {
	Message string `json:"message,omitempty"`
	Left    string `json:"left"`  // collection.field [where ...]
	Right   string `json:"right"` // file path
}

// Field returns the field with the given name.
func (t *Type) Field(name string) *Field {
	for i := range t.Fields {
		if t.Fields[i].Name == name {
			return &t.Fields[i]
		}
	}
	return nil
}

// Rules returns the rules this type owns: its ref rules and its unique rules.
func (t *Type) Rules() []config.Rule {
	var out []config.Rule
	for _, f := range t.Fields {
		if f.Ref == nil {
			continue
		}
		out = append(out, config.Rule{Ref: &config.RefRule{
			From: t.Name + "." + f.Name, To: f.Ref.To + "." + f.Ref.ToField,
			Allow: f.Ref.Allow, Many: f.Ref.Many, Message: f.Ref.Message,
			BackrefTitle: f.Ref.BackrefTitle, BackrefColumns: f.Ref.BackrefColumns,
			I18n: config.Texts(f.Ref.I18n),
		}})
	}
	for _, f := range t.Fields {
		if f.Unique {
			out = append(out, config.Rule{Unique: &config.UniqueRule{Collection: t.Name, Fields: []string{f.Name}}})
		}
	}
	for _, u := range t.Unique {
		out = append(out, config.Rule{Unique: &config.UniqueRule{Collection: t.Name, Fields: u}})
	}
	return out
}
