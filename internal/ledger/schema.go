package ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Schema is the part of a JSON Schema rackbook needs for display and writes.
type Schema struct {
	Title       string
	Description string
	Required    []string
	Props       []Prop // in the order of "properties"
}

// Prop is one property of a record schema.
type Prop struct {
	Name        string
	Title       string
	Description string
	Type        string // first non-null type, "" if unspecified
}

// Label is the display name of a property: its title, else its name.
func (p Prop) Label() string {
	if p.Title != "" {
		return p.Title
	}
	return p.Name
}

// Prop returns the property with the given name.
func (s Schema) Prop(name string) (Prop, bool) {
	for _, p := range s.Props {
		if p.Name == name {
			return p, true
		}
	}
	return Prop{}, false
}

// Order lists property names in schema order.
func (s Schema) Order() []string {
	out := make([]string, len(s.Props))
	for i, p := range s.Props {
		out[i] = p.Name
	}
	return out
}

// ParseSchema extracts titles and property order from a JSON Schema document.
func ParseSchema(raw []byte) (Schema, error) {
	var top struct {
		Title       string          `json:"title"`
		Description string          `json:"description"`
		Required    []string        `json:"required"`
		Properties  json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return Schema{}, err
	}
	s := Schema{Title: top.Title, Description: top.Description, Required: top.Required}
	if len(top.Properties) == 0 {
		return s, nil
	}
	dec := json.NewDecoder(bytes.NewReader(top.Properties))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return Schema{}, fmt.Errorf("properties must be an object")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return Schema{}, err
		}
		var p struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Type        any    `json:"type"`
		}
		if err := dec.Decode(&p); err != nil && err != io.EOF {
			return Schema{}, err
		}
		s.Props = append(s.Props, Prop{Name: kt.(string), Title: p.Title, Description: p.Description, Type: firstType(p.Type)})
	}
	return s, nil
}

func firstType(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s != "null" {
				return s
			}
		}
	}
	return ""
}
