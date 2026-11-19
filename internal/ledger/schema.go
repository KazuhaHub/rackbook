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
	// ItemOrder is the order of the properties of the objects this property
	// holds (an object, or the items of an array), empty for other types.
	ItemOrder []string
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
			Title       string          `json:"title"`
			Description string          `json:"description"`
			Type        any             `json:"type"`
			Properties  json.RawMessage `json:"properties"`
			Items       struct {
				Properties json.RawMessage `json:"properties"`
			} `json:"items"`
		}
		if err := dec.Decode(&p); err != nil && err != io.EOF {
			return Schema{}, err
		}
		s.Props = append(s.Props, Prop{Name: kt.(string), Title: p.Title, Description: p.Description, Type: firstType(p.Type), ItemOrder: objectKeys(first(p.Items.Properties, p.Properties))})
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

func first(a, b json.RawMessage) json.RawMessage {
	if len(a) > 0 {
		return a
	}
	return b
}

// objectKeys lists the keys of a JSON object in document order.
func objectKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return keys
		}
		keys = append(keys, kt.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return keys
		}
	}
	return keys
}

// ItemOrders maps a property name to the order of the keys of the objects it holds.
func (s Schema) ItemOrders() map[string][]string {
	var out map[string][]string
	for _, p := range s.Props {
		if len(p.ItemOrder) > 0 {
			if out == nil {
				out = map[string][]string{}
			}
			out[p.Name] = p.ItemOrder
		}
	}
	return out
}
