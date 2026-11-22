package config

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// ParseHistoric reads from an old rackbook.yml only what the history view needs
// of each collection: where its file is, the path of the list in it, its type
// file and its key fields. It is not Parse: it touches no file (no branding, no
// type), validates nothing, and ignores every field it does not know, so a
// rackbook.yml of an older or newer Rackbook still reads. A collection whose
// entry cannot be read as a mapping is left out.
func ParseHistoric(data []byte) (map[string]*Collection, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("rackbook.yml: %w", err)
	}
	out := map[string]*Collection{}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return out, nil
	}
	top := root.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "collections" || top.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		m := top.Content[i+1]
		for j := 0; j+1 < len(m.Content); j += 2 {
			c := &Collection{Name: m.Content[j].Value}
			if e := m.Content[j+1]; e.Kind == yaml.MappingNode {
				for k := 0; k+1 < len(e.Content); k += 2 {
					v := e.Content[k+1]
					switch e.Content[k].Value {
					case "file":
						c.File = scalar(v)
					case "path":
						c.Path = scalar(v)
					case "schema":
						c.Schema = scalar(v)
					case "key":
						if v.Kind == yaml.SequenceNode {
							for _, x := range v.Content {
								if s := scalar(x); s != "" {
									c.Key = append(c.Key, s)
								}
							}
						} else if s := scalar(v); s != "" {
							c.Key = []string{s} // an old form: a single field
						}
					}
				}
				out[c.Name] = c
			}
		}
	}
	return out, nil
}

func scalar(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}
