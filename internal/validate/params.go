package validate

import (
	"math/big"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/kazuhahub/rackbook/internal/config"
)

// structured returns the keyword that failed and the values its message is
// made of (see docs/api.md, GET /api/check), so a client can word the problem in its
// own language. Keywords without a documented shape get no params: clients
// show the English message for them.
func structured(k jsonschema.ErrorKind) (string, map[string]any) {
	// the keyword is the first element: dependentRequired and dependencies
	// add the property after it
	keyword := ""
	if p := k.KeywordPath(); len(p) > 0 {
		keyword = p[0]
	}
	switch k := k.(type) {
	case *kind.Type:
		return keyword, map[string]any{"want": k.Want, "got": k.Got}
	case *kind.Required:
		return keyword, map[string]any{"missing": k.Missing}
	case *kind.Dependency:
		// the library calls it "dependency"; the schema keyword is "dependencies"
		return "dependencies", map[string]any{"property": k.Prop, "missing": k.Missing}
	case *kind.DependentRequired:
		return keyword, map[string]any{"property": k.Prop, "missing": k.Missing}
	case *kind.Const:
		return keyword, map[string]any{"want": k.Want}
	case *kind.Format:
		return keyword, map[string]any{"value": k.Got, "format": k.Want}
	case *kind.Pattern:
		return keyword, map[string]any{"value": k.Got, "pattern": k.Want}
	case *kind.MinLength:
		return keyword, map[string]any{"limit": k.Want, "got": k.Got}
	case *kind.MaxLength:
		return keyword, map[string]any{"limit": k.Want, "got": k.Got}
	case *kind.MinItems:
		return keyword, map[string]any{"limit": k.Want, "got": k.Got}
	case *kind.MaxItems:
		return keyword, map[string]any{"limit": k.Want, "got": k.Got}
	case *kind.MinProperties:
		return keyword, map[string]any{"limit": k.Want, "got": k.Got}
	case *kind.MaxProperties:
		return keyword, map[string]any{"limit": k.Want, "got": k.Got}
	case *kind.Minimum:
		return keyword, map[string]any{"limit": number(k.Want), "value": number(k.Got)}
	case *kind.Maximum:
		return keyword, map[string]any{"limit": number(k.Want), "value": number(k.Got)}
	case *kind.ExclusiveMinimum:
		return keyword, map[string]any{"limit": number(k.Want), "value": number(k.Got)}
	case *kind.ExclusiveMaximum:
		return keyword, map[string]any{"limit": number(k.Want), "value": number(k.Got)}
	case *kind.MultipleOf:
		return keyword, map[string]any{"limit": number(k.Want), "value": number(k.Got)}
	case *kind.UniqueItems:
		return keyword, map[string]any{"first": k.Duplicates[0], "second": k.Duplicates[1]}
	case *kind.AdditionalProperties:
		return keyword, map[string]any{"properties": k.Properties}
	case *kind.Enum:
		return keyword, map[string]any{"allowed": k.Want}
	}
	return keyword, nil
}

// number is a schema number as JSON: the nearest float64, which encodes as the
// shortest text that reads back as it (0.1 stays "0.1").
func number(r *big.Rat) any {
	if r == nil {
		return nil
	}
	f, _ := r.Float64()
	return f
}

// ruleText adds a rule's own message (rackbook.yml message, default language)
// and its translations (i18n.<locale>.message) to params, when it has them.
func ruleText(params map[string]any, message string, i18n config.Texts) map[string]any {
	if message != "" {
		params["ruleMessage"] = message
	}
	tr := map[string]string{}
	for l, t := range i18n {
		if m := t["message"]; m != "" {
			tr[l] = m
		}
	}
	if len(tr) > 0 {
		params["ruleMessageI18n"] = tr
	}
	return params
}
