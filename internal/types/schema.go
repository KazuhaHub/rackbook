package types

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/labels"
	"github.com/kazuhahub/rackbook/internal/locale"
)

// The JSON Schema side of a Type. A schema is read into Fields and written
// back through an ordered object, so keys the console does not know are kept
// where they were.

const (
	kwType     = "x-rackbook-type"
	kwColors   = "x-rackbook-enum-colors"
	kwIcons    = labels.KeyIcons
	kwI18n     = labels.KeyI18n
	schemaDraf = "https://json-schema.org/draft/2020-12/schema"
)

var rootKnown = map[string]bool{"$schema": true, "title": true, "description": true, "type": true, "additionalProperties": true, "required": true, "properties": true}

// jsonType and format written for each console type.
func schemaShape(f Field) (jtype, format string) {
	switch f.Type {
	case TInteger, TPort:
		return "integer", ""
	case TNumber:
		return "number", ""
	case TBool:
		return "boolean", ""
	case TRef:
		if f.Ref != nil && f.Ref.Many {
			return "array", ""
		}
		return "string", ""
	case TTextarea:
		return "string", "textarea"
	case TIP:
		return "string", "ip"
	case TIPv4:
		return "string", "ipv4"
	case TIPv6:
		return "string", "ipv6"
	case TCIDR:
		return "string", "cidr"
	case TPortSpec:
		return "string", "port-spec"
	case THostname:
		return "string", "hostname"
	case TCountry:
		return "string", "country"
	case TSubdivision:
		return "string", "subdivision"
	case TURL:
		return "string", "uri"
	case TDate:
		return "string", "date"
	}
	return "string", ""
}

var formatToType = map[string]string{
	"textarea": TTextarea, "ip": TIP, "ipv4": TIPv4, "ipv6": TIPv6, "cidr": TCIDR,
	"port-spec": TPortSpec, "hostname": THostname, "uri": TURL, "date": TDate,
	"country": TCountry, "subdivision": TSubdivision,
}

// known lists the keywords the console manages for a type.
func known(t string) map[string]bool {
	k := map[string]bool{"title": true, "description": true, kwType: true, kwI18n: true}
	add := func(s ...string) {
		for _, x := range s {
			k[x] = true
		}
	}
	switch t {
	case TText:
		add("type", "default", "minLength", "maxLength", "pattern", "examples")
	case TInteger, TNumber:
		add("type", "default", "minimum", "maximum")
	case TPort:
		add("type", "default", "minimum", "maximum")
	case TEnum:
		add("type", "default", "enum", "oneOf", kwColors, kwIcons)
	case TBool:
		add("type", "default")
	case TRef:
		add("type", "items")
	case TAdvanced:
	case "":
	default: // textarea, ip, ..., date
		add("type", "default", "format")
	}
	return k
}

func str(m *omap, k string) string {
	s, _ := m.vals[k].(string)
	return s
}

func compact(v any) json.RawMessage { return json.RawMessage(inlineJSON(v)) }

func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func intOf(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.Atoi(n.String())
	return i, err == nil && i >= 0
}

func stringList(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, json.Number, bool, nil:
		return true
	}
	return false
}

// plain converts an ordered value into plain maps and slices, the form the
// labels package reads.
func plain(v any) any {
	switch x := v.(type) {
	case *omap:
		m := make(map[string]any, len(x.keys))
		for _, k := range x.keys {
			m[k] = plain(x.vals[k])
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = plain(e)
		}
		return out
	}
	return v
}

// enumOf reads a property as an enum-like one: a string with a plain enum or a
// oneOf of const/title entries. A property that has both keywords is not one
// (the console cannot tell which to edit), so it stays advanced.
func enumOf(prop *omap) (*labels.Enum, bool) {
	_, hasEnum := prop.vals["enum"]
	_, hasOneOf := prop.vals["oneOf"]
	if hasEnum && hasOneOf {
		return nil, false
	}
	small := map[string]any{}
	for _, k := range []string{"type", "enum", "oneOf", kwI18n, kwIcons} {
		if v, ok := prop.vals[k]; ok {
			small[k] = plain(v)
		}
	}
	return labels.Parse(small)
}

// i18nClean reports whether the x-rackbook-i18n value has the shape the
// console reads and writes back without losing anything: an object of objects,
// and in the supported languages string title and description and an enum
// object of strings. Anything else is kept as it is and edited by hand.
func i18nClean(v any) bool {
	m, ok := v.(*omap)
	if !ok {
		return false
	}
	for _, loc := range m.keys {
		lo, ok := m.vals[loc].(*omap)
		if !ok {
			return false
		}
		if !labels.Supported(loc) {
			continue
		}
		for _, k := range []string{"title", "description"} {
			if x, has := lo.vals[k]; has {
				if _, ok := x.(string); !ok {
					return false
				}
			}
		}
		if x, has := lo.vals["enum"]; has {
			em, ok := x.(*omap)
			if !ok {
				return false
			}
			for _, c := range em.keys {
				if _, ok := em.vals[c].(string); !ok {
					return false
				}
			}
		}
	}
	return true
}

// iconsClean reports whether x-rackbook-enum-icons is an object of strings.
func iconsClean(v any) bool {
	m, ok := v.(*omap)
	if !ok {
		return false
	}
	for _, c := range m.keys {
		if _, ok := m.vals[c].(string); !ok {
			return false
		}
	}
	return true
}

// fieldI18n reads the title and description translations of the supported
// languages.
func fieldI18n(prop *omap) map[string]map[string]string {
	m, _ := prop.vals[kwI18n].(*omap)
	if m == nil {
		return nil
	}
	out := labels.Translations(map[string]any{kwI18n: plain(m)})
	if len(out) == 0 {
		return nil
	}
	return out
}

// detectType decides the console type of a property.
func detectType(prop *omap, ref *config.RefRule) string {
	jt, _ := prop.vals["type"].(string)
	format := str(prop, "format")
	if ref != nil {
		if jt == "string" && !ref.Many {
			return TRef
		}
		if jt == "array" && ref.Many {
			if items, ok := prop.vals["items"].(*omap); ok && len(items.keys) == 1 && str(items, "type") == "string" {
				return TRef
			}
		}
		return TAdvanced
	}
	if x := str(prop, kwType); x != "" && x != TRef && x != TAdvanced && compatible(x, jt, format, prop) {
		return x
	}
	switch jt {
	case "string":
		if t, ok := formatToType[format]; ok {
			return t
		}
		if _, ok := enumOf(prop); ok {
			return TEnum
		}
		if _, ok := prop.vals["enum"]; ok {
			return TAdvanced
		}
		return TText
	case "integer":
		if lo, ok := number(prop.vals["minimum"]); ok && lo == 1 {
			if hi, ok := number(prop.vals["maximum"]); ok && hi == 65535 {
				return TPort
			}
		}
		return TInteger
	case "number":
		return TNumber
	case "boolean":
		return TBool
	}
	return TAdvanced
}

func compatible(t, jt, format string, prop *omap) bool {
	switch t {
	case TText:
		return jt == "string" && format == ""
	case TInteger, TPort:
		return jt == "integer"
	case TNumber:
		return jt == "number"
	case TBool:
		return jt == "boolean"
	case TEnum:
		_, ok := enumOf(prop)
		return jt == "string" && ok
	}
	want, ok := formatToType[format]
	return ok && want == t && jt == "string"
}

// fieldFromProp reads one schema property.
func fieldFromProp(name string, v any, ref *config.RefRule) Field {
	f := Field{Name: name}
	prop, ok := v.(*omap)
	if !ok { // `true`, `false` or something else that is not an object
		f.Type, f.Advanced = TAdvanced, true
		f.Extras = []Extra{{Key: "schema", Value: compact(v)}}
		return f
	}
	f.Title, f.Description = str(prop, "title"), str(prop, "description")
	f.Type = detectType(prop, ref)
	extraI18n := false
	if v, has := prop.vals[kwI18n]; has {
		if i18nClean(v) {
			f.I18n = fieldI18n(prop)
		} else {
			extraI18n = true
		}
	}
	if ref != nil {
		f.Ref = &Ref{ToField: "", Allow: ref.Allow, Many: ref.Many, Message: ref.Message, BackrefTitle: ref.BackrefTitle, BackrefColumns: ref.BackrefColumns,
			I18n: ref.I18n.Only("message", "backref_title")}
		f.Ref.To, f.Ref.ToField, _ = config.SplitRef(ref.To)
	}
	k := known(f.Type)
	extra := map[string]bool{kwI18n: extraI18n}
	if f.Type != TAdvanced {
		if d, has := prop.vals["default"]; has && k["default"] {
			if isScalar(d) {
				f.Default = d
			} else {
				extra["default"] = true
			}
		}
	}
	switch f.Type {
	case TText:
		if n, has := prop.vals["minLength"]; has {
			if i, ok := intOf(n); ok {
				f.MinLength = &i
			} else {
				extra["minLength"] = true
			}
		}
		if n, has := prop.vals["maxLength"]; has {
			if i, ok := intOf(n); ok {
				f.MaxLength = &i
			} else {
				extra["maxLength"] = true
			}
		}
		if p, has := prop.vals["pattern"]; has {
			if s, ok := p.(string); ok {
				f.Pattern = s
			} else {
				extra["pattern"] = true
			}
		}
		if e, has := prop.vals["examples"]; has {
			if l, ok := stringList(e); ok {
				f.Examples = l
			} else {
				extra["examples"] = true
			}
		}
	case TInteger, TNumber:
		for key, dst := range map[string]**float64{"minimum": &f.Min, "maximum": &f.Max} {
			if n, has := prop.vals[key]; has {
				if x, ok := number(n); ok {
					*dst = &x
				} else {
					extra[key] = true
				}
			}
		}
	case TEnum:
		colors, _ := prop.vals[kwColors].(*omap)
		if c, has := prop.vals[kwColors]; has && colors == nil {
			_ = c
			extra[kwColors] = true
		}
		if v, has := prop.vals[kwIcons]; has && !iconsClean(v) {
			extra[kwIcons] = true
		}
		e, _ := enumOf(prop)
		for _, it := range e.Items {
			item := EnumItem{Value: it.Code, Label: it.Label, Labels: it.Labels}
			if extra[kwI18n] {
				item.Labels = nil
			}
			if !extra[kwIcons] {
				item.Icon = it.Icon
			}
			if colors != nil {
				item.Color = str(colors, it.Code)
			}
			f.Enum = append(f.Enum, item)
		}
	}
	for _, key := range prop.keys {
		if !k[key] || extra[key] {
			f.Extras = append(f.Extras, Extra{Key: key, Value: compact(prop.vals[key])})
		}
	}
	f.Advanced = f.Type == TAdvanced || len(f.Extras) > 0
	return f
}

// ParseType builds the Type of a collection from its config entry, schema and
// rules.
func ParseType(col *config.Collection, schemaRaw []byte, rules []config.Rule, count int) (*Type, error) {
	t := &Type{
		Name: col.Name, Title: col.Title, Description: col.Description, Group: col.Group, Icon: col.Icon,
		I18n: col.I18n.Only("title", "description", "group"),
		File: col.File, Path: col.Path, SchemaFile: col.Schema,
		Key: nonNil(col.Key), Label: col.Label, List: nonNil(col.List), Facets: col.Facets, Unique: [][]string{}, Count: count,
	}
	if t.Facets == nil {
		t.Facets = []config.Facet{}
	}
	root := newOmap()
	if len(schemaRaw) > 0 {
		v, err := parseOrdered(schemaRaw)
		if err != nil {
			return nil, fmt.Errorf("schema %s: %w", col.Schema, err)
		}
		var ok bool
		if root, ok = v.(*omap); !ok {
			return nil, fmt.Errorf("schema %s: not a JSON object", col.Schema)
		}
	}
	required := map[string]bool{}
	if l, ok := stringList(root.vals["required"]); ok {
		for _, r := range l {
			required[r] = true
		}
	}
	refs := map[string]*config.RefRule{}
	single := map[string]bool{}
	for _, r := range rules {
		switch {
		case r.Ref != nil:
			if c, f, ok := config.SplitRef(r.Ref.From); ok && c == col.Name {
				refs[f] = r.Ref
			}
		case r.Unique != nil && r.Unique.Collection == col.Name:
			if len(r.Unique.Fields) == 1 {
				single[r.Unique.Fields[0]] = true
			} else {
				t.Unique = append(t.Unique, r.Unique.Fields)
			}
		case r.SameSet != nil && r.SameSet.Left.Collection == col.Name:
			left := r.SameSet.Left.Collection + "." + r.SameSet.Left.Field
			if len(r.SameSet.Left.Where) > 0 {
				w, _ := json.Marshal(r.SameSet.Left.Where)
				left += " where " + string(w)
			}
			t.SameSet = append(t.SameSet, SameSet{Message: r.SameSet.Message, Left: left, Right: r.SameSet.Right.File + " " + r.SameSet.Right.Path})
		}
	}
	if props, ok := root.vals["properties"].(*omap); ok {
		for _, name := range props.keys {
			f := fieldFromProp(name, props.vals[name], refs[name])
			f.Required, f.Unique = required[name], single[name]
			t.Fields = append(t.Fields, f)
		}
	}
	for _, k := range root.keys {
		if !rootKnown[k] {
			t.Extras = append(t.Extras, Extra{Key: k, Value: compact(root.vals[k])})
		}
	}
	return t, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// comparable strips what lives outside the property (required, unique, the
// rule behind a reference) so that two fields can be compared by what they
// write into the schema.
func schemaView(f Field) Field {
	f.Required, f.Unique, f.Advanced, f.Extras = false, false, false, nil
	if f.Ref != nil {
		f.Ref = &Ref{Many: f.Ref.Many}
	}
	return f
}

func sameInSchema(a, b Field) bool { return reflect.DeepEqual(schemaView(a), schemaView(b)) }

// desired lists the keyword/value pairs a field writes, in the order a fresh
// property gets them.
func desired(f Field) [][2]any {
	jt, format := schemaShape(f)
	var d [][2]any
	add := func(k string, v any) { d = append(d, [2]any{k, v}) }
	add("type", jt)
	if f.Title != "" {
		add("title", f.Title)
	}
	if f.Description != "" {
		add("description", f.Description)
	}
	if format != "" {
		add("format", format)
	}
	num := func(x float64) any { return json.Number(strconv.FormatFloat(x, 'f', -1, 64)) }
	switch f.Type {
	case TText:
		if f.MinLength != nil {
			add("minLength", json.Number(strconv.Itoa(*f.MinLength)))
		}
		if f.MaxLength != nil {
			add("maxLength", json.Number(strconv.Itoa(*f.MaxLength)))
		}
		if f.Pattern != "" {
			add("pattern", f.Pattern)
		}
	case TInteger, TNumber:
		if f.Min != nil {
			add("minimum", num(*f.Min))
		}
		if f.Max != nil {
			add("maximum", num(*f.Max))
		}
	case TPort:
		add("minimum", json.Number("1"))
		add("maximum", json.Number("65535"))
	case TEnum:
		vals := make([]any, len(f.Enum))
		colors, icons := newOmap(), newOmap()
		withLabels := false
		for i, it := range f.Enum {
			vals[i] = it.Value
			if it.Color != "" {
				colors.set(it.Value, it.Color)
			}
			if it.Icon != "" {
				icons.set(it.Value, it.Icon)
			}
			withLabels = withLabels || it.Label != "" || len(it.Labels) > 0
		}
		if withLabels {
			one := make([]any, len(f.Enum))
			for i, it := range f.Enum {
				e := newOmap()
				e.set("const", it.Value)
				if it.Label != "" {
					e.set("title", it.Label)
				}
				one[i] = e
			}
			add("oneOf", one)
		} else {
			add("enum", vals)
		}
		if len(colors.keys) > 0 {
			add(kwColors, colors)
		}
		if len(icons.keys) > 0 {
			add(kwIcons, icons)
		}
	case TRef:
		if f.Ref != nil && f.Ref.Many {
			items := newOmap()
			items.set("type", "string")
			add("items", items)
		}
	}
	if f.Default != nil && f.Type != TRef && f.Type != TAdvanced {
		add("default", f.Default)
	}
	if f.Type == TText && len(f.Examples) > 0 {
		add("examples", toOrdered(f.Examples))
	}
	add(kwType, f.Type)
	return d
}

// buildProp writes field f onto a copy of base (the existing property, nil for
// a new one). old is the field as it was read, nil for a new field: keywords
// the old type managed are removed when the new type does not, keywords the
// console does not know stay.
func buildProp(f Field, base *omap, old *Field) *omap {
	p := newOmap()
	if base != nil {
		p = base.clone()
	}
	if f.Type == TAdvanced {
		for _, kv := range [][2]string{{"title", f.Title}, {"description", f.Description}} {
			if kv[1] == "" {
				p.del(kv[0])
			} else {
				p.set(kv[0], kv[1])
			}
		}
		if old == nil || !hasExtra(old.Extras, kwI18n) {
			setI18n(p, f, old)
		}
		return p
	}
	managed := known(f.Type)
	if old != nil {
		for k := range known(old.Type) {
			managed[k] = true
		}
		for _, e := range old.Extras {
			delete(managed, e.Key)
		}
	}
	want := map[string]bool{kwI18n: true} // written by setI18n below
	for _, kv := range desired(f) {
		k := kv[0].(string)
		if !managed[k] && base != nil {
			continue
		}
		// switching between enum and oneOf keeps the keyword's place
		if k == "oneOf" && p.has("enum") && !p.has("oneOf") {
			p.rename("enum", "oneOf")
		} else if k == "enum" && p.has("oneOf") && !p.has("enum") {
			p.rename("oneOf", "enum")
		}
		want[k] = true
		p.set(k, kv[1])
	}
	for k := range managed {
		if !want[k] {
			p.del(k)
		}
	}
	if managed[kwI18n] {
		setI18n(p, f, old)
	}
	return p
}

func hasExtra(l []Extra, key string) bool {
	for _, e := range l {
		if e.Key == key {
			return true
		}
	}
	return false
}

// setI18n writes the translations of f into p's x-rackbook-i18n: title and
// description for every property, the enum labels for an enum. Keys the console
// does not know, inside a language's object or in an unsupported language's, are
// kept; a language that ends up empty is removed, and so is the keyword.
func setI18n(p *omap, f Field, old *Field) {
	cur := newOmap()
	if m, ok := p.vals[kwI18n].(*omap); ok {
		cur = m.clone()
	}
	for _, loc := range locale.Supported {
		lo := newOmap()
		if m, ok := cur.vals[loc].(*omap); ok {
			lo = m.clone()
		}
		for _, k := range []string{"title", "description"} {
			if s := f.I18n[loc][k]; s != "" {
				lo.set(k, s)
			} else {
				lo.del(k)
			}
		}
		switch f.Type {
		case TAdvanced:
			// the enum labels of a property the console cannot express stay as they are
		case TEnum:
			labs := newOmap()
			for _, it := range f.Enum {
				if s := it.Labels[loc]; s != "" {
					labs.set(it.Value, s)
				}
			}
			if len(labs.keys) > 0 {
				lo.set("enum", labs)
			} else {
				lo.del("enum")
			}
		default:
			// enum labels are managed for enums only: they go when the field stops
			// being one, and hand-written ones on any other property stay
			if old != nil && old.Type == TEnum {
				lo.del("enum")
			}
		}
		if len(lo.keys) > 0 {
			cur.set(loc, lo)
		} else {
			cur.del(loc)
		}
	}
	if len(cur.keys) > 0 {
		p.set(kwI18n, cur)
	} else {
		p.del(kwI18n)
	}
}

// applySchema returns the schema file content for newT, starting from oldRaw
// (nil for a new type) and oldT (the type read from it).
func applySchema(oldRaw []byte, oldT, newT *Type) ([]byte, error) {
	root := newOmap()
	if oldRaw != nil {
		v, err := parseOrdered(oldRaw)
		if err != nil {
			return nil, err
		}
		var ok bool
		if root, ok = v.(*omap); !ok {
			return nil, fmt.Errorf("schema is not a JSON object")
		}
	} else {
		root.set("$schema", schemaDraf)
		root.set("title", newT.Title)
		root.set("type", "object")
		root.set("additionalProperties", false)
	}
	// title and description follow the collection's while they were the same
	if oldT != nil {
		if str(root, "title") == oldT.Title && newT.Title != oldT.Title {
			root.set("title", newT.Title)
		}
		if str(root, "description") == oldT.Description && newT.Description != oldT.Description {
			if newT.Description == "" {
				root.del("description")
			} else {
				root.set("description", newT.Description)
			}
		}
	} else if newT.Description != "" {
		root.set("description", newT.Description)
	}
	// required keeps the old order for the names that stay
	var oldReq []string
	if l, ok := stringList(root.vals["required"]); ok {
		oldReq = l
	}
	want := map[string]bool{}
	for _, f := range newT.Fields {
		if f.Required {
			want[f.Name] = true
		}
	}
	var req []any
	seen := map[string]bool{}
	for _, r := range oldReq {
		if want[r] && !seen[r] {
			req = append(req, r)
			seen[r] = true
		}
	}
	for _, f := range newT.Fields {
		if f.Required && !seen[f.Name] {
			req = append(req, f.Name)
		}
	}
	if len(req) > 0 {
		root.set("required", req)
	} else {
		root.del("required")
	}
	oldProps, _ := root.vals["properties"].(*omap)
	props := newOmap()
	for _, f := range newT.Fields {
		var existing any
		if oldProps != nil {
			existing = oldProps.vals[f.Name]
		}
		var oldF *Field
		if oldT != nil {
			oldF = oldT.Field(f.Name)
		}
		if oldF != nil && existing != nil && sameInSchema(*oldF, f) {
			props.set(f.Name, existing)
			continue
		}
		base, _ := existing.(*omap)
		props.set(f.Name, buildProp(f, base, oldF))
	}
	root.set("properties", props)
	return formatSchema(root), nil
}

// sameSchema reports whether two schema documents are equal including key order.
func sameSchema(a, b []byte) bool {
	x, err1 := parseOrdered(a)
	y, err2 := parseOrdered(b)
	return err1 == nil && err2 == nil && inlineJSON(x) == inlineJSON(y)
}
