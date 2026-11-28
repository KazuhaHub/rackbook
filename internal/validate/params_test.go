package validate_test

import (
	"encoding/json"
	"testing"

	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// issueJSON is the keyword and params of the only issue at path, as the API sends them.
func issueJSON(t *testing.T, issues []ledger.Issue, path string) (string, string) {
	t.Helper()
	var found []ledger.Issue
	for _, i := range issues {
		if i.Path == path {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want one issue at %s, got %v", path, issues)
	}
	if found[0].Message == "" {
		t.Fatalf("the English message is the fallback and must stay: %+v", found[0])
	}
	b, err := json.Marshal(found[0].Params)
	if err != nil {
		t.Fatal(err)
	}
	return found[0].Keyword, string(b)
}

func TestIssueParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, old, new, path, keyword, params string
	}{
		{"enum hint", "ipv4_type: static", "ipv4_type: 静态", "/ipv4_type", "enum", `{"use":"static","value":"静态"}`},
		{"enum list", "ipv4_type: static", "ipv4_type: xyz", "/ipv4_type", "enum", `{"allowed":["static","dynamic","nat"],"value":"xyz"}`},
		{"legacy enum list", "status: up", "status: sideways", "/status", "enum", `{"allowed":["up","down"],"value":"sideways"}`},
		{"type", "ipv4_type: static", "ipv4_type: 5", "/ipv4_type", "type", `{"got":"number","want":["string"]}`},
		{"format", "country: US", "country: XX", "/country", "format", `{"format":"country","value":"XX"}`},
		{"additionalProperties", "country: tbd, owner: ann}", "country: tbd, owner: ann, colour: red}", "", "additionalProperties", `{"properties":["colour"]}`},
		{"required", "{name: ap, ", "{", "", "required", `{"missing":["name"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := testutil.CopyFixture(t, "labels")
			testutil.Replace(t, dir, labelDevices, c.old, c.new)
			var schema []ledger.Issue
			for _, i := range run(t, dir) {
				if i.Rule == ledger.RuleSchema {
					schema = append(schema, i)
				}
			}
			kw, params := issueJSON(t, schema, c.path)
			if kw != c.keyword || params != c.params {
				t.Fatalf("got %s %s, want %s %s", kw, params, c.keyword, c.params)
			}
		})
	}
}

func TestRuleIssueParams(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, labelDevices, "country: tbd, owner: ann", "country: tbd, owner: bob")
	var refs []ledger.Issue
	for _, i := range run(t, dir) {
		if i.Rule == ledger.RuleRef {
			refs = append(refs, i)
		}
	}
	kw, params := issueJSON(t, refs, "/owner")
	want := `{"ruleMessage":"负责人不存在","ruleMessageI18n":{"en-US":"Unknown owner"},"target":"people.name","value":"bob"}`
	if kw != "ref" || params != want {
		t.Fatalf("got %s %s\nwant ref %s", kw, params, want)
	}

	dir = testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, labelDevices, "{name: ap,", "{name: gw,")
	var dups []ledger.Issue
	for _, i := range run(t, dir) {
		if i.Rule == ledger.RuleUnique {
			dups = append(dups, i)
		}
	}
	kw, params = issueJSON(t, dups, "/name")
	if want := `{"fields":["name"],"key":true,"values":["gw"]}`; kw != "unique" || params != want {
		t.Fatalf("got %s %s\nwant unique %s", kw, params, want)
	}
}

// dependentRequired reports the keyword itself, not the property the library
// appends to its keyword path.
func TestDependentRequiredKeyword(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, "schemas/device.json", `"required": ["name"],`, `"required": ["name"], "dependentRequired": {"owner": ["country"]},`)
	testutil.Replace(t, dir, labelDevices, "country: US, owner: ann", "owner: ann")
	var schema []ledger.Issue
	for _, i := range run(t, dir) {
		if i.Rule == ledger.RuleSchema {
			schema = append(schema, i)
		}
	}
	kw, params := issueJSON(t, schema, "")
	if want := `{"missing":["country"],"property":"owner"}`; kw != "dependentRequired" || params != want {
		t.Fatalf("got %s %s, want dependentRequired %s", kw, params, want)
	}
}

// draft-07 dependencies reports the schema keyword too.
func TestDependenciesKeyword(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, "schemas/device.json", `"https://json-schema.org/draft/2020-12/schema"`, `"http://json-schema.org/draft-07/schema#"`)
	testutil.Replace(t, dir, "schemas/device.json", `"required": ["name"],`, `"required": ["name"], "dependencies": {"owner": ["country"]},`)
	testutil.Replace(t, dir, labelDevices, "country: US, owner: ann", "owner: ann")
	var schema []ledger.Issue
	for _, i := range run(t, dir) {
		if i.Rule == ledger.RuleSchema {
			schema = append(schema, i)
		}
	}
	kw, params := issueJSON(t, schema, "")
	if want := `{"missing":["country"],"property":"owner"}`; kw != "dependencies" || params != want {
		t.Fatalf("got %s %s, want dependencies %s", kw, params, want)
	}
}
