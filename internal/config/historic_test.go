package config

import "testing"

func TestParseHistoricReadsOnlyWhatHistoryNeedsAndTouchesNoFile(t *testing.T) {
	src := `title: old
branding: {name: X, logo: not/there.svg}
editors: [a@b.c]
future: {x: 1}
collections:
  hosts:
    file: data/hosts.yml
    path: items
    schema: schemas/host.json
    key: [name, site]
    from_the_future: true
  single:
    file: s.yml
    key: name
  broken: [1, 2]
`
	if _, err := Parse([]byte(src), "/nonexistent/rackbook.yml"); err == nil {
		t.Fatal("today's parser would read the branding files and refuse this")
	}
	cols, err := ParseHistoric([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	h := cols["hosts"]
	if h == nil || h.File != "data/hosts.yml" || h.Path != "items" || h.Schema != "schemas/host.json" || len(h.Key) != 2 || h.Key[1] != "site" {
		t.Fatalf("%+v", h)
	}
	if s := cols["single"]; s == nil || len(s.Key) != 1 || s.Key[0] != "name" {
		t.Fatalf("a key written as one name: %+v", s)
	}
	if _, has := cols["broken"]; has || len(cols) != 2 {
		t.Fatalf("%v", cols)
	}
	if cols, err := ParseHistoric([]byte("title: none\n")); err != nil || len(cols) != 0 {
		t.Fatalf("%v %v", cols, err)
	}
	if _, err := ParseHistoric([]byte("collections: [\n")); err == nil {
		t.Fatal("not YAML")
	}
}
