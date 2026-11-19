package ledger

import (
	"strings"
	"testing"
)

func TestItemOrders(t *testing.T) {
	s, err := ParseSchema([]byte(`{"properties": {
	  "name": {"type": "string"},
	  "ports": {"type": "array", "items": {"type": "object", "properties": {"protocol": {}, "port": {}, "note": {}}}},
	  "meta": {"type": "object", "properties": {"b": {}, "a": {}}}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := s.ItemOrders()
	if len(got) != 2 || strings.Join(got["ports"], ",") != "protocol,port,note" || strings.Join(got["meta"], ",") != "b,a" {
		t.Fatalf("%v", got)
	}
}
