package lru

import "testing"

func TestEvictsLeastRecentlyUsedOnly(t *testing.T) {
	c := New[string, int](3)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)
	c.Get("a")
	c.Put("d", 4) // evicts b, not everything
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should be evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.Get(k); !ok {
			t.Fatalf("%s was evicted", k)
		}
	}
	if c.Len() != 3 {
		t.Fatal(c.Len())
	}
}
