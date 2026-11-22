package api

import (
	"strings"
	"testing"
)

func TestCursorIsSignedBoundToItsOwnerAndChecked(t *testing.T) {
	s := &server{cursorKey: []byte(strings.Repeat("k", 32))}
	c := activityCursor{"ledger": {Tip: strings.Repeat("a", 40), N: 7}, "audit": {Resume: 12}}
	v := s.encodeCursor("oidc:boss", c)
	got, err := s.decodeCursor("oidc:boss", v)
	if err != nil || got["ledger"].N != 7 || got["audit"].Resume != 12 {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := s.decodeCursor("oidc:tom", v); err == nil {
		t.Fatal("another person's cursor was accepted")
	}
	payload, mac, _ := strings.Cut(v, ".")
	for _, bad := range []string{payload, payload + ".", "." + mac, payload + "." + mac[:len(mac)-2] + "AA", "x" + payload + "." + mac} {
		if _, err := s.decodeCursor("oidc:boss", bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	other := &server{cursorKey: []byte(strings.Repeat("z", 32))}
	if _, err := other.decodeCursor("oidc:boss", v); err == nil {
		t.Fatal("a cursor of another server run was accepted")
	}
	// a signed cursor with a position below zero is refused all the same
	for _, neg := range []activityCursor{{"ledger": {N: -1}}, {"audit": {Resume: -5}}, {"ledger": {Tip: "not-hex"}}} {
		if _, err := s.decodeCursor("oidc:boss", s.encodeCursor("oidc:boss", neg)); err == nil {
			t.Fatalf("%+v accepted", neg)
		}
	}
}
