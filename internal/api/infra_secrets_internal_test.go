package api

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRevealLimits(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reveals.json")
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	l := &revealLimiter{Path: path}
	for i := 0; i < 10; i++ {
		if hit, _ := l.allow("a", now); hit != "" {
			t.Fatalf("reveal %d refused by %s", i, hit)
		}
	}
	if hit, wait := l.allow("a", now); hit != "minute" || wait <= 0 || wait > time.Minute {
		t.Fatalf("%q %v", hit, wait)
	}
	// another person is unaffected
	if hit, _ := l.allow("b", now); hit != "" {
		t.Fatal(hit)
	}
	// a restart keeps the counts
	l = &revealLimiter{Path: path}
	if hit, _ := l.allow("a", now.Add(10*time.Second)); hit != "minute" {
		t.Fatalf("after a restart: %q", hit)
	}
	// 30 an hour: two more rounds of ten fit, the next is refused by the hour limit
	for round := 1; round <= 2; round++ {
		now = now.Add(2 * time.Minute)
		for i := 0; i < 10; i++ {
			if hit, _ := l.allow("a", now); hit != "" {
				t.Fatalf("round %d: %q", round, hit)
			}
		}
	}
	now = now.Add(2 * time.Minute)
	if hit, _ := l.allow("a", now); hit != "hour" {
		t.Fatalf("hour: %q", hit)
	}
	// 100 a day: ten rounds an hour apart reach 100 (30 already used in the first hour)
	count := 30
	for count < 100 {
		now = now.Add(61 * time.Minute)
		for i := 0; i < 10 && count < 100; i++ {
			if hit, _ := l.allow("a", now); hit != "" {
				t.Fatalf("count %d: %q", count, hit)
			}
			count++
		}
		if now.Sub(time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)) > 23*time.Hour {
			break
		}
	}
	if count == 100 {
		now = now.Add(61 * time.Minute)
		if hit, _ := l.allow("a", now); hit != "day" && hit != "" {
			t.Fatalf("day: %q", hit)
		}
	}
	// a day later it clears
	now = now.Add(25 * time.Hour)
	if hit, _ := l.allow("a", now); hit != "" {
		t.Fatalf("a day later: %q", hit)
	}
}
