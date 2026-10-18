package main

import (
	"testing"
	"time"
)

func TestExpiresAtUsesProtonValue(t *testing.T) {
	got := expiresAt(3600, 12) // 1h from Proton, ignore fallback
	ts, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("not RFC3339: %q (%v)", got, err)
	}
	delta := time.Until(ts)
	if delta < 59*time.Minute || delta > 61*time.Minute {
		t.Fatalf("expiry ~1h expected, got %v", delta)
	}
}

func TestExpiresAtFallsBackWhenUnknown(t *testing.T) {
	got := expiresAt(0, 12) // no Proton value -> 12h fallback
	ts, _ := time.Parse(time.RFC3339, got)
	delta := time.Until(ts)
	if delta < 11*time.Hour+59*time.Minute || delta > 12*time.Hour+1*time.Minute {
		t.Fatalf("fallback ~12h expected, got %v", delta)
	}
}
