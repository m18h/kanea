package main

import (
	"testing"
	"time"
)

// The backoff after failed passes: 1m, 2m, 4m … capped at the configured
// interval, with ±10% jitter around whichever applies.
func TestSecretSyncWaitBacksOffAndCaps(t *testing.T) {
	interval := 5 * time.Minute
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, interval},
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, interval}, // 8m capped
		{9, interval},
	}
	for _, tc := range cases {
		got := secretSyncWait(interval, tc.failures)
		low := time.Duration(float64(tc.want) * 0.9)
		high := time.Duration(float64(tc.want) * 1.1)
		if got < low || got > high {
			t.Errorf("wait(%d failures) = %v, want %v ±10%%", tc.failures, got, tc.want)
		}
	}
}

// A short configured interval also caps the very first retry: the operator's
// number is the ceiling, wherever the backoff is.
func TestSecretSyncWaitNeverExceedsTheInterval(t *testing.T) {
	interval := 45 * time.Second
	for failures := 1; failures < 6; failures++ {
		got := secretSyncWait(interval, failures)
		if got > time.Duration(float64(interval)*1.1) {
			t.Errorf("wait(%d failures) = %v exceeds the %v interval", failures, got, interval)
		}
	}
}

func TestJoinBounded(t *testing.T) {
	if got := joinBounded([]string{"a", "b"}, 3); got != "a, b" {
		t.Errorf("joinBounded = %q", got)
	}
	if got := joinBounded([]string{"a", "b", "c", "d"}, 2); got != "a, b, and 2 more" {
		t.Errorf("joinBounded = %q", got)
	}
}
