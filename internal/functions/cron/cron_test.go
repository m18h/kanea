package cron

import (
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, expr string) Schedule {
	t.Helper()
	s, err := Parse(expr)
	if err != nil {
		t.Fatalf("Parse(%q): %v", expr, err)
	}
	return s
}

func at(t *testing.T, value string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestParseRejectsWhatItShould(t *testing.T) {
	tests := []struct {
		expr string
		want string
	}{
		{"", "5"},
		{"* * * *", "5"},
		{"* * * * * *", "5"},
		{"60 * * * *", "outside"},
		{"* 24 * * *", "outside"},
		{"* * 0 * *", "outside"},
		{"* * 32 * *", "outside"},
		{"* * * 13 *", "outside"},
		{"* * * * 8", "outside"},
		{"x * * * *", "not a number"},
		{"5-1 * * * *", "inverted"},
		{"*/0 * * * *", "step"},
		{"5/15 * * * *", "range"},
		{"@daily", "5"}, // macros are deliberately unsupported
	}
	for _, tc := range tests {
		if _, err := Parse(tc.expr); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) = %v, want an error mentioning %q", tc.expr, err, tc.want)
		}
	}
}

func TestNext(t *testing.T) {
	tests := []struct {
		expr string
		from string
		want string
	}{
		// The PRD §6.1 example: nightly at 03:00 UTC.
		{"0 3 * * *", "2026-08-10T12:00:00Z", "2026-08-11T03:00:00Z"},
		{"0 3 * * *", "2026-08-10T02:59:00Z", "2026-08-10T03:00:00Z"},
		// Strictly after: a tick at exactly the scheduled minute advances.
		{"0 3 * * *", "2026-08-10T03:00:00Z", "2026-08-11T03:00:00Z"},
		// Steps and ranges.
		{"*/15 * * * *", "2026-08-10T12:07:00Z", "2026-08-10T12:15:00Z"},
		{"0 9-17/4 * * *", "2026-08-10T10:00:00Z", "2026-08-10T13:00:00Z"},
		// Lists.
		{"0 0 1,15 * *", "2026-08-02T00:00:00Z", "2026-08-15T00:00:00Z"},
		// Day-of-week: Monday.
		{"0 6 * * 1", "2026-08-10T07:00:00Z", "2026-08-17T06:00:00Z"}, // 2026-08-10 is a Monday
		// 7 is Sunday, like 0.
		{"0 6 * * 7", "2026-08-10T07:00:00Z", "2026-08-16T06:00:00Z"},
		// Standard cron OR semantics when both day fields are restricted:
		// the 13th of the month, or any Friday.
		{"0 0 13 * 5", "2026-08-10T00:00:00Z", "2026-08-13T00:00:00Z"},
		{"0 0 13 * 5", "2026-08-13T00:00:00Z", "2026-08-14T00:00:00Z"}, // the Friday after
		// Restricted day-of-month with * day-of-week: only the date decides.
		{"0 0 13 * *", "2026-08-13T00:00:00Z", "2026-09-13T00:00:00Z"},
		// Month boundaries and Feb 29: fires only in leap years.
		{"0 0 29 2 *", "2026-01-01T00:00:00Z", "2028-02-29T00:00:00Z"},
		// Month restriction jumps whole months at a time.
		{"0 0 1 12 *", "2026-01-15T00:00:00Z", "2026-12-01T00:00:00Z"},
	}
	for _, tc := range tests {
		got, err := mustParse(t, tc.expr).Next(at(t, tc.from))
		if err != nil {
			t.Errorf("Next(%q from %s): %v", tc.expr, tc.from, err)
			continue
		}
		if want := at(t, tc.want); !got.Equal(want) {
			t.Errorf("Next(%q from %s) = %s, want %s", tc.expr, tc.from, got.Format(time.RFC3339), tc.want)
		}
	}
}

// A schedule that can never fire must say so rather than spin.
func TestNextRefusesTheImpossible(t *testing.T) {
	s := mustParse(t, "0 0 31 2 *")
	if _, err := s.Next(at(t, "2026-01-01T00:00:00Z")); err == nil {
		t.Fatal("Feb 31 produced a next firing")
	}
}

// Next is evaluated in UTC whatever location the input carries (R26).
func TestNextIsUTC(t *testing.T) {
	loc := time.FixedZone("UTC+9", 9*3600)
	from := time.Date(2026, 8, 10, 11, 30, 0, 0, loc) // 02:30 UTC
	got, err := mustParse(t, "0 3 * * *").Next(from)
	if err != nil {
		t.Fatal(err)
	}
	if want := at(t, "2026-08-10T03:00:00Z"); !got.Equal(want) {
		t.Fatalf("Next = %s, want %s (UTC evaluation)", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}
