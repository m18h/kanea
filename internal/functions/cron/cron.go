// Package cron parses five-field cron schedules and computes their next
// firing, in UTC (PRD §6.2 R26).
//
// Hand-written rather than a dependency, the way the MCP server and the S3
// sink are: the surface Kanea needs is five fields, `*`, lists, ranges and
// steps (no macros, no seconds field, no time zones) and a library carrying
// all of those would be mostly code nobody here reviews. UTC is the only
// clock, stated in R26 rather than configurable: a schedule that means a
// different hour after a node reinstall picks a different /etc/localtime is a
// schedule nobody wrote.
package cron

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed five-field cron expression.
//
// Each field is a bitmask of the permitted values, which makes matching a
// time O(1) and makes "every value" and "these values" the same shape.
type Schedule struct {
	minute uint64 // 0-59
	hour   uint64 // 0-23
	dom    uint64 // 1-31
	month  uint64 // 1-12
	dow    uint64 // 0-6, Sunday = 0 (7 accepted as Sunday on input)

	// domStar and dowStar record whether the field was `*`. Standard cron
	// semantics: when BOTH day fields are restricted, a time matches if
	// EITHER does; when one is `*`, only the other decides.
	domStar, dowStar bool
}

type field struct {
	name     string
	min, max int
}

var fields = [5]field{
	{"minute", 0, 59},
	{"hour", 0, 23},
	{"day-of-month", 1, 31},
	{"month", 1, 12},
	{"day-of-week", 0, 7}, // 7 folds to 0 (both mean Sunday)
}

// Parse validates a five-field cron expression.
func Parse(expr string) (Schedule, error) {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return Schedule{}, fmt.Errorf("cron: %q has %d fields, want 5 (minute hour day-of-month month day-of-week)",
			expr, len(parts))
	}
	var masks [5]uint64
	var stars [5]bool
	for i, part := range parts {
		mask, star, err := parseField(part, fields[i])
		if err != nil {
			return Schedule{}, err
		}
		masks[i], stars[i] = mask, star
	}
	return Schedule{
		minute: masks[0], hour: masks[1], dom: masks[2], month: masks[3], dow: masks[4],
		domStar: stars[2], dowStar: stars[4],
	}, nil
}

// parseField parses one comma-separated list of ranges into a bitmask.
func parseField(s string, f field) (mask uint64, star bool, err error) {
	for _, item := range strings.Split(s, ",") {
		m, isStar, err := parseRange(item, f)
		if err != nil {
			return 0, false, err
		}
		// `*` in a list ("*,5") is odd but harmless; it only counts as the
		// day-field wildcard when it stands alone.
		star = star || (isStar && !strings.Contains(s, ","))
		mask |= m
	}
	if mask == 0 {
		return 0, false, fmt.Errorf("cron: %s field %q matches nothing", f.name, s)
	}
	return mask, star, nil
}

// parseRange parses one of: `*`, `*/step`, `N`, `N-M`, `N-M/step`.
func parseRange(s string, f field) (uint64, bool, error) {
	body, step := s, 1
	if i := strings.IndexByte(s, '/'); i >= 0 {
		body = s[:i]
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n <= 0 {
			return 0, false, fmt.Errorf("cron: %s step %q is not a positive number", f.name, s)
		}
		step = n
	}

	lo, hi := f.min, f.max
	star := body == "*"
	if !star {
		var err error
		if i := strings.IndexByte(body, '-'); i >= 0 {
			lo, err = parseValue(body[:i], f)
			if err != nil {
				return 0, false, err
			}
			hi, err = parseValue(body[i+1:], f)
			if err != nil {
				return 0, false, err
			}
			if hi < lo {
				return 0, false, fmt.Errorf("cron: %s range %q is inverted", f.name, s)
			}
		} else {
			lo, err = parseValue(body, f)
			if err != nil {
				return 0, false, err
			}
			hi = lo
			if step > 1 {
				// "5/15" is a vixie-cron oddity ("from 5 to max"); refuse it;
				// writing "5-59/15" says what it means.
				return 0, false, fmt.Errorf("cron: %s %q has a step on a single value; write a range (e.g. %d-%d/%d)",
					f.name, s, lo, f.max, step)
			}
		}
	}

	var mask uint64
	for v := lo; v <= hi; v += step {
		mask |= 1 << fold(v, f)
	}
	return mask, star, nil
}

func parseValue(s string, f field) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("cron: %s value %q is not a number", f.name, s)
	}
	if n < f.min || n > f.max {
		return 0, fmt.Errorf("cron: %s value %d is outside %d-%d", f.name, n, f.min, f.max)
	}
	return n, nil
}

// fold maps day-of-week 7 to 0; both spell Sunday.
func fold(v int, f field) int {
	if f.name == "day-of-week" && v == 7 {
		return 0
	}
	return v
}

// Next returns the first time strictly after t that matches, in UTC.
//
// The scan advances a field at a time rather than minute-by-minute, so a
// schedule that fires yearly still answers in microseconds. The four-year
// horizon covers the worst legal case (Feb 29) with room to spare; a schedule
// that cannot fire within it (`0 0 31 2 *`) reports itself rather than
// spinning.
func (s Schedule) Next(t time.Time) (time.Time, error) {
	// Truncate to the minute and step off it: "strictly after" is what lets a
	// scheduler call Next(lastFire) without re-firing the same tick.
	t = t.UTC().Truncate(time.Minute).Add(time.Minute)

	limit := t.AddDate(4, 0, 0)
	for t.Before(limit) {
		if s.month&(1<<int(t.Month())) == 0 {
			// Jump to the first minute of the next month.
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
			continue
		}
		if s.hour&(1<<t.Hour()) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, time.UTC).Add(time.Hour)
			continue
		}
		if s.minute&(1<<t.Minute()) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cron: schedule never fires within %d years of %s", 4, t.Format(time.RFC3339))
}

// dayMatches applies standard cron day semantics: with both day fields
// restricted a date matches if either does; with one `*`, the other decides.
func (s Schedule) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<t.Day()) != 0
	dow := s.dow&(1<<int(t.Weekday())) != 0
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dow
	case s.dowStar:
		return dom
	default:
		return dom || dow
	}
}

// String renders the mask sizes for debugging; not a re-serialisation.
func (s Schedule) String() string {
	return fmt.Sprintf("cron(min:%d hr:%d dom:%d mon:%d dow:%d)",
		bits.OnesCount64(s.minute), bits.OnesCount64(s.hour),
		bits.OnesCount64(s.dom), bits.OnesCount64(s.month), bits.OnesCount64(s.dow))
}
