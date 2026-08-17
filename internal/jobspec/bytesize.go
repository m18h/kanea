package jobspec

import (
	"fmt"
	"strconv"
	"strings"
)

// Byte sizes in a spec (PRD v1.69, §6.2 R31).
//
// A string rather than a number, for the reason `mode` is one: HCL has no size
// literal, and `size = 10GiB` is not expressible. Unlike R11's `memory`, which
// is a bare count of MiB and always was, storage spans MiB to TiB in ordinary
// use: a bare integer there would be a unit nobody could infer from the value.

// byteUnits are the suffixes ParseByteSize accepts, longest first so "GiB" is
// matched before "G".
var byteUnits = []struct {
	suffix string
	scale  int64
}{
	{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"TiB", 1 << 40}, {"T", 1 << 40},
	{"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1},
}

// ParseByteSize reads "128MiB", "1GiB", or a plain byte count.
//
// The result is always positive: every caller is declaring a size for
// something, and zero means "not declared", which is the absent field rather
// than a value anyone writes.
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("want a byte count or a size like 128MiB")
	}
	for _, u := range byteUnits {
		rest, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q: %w", s, err)
		}
		if n <= 0 {
			return 0, fmt.Errorf("%q: must be positive", s)
		}
		// Overflow would silently wrap a plausible-looking "16777216TiB" into a
		// small or negative budget, which is worse than refusing it.
		if n > (1<<62)/u.scale {
			return 0, fmt.Errorf("%q: is too large", s)
		}
		return n * u.scale, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q: want a byte count or a size like 128MiB", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%q: must be positive", s)
	}
	return n, nil
}
