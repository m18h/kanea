//go:build !linux

package storage

import "errors"

// stagingSupported is false off linux: the race K-20 closes exists where runc
// does. Dev mode mounts the resolved path itself, as it always has.
const stagingSupported = false

// errNoStaging is unreachable behind stagingSupported; it exists so the call
// sites compile with one shape on every platform.
var errNoStaging = errors.New("storage: host-volume staging exists on linux only")

func pinAndBind(_, _ string, _ []string) error { return errNoStaging }

func unstagePath(_ func(string) (bool, error), _ string) error { return nil }
