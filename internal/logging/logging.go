// Package logging is the platform's logging foundation.
//
// Conventions (AGENTS.md): everything logs through log/slog; components
// receive a *slog.Logger by injection (no global state); the stdlib "log"
// package and direct fmt.Print* are lint-forbidden; CLI output belongs in
// cmd/kanea and goes through fmt.Fprint*(os.Stdout/os.Stderr).
//
// Daemon (kanead/kanea-edge) file sinks rotate via lumberjack: bounded size,
// bounded backups, gzip compression. The workload log pipeline (PRD §17) adds
// its own non-blocking drain in front of a sink like this — never let a
// rotation stall a workload's write().
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// Config controls one logger sink. The zero value is valid: info level, JSON,
// stderr only, no rotation.
type Config struct {
	// Level: debug|info|warn|error. Default info (server config: log_level, PRD §15.1).
	Level string
	// Format: json|text. Default json.
	Format string
	// File enables a lumberjack-rotated file sink (e.g. /var/log/kanea/kanead.log).
	// Empty logs to stderr only (development / journald).
	File string
	// AlsoStderr tees the file sink to stderr (debugging a daemon interactively).
	AlsoStderr bool
	// Rotation knobs (File only). Defaults: 100 MiB, 5 backups, 14 days.
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	// Compress gzips rotated files. Default false (opt-in; daemons set it).
	Compress bool
	// AddSource adds file:line to every record.
	AddSource bool
}

// New builds the logger. The returned closer releases the file sink (if any)
// and should be deferred by the caller; it is never nil.
func New(cfg Config) (*slog.Logger, io.Closer, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}

	sink := io.Writer(os.Stderr)
	closer := io.Closer(nopCloser{})
	if cfg.File != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.File), 0o750); err != nil {
			return nil, nil, fmt.Errorf("log dir: %w", err)
		}
		lj := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    orDefault(cfg.MaxSizeMB, 100),
			MaxBackups: orDefault(cfg.MaxBackups, 5),
			MaxAge:     orDefault(cfg.MaxAgeDays, 14),
			Compress:   cfg.Compress,
		}
		sink = lj
		closer = lj
		if cfg.AlsoStderr {
			sink = io.MultiWriter(lj, os.Stderr)
		}
	}

	opts := &slog.HandlerOptions{Level: level, AddSource: cfg.AddSource}
	var h slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "", "json":
		h = slog.NewJSONHandler(sink, opts)
	case "text":
		h = slog.NewTextHandler(sink, opts)
	default:
		return nil, nil, fmt.Errorf("unknown log format %q (want json|text)", cfg.Format)
	}
	return slog.New(h), closer, nil
}

// Nop discards all records. For tests and optional subsystems.
func Nop() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want debug|info|warn|error)", s)
	}
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
