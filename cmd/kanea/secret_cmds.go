package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
)

// runSecret is `kanea secret <put|ls|rm>`.
//
// There is no `get`. Secrets are write-only over the API (PRD §13.3), so the
// CLI cannot offer a read even to a local operator — the daemon has no route
// that would answer it.
func runSecret(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea secret <put|ls|rm> [args]")
	}
	switch args[0] {
	case "put", "set":
		return runSecretPut(args[1:])
	case "ls", "list":
		return runSecretList(args[1:])
	case "rm", "delete":
		return runSecretDelete(args[1:])
	default:
		return fmt.Errorf("unknown secret command %q: want put, ls or rm", args[0])
	}
}

// runSecretPut writes a secret read from stdin or a file.
//
// Never from a command-line argument. Everything in argv is world-readable
// through /proc/<pid>/cmdline and lands in the operator's shell history — the
// same reasoning that keeps mount credentials out of argv (M2).
func runSecretPut(args []string) error {
	fs := flag.NewFlagSet("secret put", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	from := fs.String("from-file", "", "read the value from a file instead of stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea secret put [--from-file=path] <project>/<name> < value")
	}
	path := fs.Arg(0)

	value, err := readSecretValue(*from)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return errors.New("the value is empty; pipe it in or use --from-file")
	}

	// The client bounds the request itself (30s), matching every other command.
	if err := api.NewClient(*socket).PutSecret(context.Background(), path, value); err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "wrote %s (%d bytes)\n", path, len(value))
	return err
}

// readSecretValue reads from a file or stdin, trimming one trailing newline.
//
// One, and only from stdin: `echo secret | kanea secret put` should not store
// the newline the shell added, but a file containing a key with a trailing
// newline is a file whose bytes matter.
func readSecretValue(fromFile string) ([]byte, error) {
	if fromFile != "" {
		body, err := os.ReadFile(fromFile) // #nosec G304 — an operator-named file
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", fromFile, err)
		}
		return body, nil
	}

	body, err := io.ReadAll(io.LimitReader(os.Stdin, api.MaxSecretBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(body) > api.MaxSecretBytes {
		return nil, fmt.Errorf("the value is larger than %d bytes", api.MaxSecretBytes)
	}
	return []byte(strings.TrimSuffix(string(body), "\n")), nil
}

func runSecretList(args []string) error {
	fs := flag.NewFlagSet("secret ls", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	prefix := ""
	if fs.NArg() > 0 {
		prefix = fs.Arg(0)
	}

	infos, err := api.NewClient(*socket).ListSecrets(context.Background(), prefix)
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		_, err := fmt.Fprintln(os.Stdout, "no secrets")
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "PATH\tCREATED\tUPDATED"); err != nil {
		return err
	}
	for _, info := range infos {
		// Values are absent by construction: the API never sent them.
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n",
			info.Path, age(info.Created), age(info.Updated)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func runSecretDelete(args []string) error {
	fs := flag.NewFlagSet("secret rm", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea secret rm <project>/<name>")
	}

	if err := api.NewClient(*socket).DeleteSecret(context.Background(), fs.Arg(0)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(os.Stdout, "removed %s\n", fs.Arg(0))
	return err
}

// age renders a timestamp the way every other table column does.
func age(at time.Time) string {
	if at.IsZero() {
		return "-"
	}
	return shortDuration(time.Since(at))
}
