package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/auth"
)

// runUser is `kanea user <add|ls|rm>`.
//
// Accounts live in the Store and are managed at runtime over the API (PRD
// v1.18, §13.2), so this is a client command like every other — not an editor
// for a config stanza the daemon would have to be restarted to notice.
func runUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea user <add|ls|rm> [args]")
	}
	switch args[0] {
	case "add", "set":
		return runUserAdd(args[1:])
	case "ls", "list":
		return runUserList(args[1:])
	case "rm", "delete":
		return runUserDelete(args[1:])
	default:
		return fmt.Errorf("unknown user command %q: want add, ls or rm", args[0])
	}
}

// runUserAdd creates or replaces an account.
//
// The password is read from a terminal prompt or stdin, never from a flag:
// argv is world-readable through /proc/<pid>/cmdline and lands in shell
// history — the same reasoning that keeps secret values out of argv.
func runUserAdd(args []string) error {
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	role := fs.String("role", string(auth.RoleAdmin), "admin or viewer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea user add [--role=admin|viewer] <name>")
	}
	name := fs.Arg(0)

	if !auth.Role(*role).Valid() {
		return fmt.Errorf("unknown role %q: want admin or viewer", *role)
	}
	password, err := readPassword(fmt.Sprintf("password for %s: ", name))
	if err != nil {
		return err
	}

	if err := api.NewClient(*socket).PutUser(context.Background(), name, password, auth.Role(*role)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "wrote account %s (%s)\n", name, *role)
	return err
}

func runUserList(args []string) error {
	fs := flag.NewFlagSet("user ls", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	users, err := api.NewClient(*socket).Users(context.Background())
	if err != nil {
		return err
	}
	if len(users) == 0 {
		// Worth saying plainly: with no account, the API is socket-only (§13.1).
		_, err := fmt.Fprintln(os.Stdout,
			"no accounts — the API accepts only local socket callers until one exists")
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tROLE\tCREATED\tUPDATED"); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			u.Name, u.Role, age(u.Created), age(u.Updated)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func runUserDelete(args []string) error {
	fs := flag.NewFlagSet("user rm", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea user rm <name>")
	}

	if err := api.NewClient(*socket).DeleteUser(context.Background(), fs.Arg(0)); err != nil {
		return err
	}
	// Sessions are not swept here: they carry an absolute expiry and are
	// revoked server-side, so the account is gone and its sessions age out.
	_, err := fmt.Fprintf(os.Stdout, "removed account %s\n", fs.Arg(0))
	return err
}

// runToken is `kanea token <create|ls|rm>`.
func runToken(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea token <create|ls|rm> [args]")
	}
	switch args[0] {
	case "create", "add":
		return runTokenCreate(args[1:])
	case "ls", "list":
		return runTokenList(args[1:])
	case "rm", "revoke", "delete":
		return runTokenRevoke(args[1:])
	default:
		return fmt.Errorf("unknown token command %q: want create, ls or rm", args[0])
	}
}

func runTokenCreate(args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	role := fs.String("role", string(auth.RoleViewer), "admin or viewer")
	ttl := fs.String("expires-in", "", "lifetime, e.g. 720h (default: never expires)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea token create [--role=admin|viewer] [--expires-in=720h] <name>")
	}
	if !auth.Role(*role).Valid() {
		return fmt.Errorf("unknown role %q: want admin or viewer", *role)
	}

	resp, err := api.NewClient(*socket).CreateToken(context.Background(), fs.Arg(0), auth.Role(*role), *ttl)
	if err != nil {
		return err
	}

	// The secret goes to stdout alone so `kanea token create ... > token` is a
	// file containing exactly the token; everything else is commentary on
	// stderr. This is the only time the secret exists outside the caller.
	if _, err := fmt.Fprintf(os.Stderr, "created token %s (%s, id %s)\n",
		resp.Token.Name, resp.Token.Role, resp.Token.ID); err != nil {
		return err
	}
	if resp.Token.Expires.IsZero() {
		if _, err := fmt.Fprintln(os.Stderr,
			"warning: this token never expires — revoke it with `kanea token rm "+resp.Token.ID+"`"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(os.Stderr,
		"store it now: it is not recoverable and cannot be shown again"); err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, resp.Secret)
	return err
}

func runTokenList(args []string) error {
	fs := flag.NewFlagSet("token ls", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tokens, err := api.NewClient(*socket).Tokens(context.Background())
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		_, err := fmt.Fprintln(os.Stdout, "no tokens")
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tNAME\tROLE\tCREATED\tEXPIRES\tLAST USED"); err != nil {
		return err
	}
	for _, t := range tokens {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Name, t.Role, age(t.Created), expiry(t.Expires), age(t.LastUsed)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func runTokenRevoke(args []string) error {
	fs := flag.NewFlagSet("token rm", flag.ContinueOnError)
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea token rm <id>")
	}

	if err := api.NewClient(*socket).RevokeToken(context.Background(), fs.Arg(0)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(os.Stdout, "revoked token %s\n", fs.Arg(0))
	return err
}

// expiry renders a token's expiry, naming the unbounded case rather than
// leaving a blank column that reads like "unknown".
func expiry(at time.Time) string {
	switch {
	case at.IsZero():
		return "never"
	case time.Now().After(at):
		return "expired"
	default:
		return "in " + shortDuration(time.Until(at))
	}
}

// readPassword prompts without echoing, or reads one line from a pipe.
//
// The pipe case is what makes `kanea user add` scriptable — `kanea init` and CI
// both need it — and the terminal case is what keeps a password off the screen
// and out of the scrollback of anyone typing it by hand.
func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := readLine(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return line, nil
	}

	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", err
	}
	typed, err := term.ReadPassword(fd)
	if _, perr := fmt.Fprintln(os.Stderr); perr != nil {
		return "", perr
	}
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	if _, err := fmt.Fprint(os.Stderr, "again: "); err != nil {
		return "", err
	}
	again, err := term.ReadPassword(fd)
	if _, perr := fmt.Fprintln(os.Stderr); perr != nil {
		return "", perr
	}
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(typed) != string(again) {
		return "", errors.New("the two passwords do not match")
	}
	return string(typed), nil
}

// readLine reads one line, without the newline.
func readLine(f *os.File) (string, error) {
	// Bounded: a password is short, and an unbounded read from a pipe someone
	// pointed at /dev/urandom is not a password.
	buf := make([]byte, 1024)
	n, err := f.Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	return strings.TrimSuffix(line, "\r"), nil
}
