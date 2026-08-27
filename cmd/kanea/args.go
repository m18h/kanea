package main

import (
	"flag"
	"strings"
)

// parseArgs parses a client command's arguments with flags allowed on either
// side of the positionals.
//
// The standard library stops flag parsing at the first non-flag argument, so
// `kanea logs shop/api -c migrate` - the exact form the README teaches - left
// `-c migrate` in the residual arguments, which nothing read: the command
// answered with the task's log and no error. Same story for
// `kanea stop shop/web --rm`, which quietly scaled to zero instead of
// deleting. A flag the user typed is either honoured or refused out loud,
// never dropped.
//
// Everything after a literal "--" stays positional, verbatim. After parseArgs
// returns, fs.Args() holds exactly the positionals, in order, so callers read
// fs.Arg/fs.NArg as they always have. Not used by `kanea exec`, whose "--"
// tail is a remote argv with its own splitter.
func parseArgs(fs *flag.FlagSet, args []string) error {
	var tail []string
	for i, a := range args {
		if a == "--" {
			tail = args[i+1:]
			args = args[:i]
			break
		}
	}

	var positionals []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return err
		}
		rest := fs.Args()
		// A bare "-" is stdin by convention, not a flag.
		i := 0
		for i < len(rest) && (rest[i] == "-" || !strings.HasPrefix(rest[i], "-")) {
			i++
		}
		positionals = append(positionals, rest[:i]...)
		if i == len(rest) {
			break
		}
		args = rest[i:]
	}
	positionals = append(positionals, tail...)

	// Feed the positionals back through the set, behind a terminator so none
	// of them can be mistaken for a flag, leaving fs.Args() exactly right.
	return fs.Parse(append([]string{"--"}, positionals...))
}
