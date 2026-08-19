package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/m18h/kanea/internal/certsource"
)

// runCA is `kanea ca`: this node's self-signed CA, for installing on devices.
//
// It goes through the API rather than opening the Store, like every other CLI
// command: bbolt takes a whole-file lock, so reading the CA directly would
// block until kanead exits (PRD §5.2.6).
//
// There is no `rotate` and no way to get the key. Rotation means re-trusting
// every device that has the old one, and a command for it would imply that is
// cheap; an operator who truly wants a new CA can delete the record. The key
// moves in the encrypted archive or not at all.
func runCA(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea ca <show|info>")
	}
	switch args[0] {
	case "show", "cert":
		return runCAShow(args[1:])
	case "info":
		return runCAInfo(args[1:])
	default:
		return fmt.Errorf("unknown ca command %q: want show or info", args[0])
	}
}

// runCAShow prints the CA certificate.
//
// The PEM goes to stdout and everything else to stderr, so that
// `kanea ca show > kanea-ca.crt` produces a file a trust store will accept
// rather than one with installation advice pasted on the front.
func runCAShow(args []string) error {
	fs := flag.NewFlagSet("ca show", flag.ContinueOnError)
	ep := endpointFlags(fs)
	out := fs.String("out", "", "write to this file instead of stdout")
	quiet := fs.Bool("quiet", false, "omit the installation hints")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, cerr := ep.client()
	if cerr != nil {
		return cerr
	}
	pem, err := client.CACertificate(context.Background())
	if err != nil {
		return err
	}

	if *out != "" {
		// 0644: a CA certificate is presented in every handshake to every
		// client that trusts it. It is not secret, and making it unreadable
		// would only obstruct the one thing it exists for.
		if err := os.WriteFile(*out, pem, 0o644); err != nil { // #nosec G306; a public certificate
			return fmt.Errorf("write %s: %w", *out, err)
		}
		if _, err := fmt.Fprintf(os.Stderr, "Wrote %s\n", *out); err != nil {
			return err
		}
	} else if _, err := os.Stdout.Write(pem); err != nil {
		return err
	}

	if *quiet {
		return nil
	}
	return printTrustHints(pem)
}

// printTrustHints says what to do with the certificate, on stderr.
func printTrustHints(pem []byte) error {
	info, err := certsource.DescribeCA(pem)
	if err != nil {
		// The certificate itself is already delivered; failing to summarise it
		// is not a reason to report the command as failed.
		return nil
	}
	for _, line := range []string{
		"",
		"This is " + info.Subject + ".",
		"Install it once on every device that will reach this node's services:",
		"",
		"  macOS    sudo security add-trusted-cert -d -r trustRoot \\",
		"             -k /Library/Keychains/System.keychain kanea-ca.crt",
		"  Debian   sudo cp kanea-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates",
		"  Fedora   sudo cp kanea-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust",
		"  iOS      AirDrop it, then Settings → General → VPN & Device Management → install,",
		"             then Settings → General → About → Certificate Trust Settings → enable",
		"  Android  Settings → Security → Encryption & credentials → Install a certificate → CA",
		"",
		"Firefox keeps its own trust store; add it under Settings → Privacy & Security → Certificates.",
		"",
		"Check the fingerprint matches what the device shows:",
		"  " + info.Fingerprint,
		"",
	} {
		if _, err := fmt.Fprintln(os.Stderr, line); err != nil {
			return err
		}
	}
	return nil
}

// runCAInfo summarises the CA without printing it.
func runCAInfo(args []string) error {
	fs := flag.NewFlagSet("ca info", flag.ContinueOnError)
	ep := endpointFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, cerr := ep.client()
	if cerr != nil {
		return cerr
	}
	pem, err := client.CACertificate(context.Background())
	if err != nil {
		return err
	}
	info, err := certsource.DescribeCA(pem)
	if err != nil {
		return err
	}

	for _, line := range []string{
		"Subject:     " + info.Subject,
		// SHA-256, colon-separated and upper case, because that is the form a
		// device's trust dialog shows; comparing the two by eye is the only
		// verification an operator can actually perform.
		"Fingerprint: " + info.Fingerprint,
		"Valid from:  " + info.NotBefore.Format(time.DateOnly),
		"Valid until: " + info.NotAfter.Format(time.DateOnly),
	} {
		if _, err := fmt.Fprintln(os.Stdout, line); err != nil {
			return err
		}
	}
	return nil
}
