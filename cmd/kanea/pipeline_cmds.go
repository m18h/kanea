package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/gitops"
)

// `kanea build` and `kanea project` (PRD §10, §16.2).

// runBuild implements `kanea build [project/]service`.
func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	socket := socketFlag(fs)
	project := fs.String("project", "", "project name")
	deploy := fs.Bool("deploy", true, "deploy the built digest when the build succeeds")
	follow := fs.Bool("follow", true, "stream the build log until it finishes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea build [--project P] <[project/]service>")
	}

	ctx := context.Background()
	client := api.NewClient(*socket)

	// One resolver for every service-targeting command (v1.56): build used
	// to carry its own stricter splitter, which was the one place a unique
	// bare name did not resolve.
	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	target, err := findService(services, *project, fs.Arg(0))
	if err != nil {
		return err
	}

	run, err := client.Build(ctx, target.Project, target.Service, *deploy)
	if err != nil {
		return err
	}

	o := newOut()
	o.printf("queued build %s for %s/%s\n", gitops.ShortID(run.ID), target.Project, target.Service)
	if err := o.Err(); err != nil {
		return err
	}
	if !*follow {
		return nil
	}
	return followBuild(ctx, client, run)
}

// followBuild streams a run's log, then reports how it ended.
//
// The exit status matters: `kanea build` in a script must fail when the build
// failed, and a streamed log that ends is not by itself a success; the stream
// also ends when the run is cancelled.
func followBuild(ctx context.Context, client *api.Client, run gitops.Run) error {
	// A queued build has no log file until the worker picks it up, and the
	// worker may be busy with someone else's. Wait for it rather than reporting
	// "no log", which would be true and useless.
	if err := waitForBuildLog(ctx, client, run); err != nil {
		return err
	}
	if err := client.BuildLogs(ctx, run.Project, run.Service, run.ID, true, scrubTerminal{os.Stdout}); err != nil {
		return err
	}

	final, err := client.Run(ctx, run.Project, run.Service, run.ID)
	if err != nil {
		return err
	}
	o := newOut()
	o.printf("%s in %s\n", final.State, shortDuration(final.Duration(time.Now())))
	if final.Image != "" {
		o.printf("image %s\n", final.Image)
	}
	if err := o.Err(); err != nil {
		return err
	}
	if final.State != gitops.RunSucceeded {
		if final.Error != "" {
			return fmt.Errorf("build %s: %s", gitops.ShortID(run.ID), final.Error)
		}
		return fmt.Errorf("build %s %s", gitops.ShortID(run.ID), final.State)
	}
	return nil
}

// waitForBuildLog blocks until the run has left the queue.
func waitForBuildLog(ctx context.Context, client *api.Client, run gitops.Run) error {
	for {
		current, err := client.Run(ctx, run.Project, run.Service, run.ID)
		if err != nil {
			return err
		}
		if current.State != gitops.RunQueued {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// runProject implements `kanea project <sub>`.
func runProject(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea project sync <project> | kanea project builds <project>")
	}
	switch args[0] {
	case "sync":
		return runProjectSync(args[1:])
	case "builds", "runs":
		return runProjectBuilds(args[1:])
	default:
		return fmt.Errorf("unknown project subcommand %q; expected sync or builds", args[0])
	}
}

// runProjectSync implements `kanea project sync <project>`.
func runProjectSync(args []string) error {
	fs := flag.NewFlagSet("project sync", flag.ContinueOnError)
	socket := socketFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea project sync <project>")
	}

	result, err := api.NewClient(*socket).Sync(context.Background(), fs.Arg(0))
	if err != nil {
		return err
	}
	o := newOut()
	o.printf("commit %s", gitops.ShortID(result.Commit))
	if result.Message != "" {
		o.printf("  %s", firstLine(result.Message))
	}
	o.printf("\n")
	if len(result.Applied) > 0 {
		o.printf("applied  %s\n", strings.Join(result.Applied, ", "))
	}
	if len(result.Built) > 0 {
		o.printf("building %s\n", strings.Join(result.Built, ", "))
	}
	// Held is not a failure and not a success. Saying so plainly is the whole
	// point of require_approval: someone has to go and look.
	if len(result.Held) > 0 {
		o.printf("held for approval: %s\n", strings.Join(result.Held, ", "))
	}
	if len(result.Applied) == 0 && len(result.Built) == 0 && len(result.Held) == 0 {
		o.printf("nothing to do\n")
	}
	return o.Err()
}

// runProjectBuilds implements `kanea project builds <project>`.
func runProjectBuilds(args []string) error {
	fs := flag.NewFlagSet("project builds", flag.ContinueOnError)
	socket := socketFlag(fs)
	service := fs.String("service", "", "only this service")
	limit := fs.Int("limit", gitops.DefaultRunListLimit, "how many runs to list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea project builds <project>")
	}

	runs, err := api.NewClient(*socket).Runs(context.Background(), fs.Arg(0), *service, *limit)
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		o := newOut()
		o.println("no builds")
		return o.Err()
	}

	o := newOut()
	o.table()
	o.printf("RUN\tSERVICE\tSTATE\tTRIGGER\tDURATION\tCOMMIT\tIMAGE\n")
	now := time.Now()
	for _, run := range runs {
		o.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			gitops.ShortID(run.ID), run.Service, run.State, run.Trigger,
			shortDuration(run.Duration(now)), gitops.ShortID(run.Commit),
			lastPathElement(run.Image))
	}
	return o.Err()
}

// firstLine trims a commit message to its subject.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// lastPathElement shortens an image reference for a table: the registry host
// and the repository are the same for every row and the digest is what differs.
func lastPathElement(ref string) string {
	if ref == "" {
		return "-"
	}
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		return ref[i+1:]
	}
	return ref
}
