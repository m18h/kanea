package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// runClean resets everything the spike created: containers, endpoints, netns,
// the service and the imported policies. Safe to run repeatedly.
func runClean(ctx context.Context) error {
	e, ctx, err := setup(ctx)
	if err != nil {
		return err
	}
	defer e.client.Close()

	for _, f := range []string{isolationFile, dnsPolicyFile} {
		if err := removePolicy(f); err != nil {
			fmt.Printf("note: remove policy %s: %v\n", f, err)
		} else {
			fmt.Printf("policy %s removed\n", f)
		}
	}
	if err := os.Remove(lbStateFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("note: remove %s: %v\n", lbStateFile, err)
	} else {
		fmt.Printf("%s removed\n", lbStateFile)
	}

	containers, err := e.client.Containers(ctx)
	if err != nil {
		return err
	}
	for _, c := range containers {
		removeAlloc(ctx, e.client, c.ID())
		fmt.Printf("removed container %s\n", c.ID())
	}

	// Sweep any endpoint left behind by an interrupted run (netns already gone).
	eps, err := e.cil.endpoints(ctx)
	if err != nil {
		return err
	}
	for _, ep := range eps {
		cid := ep.Status.ExternalIdentifiers.ContainerID
		if cid == "" || !strings.HasPrefix(cid, "spike-") {
			continue
		}
		code, msg, err := e.cil.do(ctx, http.MethodDelete, "/endpoint/container-id:"+cid, nil, nil)
		fmt.Printf("removed endpoint %d (%s): http=%d %s %v\n", ep.ID, cid, code, truncate(msg, 60), err)
		deleteNetns(cid)
	}

	fmt.Println("clean done")
	return nil
}
