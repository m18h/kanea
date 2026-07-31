package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// runClean removes the spike's build containers, snapshots and output dirs, and
// empties the registry's data. Safe to run repeatedly.
func runClean(ctx context.Context) error {
	e, ctx, err := setup(ctx)
	if err != nil {
		return err
	}
	defer e.client.Close()

	containers, err := e.client.Containers(ctx)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if c.ID() == "kanea-spike-registry" {
			continue // the registry is a service, not spike output
		}
		removeContainer(ctx, e.client, c.ID())
		fmt.Printf("removed container %s\n", c.ID())
	}

	if err := os.RemoveAll(workDir + "/out"); err != nil {
		fmt.Printf("note: remove out dir: %v\n", err)
	} else {
		fmt.Println("build outputs removed")
	}

	// Wipe pushed images by restarting the registry on an empty data dir.
	if err := exec.Command("systemctl", "stop", "kanea-spike-registry").Run(); err != nil {
		fmt.Printf("note: stop registry: %v\n", err)
	}
	if err := os.RemoveAll(workDir + "/registry-data"); err != nil {
		fmt.Printf("note: remove registry data: %v\n", err)
	}
	if err := os.MkdirAll(workDir+"/registry-data", 0o755); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "start", "kanea-spike-registry").Run(); err != nil {
		fmt.Printf("note: start registry: %v\n", err)
	} else {
		fmt.Println("registry restarted with empty storage")
	}

	fmt.Println("clean done")
	return nil
}
