package main

import (
	"context"
	"fmt"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// runClean unmounts every driver, removes the spike's containers and empties the
// bucket. Safe to run repeatedly, and the way out of a wedged FUSE mount.
func runClean(ctx context.Context) error {
	for i := range drivers {
		d := &drivers[i]
		if err := d.unmount(); err != nil {
			fmt.Printf("note: unmount %s: %v\n", d.Name, err)
		} else {
			fmt.Printf("unmounted %s (%s)\n", d.Name, d.Mount)
		}
	}

	if err := systemctl("start", minioUnit); err != nil {
		fmt.Printf("note: %v\n", err)
	}

	if client, err := containerd.New(containerdSock); err == nil {
		defer client.Close()
		cctx := namespaces.WithNamespace(ctx, ctrNamespace)
		if containers, err := client.Containers(cctx); err == nil {
			for _, c := range containers {
				removeContainer(cctx, client, c.ID())
				fmt.Printf("removed container %s\n", c.ID())
			}
		}
	} else {
		fmt.Printf("note: containerd: %v\n", err)
	}

	if err := resetBucket(); err != nil {
		fmt.Printf("note: reset bucket: %v\n", err)
	} else {
		fmt.Printf("bucket %s emptied\n", bucket)
	}

	fmt.Println("clean done")
	return nil
}
