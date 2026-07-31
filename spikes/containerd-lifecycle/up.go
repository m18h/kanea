package main

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// runUp is a debug helper: starts one alloc with CNI networking and leaves it
// running so we can poke at it with ctr/tcpdump from the VM.
// usage: spike up <id> [cmd...]
func runUp(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: spike up <id> [cmd...]")
	}
	id := args[0]
	cmd := []string{"sleep", "infinity"}
	if len(args) > 1 {
		cmd = args[1:]
	}
	client, ctx, err := dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	img, err := ensureImage(ctx, client)
	if err != nil {
		return err
	}
	if err := writeCNINetConf(); err != nil {
		return err
	}
	task, err := startAlloc(ctx, client, img, alloc{ID: id, Cmd: cmd})
	if err != nil {
		return err
	}
	ips, err := cniAdd(ctx, id, task.Pid())
	if err != nil {
		return err
	}
	fmt.Printf("up: %s pid=%d ip=%s\n", id, task.Pid(), strings.Join(ips, ","))
	// Do NOT wait; leave running for manual debugging.
	_ = os.Stdout.Sync()
	return nil
}
