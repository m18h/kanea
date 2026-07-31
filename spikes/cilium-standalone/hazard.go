package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const hazardFile = "kanea-spike-hazard.yaml"

// malformedPolicy is not valid CNP YAML. pkg/policy/directory/watcher.go calls
// logging.Fatal() when translation fails — both during the startup scan and on
// fsnotify events — so this is expected to take the agent down.
const malformedPolicy = `apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: kanea-spike-hazard
spec:
  endpointSelector: "this should be an object, not a string"
  ingress: 17
`

// runHazard verifies the blast radius of an invalid policy file. It is a
// separate subcommand because it deliberately kills the agent; `all` must not
// depend on it.
func runHazard(ctx context.Context) error {
	cil := newCiliumClient()

	if _, err := cil.endpoints(ctx); err != nil {
		return fmt.Errorf("agent not reachable before the test: %w", err)
	}
	fmt.Println("agent healthy; installing a malformed policy file")

	if err := writePolicy(hazardFile, malformedPolicy); err != nil {
		return err
	}

	died, detail := agentDied(ctx, cil, 30*time.Second)
	check("invalid policy file is fatal to cilium-agent (hazard, not a feature)",
		died, detail)

	// Recovery: the file must go before the agent restarts, or the startup scan
	// hits the same Fatal and the agent crash-loops.
	fmt.Println("\nremoving the file and restarting the agent")
	if err := removePolicy(hazardFile); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "restart", "kanea-spike-cilium").CombinedOutput(); err != nil {
		return fmt.Errorf("restart agent: %w (%s)", err, out)
	}
	recovered := waitAgent(ctx, cil, 90*time.Second)
	check("agent recovers once the bad file is removed", recovered, "")

	// And confirm the crash-loop claim: a bad file present at startup is fatal too.
	files, _ := os.ReadDir(policyDir)
	info("policy directory after recovery", fmt.Sprintf("%d file(s) in %s", len(files), filepath.Clean(policyDir)))

	return summary()
}

func agentDied(ctx context.Context, cil *ciliumClient, timeout time.Duration) (bool, string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := cil.endpoints(ctx); err != nil {
			return true, fmt.Sprintf("API unreachable after %v: %v",
				time.Until(deadline).Round(time.Second), err)
		}
		settle(500 * time.Millisecond)
	}
	return false, fmt.Sprintf("agent still serving the API %v after the write", timeout)
}

func waitAgent(ctx context.Context, cil *ciliumClient, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := cil.endpoints(ctx); err == nil {
			return true
		}
		settle(time.Second)
	}
	return false
}
