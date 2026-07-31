package main

import (
	"context"
	"fmt"
	"os"

	cnilib "github.com/containernetworking/cni/libcni"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// bridgeConf is a minimal throwaway network for spike ② only.
// Spike ① replaces this with Cilium; M2 derives real config from the network driver.
const bridgeConf = `{
  "cniVersion": "1.0.0",
  "name": "kanea-spike",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "kaneasp0",
      "isGateway": true,
      "isDefaultGateway": true,
      "ipMasq": true,
      "ipam": {
        "type": "host-local",
        "ranges": [[{"subnet": "10.200.0.0/24", "gateway": "10.200.0.1"}]],
        "dataDir": "/var/lib/cni/networks/kanea-spike"
      }
    }
  ]
}`

func writeCNINetConf() error {
	if b, err := os.ReadFile(cniConfPath); err == nil && string(b) == bridgeConf {
		return nil
	}
	if err := os.MkdirAll("/var/lib/cni/networks/kanea-spike", 0o755); err != nil {
		return err
	}
	return os.WriteFile(cniConfPath, []byte(bridgeConf), 0o644)
}

func cniRuntime(containerID string, pid uint32) *cnilib.RuntimeConf {
	return &cnilib.RuntimeConf{
		ContainerID: containerID,
		NetNS:       fmt.Sprintf("/proc/%d/ns/net", pid),
		IfName:      "eth0",
		Args:        [][2]string{{"IgnoreUnknown", "1"}},
	}
}

func cniClient() (*cnilib.CNIConfig, *cnilib.NetworkConfigList, error) {
	conf, err := cnilib.ConfListFromBytes([]byte(bridgeConf))
	if err != nil {
		return nil, nil, fmt.Errorf("parse conflist: %w", err)
	}
	// nil exec: libcni substitutes its default plugin invoker.
	return cnilib.NewCNIConfig([]string{cniBinDir}, nil), conf, nil
}

// cniAdd runs CNI ADD for the task's netns and returns allocated IPv4 addresses.
func cniAdd(ctx context.Context, containerID string, pid uint32) ([]string, error) {
	cninet, conf, err := cniClient()
	if err != nil {
		return nil, err
	}
	res, err := cninet.AddNetworkList(ctx, conf, cniRuntime(containerID, pid))
	if err != nil {
		return nil, fmt.Errorf("CNI ADD %s: %w", containerID, err)
	}
	return cniIPs(res)
}

// cniDel releases CNI state. Tolerates a dead task (netns already gone).
func cniDel(id string, pid uint32) error {
	cninet, conf, err := cniClient()
	if err != nil {
		return err
	}
	if err := cninet.DelNetworkList(context.Background(), conf, cniRuntime(id, pid)); err != nil {
		return fmt.Errorf("CNI DEL %s: %w", id, err)
	}
	return nil
}

func cniIPs(res cnitypes.Result) ([]string, error) {
	cur, err := current.NewResultFromResult(res)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, ip := range cur.IPs {
		ips = append(ips, ip.Address.String())
	}
	return ips, nil
}
