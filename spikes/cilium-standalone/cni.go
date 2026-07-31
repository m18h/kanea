package main

import (
	"context"
	"fmt"
	"os"

	cnilib "github.com/containernetworking/cni/libcni"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// cniClient loads the conflist that provision-vm.sh installed at the PRD §5.2.5
// path, so the spike exercises the real deployed config rather than an inline copy.
func cniClient() (*cnilib.CNIConfig, *cnilib.NetworkConfigList, error) {
	b, err := os.ReadFile(cniConfPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", cniConfPath, err)
	}
	conf, err := cnilib.ConfListFromBytes(b)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", cniConfPath, err)
	}
	// nil exec: libcni substitutes its default plugin invoker.
	return cnilib.NewCNIConfig([]string{cniBinDir}, nil), conf, nil
}

// cniRuntime targets a *persistent* netns (/run/netns/<id>) rather than
// /proc/<pid>/ns/net: the network must exist before the workload starts, so the
// alloc never runs unlabelled (see phaseNet).
//
// The container ID must be >= 5 characters: Cilium derives the temporary
// interface name from the first 5 characters of "<containerID>:<ifname>", and a
// shorter ID leaks the ':' into an interface name (kernel EINVAL).
func cniRuntime(containerID string) *cnilib.RuntimeConf {
	return &cnilib.RuntimeConf{
		ContainerID: containerID,
		NetNS:       netnsPath(containerID),
		IfName:      "eth0",
		Args:        [][2]string{{"IgnoreUnknown", "1"}},
	}
}

func cniAdd(ctx context.Context, containerID string) (string, error) {
	cninet, conf, err := cniClient()
	if err != nil {
		return "", err
	}
	res, err := cninet.AddNetworkList(ctx, conf, cniRuntime(containerID))
	if err != nil {
		return "", fmt.Errorf("CNI ADD %s: %w", containerID, err)
	}
	return cniIPv4(res)
}

func cniDel(ctx context.Context, containerID string) error {
	cninet, conf, err := cniClient()
	if err != nil {
		return err
	}
	if err := cninet.DelNetworkList(ctx, conf, cniRuntime(containerID)); err != nil {
		return fmt.Errorf("CNI DEL %s: %w", containerID, err)
	}
	return nil
}

func cniIPv4(res cnitypes.Result) (string, error) {
	cur, err := current.NewResultFromResult(res)
	if err != nil {
		return "", err
	}
	for _, ip := range cur.IPs {
		if v4 := ip.Address.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("CNI result carried no IPv4 address")
}
