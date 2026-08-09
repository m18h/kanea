package network

import (
	"context"
	"fmt"
	"net"
	"os"

	cnilib "github.com/containernetworking/cni/libcni"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
)

// CNI defaults (PRD §5.2.5).
const (
	// DefaultCNIConfPath is where `kanea install` writes the Cilium conflist
	// (internal/provision.Layout.Files).
	//
	// Under /etc/kanea rather than /etc/cni/net.d: that directory is shared
	// with whatever else on the node uses CNI, and every plugin there is
	// consulted in name order by anything reading it. Kanea's containerd is
	// pointed at its own directory instead, so installing Kanea cannot change
	// how another runtime networks its containers (PRD §5.2.12).
	DefaultCNIConfPath = "/etc/kanea/cni/net.d/05-cilium.conflist"
	// DefaultCNIBinDir holds the cilium-cni plugin binary. Kanea's own, for
	// the same reason.
	DefaultCNIBinDir = "/usr/local/lib/kanea/cni/bin"
	// interfaceName is the alloc-side interface every plugin creates.
	interfaceName = "eth0"
)

// cniInvoker runs CNI ADD and DEL against a pre-created netns.
//
// The netns is the persistent one at /run/netns/<alloc> rather than
// /proc/<pid>/ns/net, and that is the whole design: the network has to be
// complete before the workload's first instruction, so there is no process to
// borrow a namespace from yet (M0 spikes ①, ②).
type cniInvoker struct {
	confPath string
	binDir   string
}

func newCNIInvoker(confPath, binDir string) *cniInvoker {
	if confPath == "" {
		confPath = DefaultCNIConfPath
	}
	if binDir == "" {
		binDir = DefaultCNIBinDir
	}
	return &cniInvoker{confPath: confPath, binDir: binDir}
}

// load reads the deployed CNI configuration. It is read per call rather than
// cached at construction: the operator may fix a broken conflist while kanead
// is running, and a cached copy would mean the fix does not take until restart.
func (c *cniInvoker) load() (*cnilib.CNIConfig, *cnilib.NetworkConfigList, error) {
	raw, err := os.ReadFile(c.confPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read cni config %s: %w", c.confPath, err)
	}
	conf, err := cnilib.ConfListFromBytes(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cni config %s: %w", c.confPath, err)
	}
	// A nil exec makes libcni use its default plugin invoker.
	return cnilib.NewCNIConfig([]string{c.binDir}, nil), conf, nil
}

// runtimeConf describes one alloc's attachment.
func (c *cniInvoker) runtimeConf(allocID, netnsPath string) *cnilib.RuntimeConf {
	return &cnilib.RuntimeConf{
		ContainerID: allocID,
		NetNS:       netnsPath,
		IfName:      interfaceName,
		// IgnoreUnknown keeps a plugin from rejecting args it does not model.
		Args: [][2]string{{"IgnoreUnknown", "1"}},
	}
}

// add attaches the alloc and returns the IPv4 address assigned to it.
func (c *cniInvoker) add(ctx context.Context, allocID, netnsPath string) (string, error) {
	cninet, conf, err := c.load()
	if err != nil {
		return "", err
	}
	res, err := cninet.AddNetworkList(ctx, conf, c.runtimeConf(allocID, netnsPath))
	if err != nil {
		return "", fmt.Errorf("cni add %s: %w", allocID, err)
	}
	return ipv4From(res)
}

// del detaches the alloc. CNI DEL is required to be idempotent by the spec, so
// a repeat call on an already-detached alloc succeeds — which is what makes a
// retrying teardown safe.
//
// It must run while the netns still exists: the plugin enters the namespace to
// clean up, and deleting the namespace first leaves the endpoint and its IP
// allocation stranded in the agent (M0 spike ②).
func (c *cniInvoker) del(ctx context.Context, allocID, netnsPath string) error {
	cninet, conf, err := c.load()
	if err != nil {
		return err
	}
	if err := cninet.DelNetworkList(ctx, conf, c.runtimeConf(allocID, netnsPath)); err != nil {
		return fmt.Errorf("cni del %s: %w", allocID, err)
	}
	return nil
}

// ipv4From extracts the assigned IPv4 address from a CNI result.
func ipv4From(res cnitypes.Result) (string, error) {
	cur, err := current.NewResultFromResult(res)
	if err != nil {
		return "", fmt.Errorf("convert cni result: %w", err)
	}
	for _, ip := range cur.IPs {
		if v4 := ip.Address.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("cni result carried no IPv4 address")
}

// validIP reports whether s parses as an IP address — used to refuse an
// endpoint whose address the agent has not filled in yet.
func validIP(s string) bool {
	return net.ParseIP(s) != nil
}
