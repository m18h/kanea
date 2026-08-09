//go:build linux

package datapath

import "github.com/m18h/kanea/internal/runtime"

// hostNetns is the real Netns: runtime's persistent named namespaces.
// Namespace creation stays the runtime's, not the datapath's.
type hostNetns struct{}

func (hostNetns) Create(allocID string) (string, error) { return runtime.CreateNetns(allocID) }
func (hostNetns) Path(allocID string) string            { return runtime.NetnsPath(allocID) }
func (hostNetns) Delete(allocID string) error           { return runtime.DeleteNetns(allocID) }
