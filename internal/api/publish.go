package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
)

// PathEdgePolicy reports what this node lets a spec publish.
const PathEdgePolicy = "/v1/edge/policy"

// DefaultPublishRange is what a node allows a spec to bind when nothing is
// configured.
//
// Unprivileged ports only. Privileged ports are the node's decision, not the
// spec's: a repository anyone can push to must not be able to claim 22, 25 or
// 53 on this machine's address.
const DefaultPublishRange = "1024-65535"

// PublishOff disables published ports entirely.
const PublishOff = "off"

// PortPolicy is which node ports a spec may claim (PRD §6.2 R22).
//
// It is enforced here rather than at plan time because GitOps never goes
// through the CLI: a synced repository reaches the Store through handleApply,
// and a check that lives only in `kanea plan` is a check a push walks past.
// `kanea plan` asks for this policy over PathEdgePolicy so the refusal still
// lands in front of the person who typed it — but that is a courtesy, and this
// is the boundary.
type PortPolicy struct {
	// ranges are the inclusive spans a spec may bind. Empty means publishing is
	// off, which is a real configuration and not an unset one.
	ranges []portRange
	raw    string
}

type portRange struct{ lo, hi int }

// ParsePortPolicy reads a --publish-ports value: "1024-65535", "8000-9000,25565",
// or "off".
func ParsePortPolicy(spec string) (PortPolicy, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = DefaultPublishRange
	}
	if strings.EqualFold(spec, PublishOff) {
		return PortPolicy{raw: PublishOff}, nil
	}

	out := PortPolicy{raw: spec}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, err := parseRange(part)
		if err != nil {
			return PortPolicy{}, fmt.Errorf("--publish-ports %q: %w", part, err)
		}
		out.ranges = append(out.ranges, portRange{lo: lo, hi: hi})
	}
	if len(out.ranges) == 0 {
		return PortPolicy{}, fmt.Errorf("--publish-ports %q names no port; write %q to disable publishing",
			spec, PublishOff)
	}
	sort.Slice(out.ranges, func(i, j int) bool { return out.ranges[i].lo < out.ranges[j].lo })
	return out, nil
}

func parseRange(part string) (int, int, error) {
	lo, hi := part, part
	if from, to, isRange := strings.Cut(part, "-"); isRange {
		lo, hi = strings.TrimSpace(from), strings.TrimSpace(to)
	}
	low, err := strconv.Atoi(lo)
	if err != nil {
		return 0, 0, errors.New("not a port or a port range")
	}
	high, err := strconv.Atoi(hi)
	if err != nil {
		return 0, 0, errors.New("not a port or a port range")
	}
	if low < 1 || high > jobspec.MaxPort || low > high {
		return 0, 0, fmt.Errorf("outside 1-%d, or reversed", jobspec.MaxPort)
	}
	return low, high, nil
}

// String is the policy as an operator wrote it.
func (p PortPolicy) String() string {
	if p.raw == "" {
		return DefaultPublishRange
	}
	return p.raw
}

// Enabled reports whether this node permits published ports at all.
func (p PortPolicy) Enabled() bool { return len(p.ranges) > 0 }

// Allows reports whether a spec may bind this node port.
func (p PortPolicy) Allows(port int) bool {
	if _, reserved := jobspec.ReservedPorts[port]; reserved {
		return false
	}
	for _, r := range p.ranges {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// Check refuses a desired record that publishes a port this node does not
// allow. The error names the reason, because "port 22 is not permitted" reads
// as a bug and the actual reason does not.
func (p PortPolicy) Check(d reconciler.Desired) error {
	if len(d.Publish) == 0 {
		return nil
	}
	name := d.Project + "/" + d.Service
	if !p.Enabled() {
		return fmt.Errorf("%s publishes %d node port(s), and this node has published ports "+
			"turned off (--publish-ports %s)", name, len(d.Publish), PublishOff)
	}
	for _, published := range d.Publish {
		if reason, reserved := jobspec.ReservedPorts[published.Host]; reserved {
			return fmt.Errorf("%s publishes node port %d, which Kanea holds: %s",
				name, published.Host, reason)
		}
		if !p.Allows(published.Host) {
			return fmt.Errorf("%s publishes node port %d, which this node does not allow "+
				"(--publish-ports %s). A spec that could claim 22, 25 or 53 on this node's "+
				"address would be deciding something that belongs to whoever owns the machine",
				name, published.Host, p.String())
		}
	}
	return nil
}

// handleEdgePolicy reports the node's publishing policy, so `kanea plan` can
// refuse a port in front of the person who typed it rather than at apply.
func (s *Server) handleEdgePolicy(w http.ResponseWriter, _ *http.Request) {
	reserved := make([]int, 0, len(jobspec.ReservedPorts))
	for port := range jobspec.ReservedPorts {
		reserved = append(reserved, port)
	}
	sort.Ints(reserved)

	ranges := make([]map[string]int, 0, len(s.publishPorts.ranges))
	for _, r := range s.publishPorts.ranges {
		ranges = append(ranges, map[string]int{"from": r.lo, "to": r.hi})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publish_enabled": s.publishPorts.Enabled(),
		"publish_ports":   s.publishPorts.String(),
		"ranges":          ranges,
		"reserved":        reserved,
	})
}
