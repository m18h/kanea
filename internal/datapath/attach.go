package datapath

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/runtime"
)

// hostDevName derives the host-side veth name from the alloc id: "kn" plus
// 11 hex characters of its SHA-256, 13 characters total — inside IFNAMSIZ,
// collision-safe at any plausible alloc count, and stable so a re-attach and a
// detach find the same device without remembering anything.
func hostDevName(allocID string) string {
	sum := sha256.Sum256([]byte(allocID))
	return devPrefix + hex.EncodeToString(sum[:])[:11]
}

// peerDevName is the peer's temporary host-side name before it moves into the
// netns and becomes eth0.
func peerDevName(allocID string) string {
	return hostDevName(allocID) + "p"
}

// Attach wires an alloc into the datapath. The order is the contract, and it
// is deny-closed by construction (PRD v1.36 §5.2.5):
//
//	identity write → veth (host side DOWN) → tc programs → peer into netns →
//	peer addresses/routes/neigh → host neigh + up → the host /32 route LAST
//
// A skipped step fails closed, because an identity miss in the tc program is a
// drop and an absent route is unreachability — there is no wait loop, no
// readiness poll and nothing to retry. Idempotent: an alloc whose marked link
// already exists with its identity in place returns nil without touching the
// node.
func (d *Datapath) Attach(ctx context.Context, spec runtime.AllocSpec) error {
	if err := validateAttach(spec); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	projectID, err := d.ids.ProjectID(ctx, spec.Project)
	if err != nil {
		return err
	}
	serviceID, err := d.ids.ServiceID(ctx, spec.Project, spec.Service)
	if err != nil {
		return err
	}
	identity := dpmap.Identity{ProjectID: projectID, ServiceID: serviceID}

	d.mu.Lock()
	defer d.mu.Unlock()

	host := hostDevName(spec.ID)
	done, err := d.reuseExisting(spec.ID, host, identity)
	if err != nil {
		return err
	}
	if done {
		return nil
	}

	ip, err := d.ipam.Reserve(spec.ID)
	if err != nil {
		return err
	}
	var ip6 netip.Addr
	if d.ipam6 != nil {
		if ip6, err = d.ipam6.Reserve(spec.ID); err != nil {
			d.ipam.Release(spec.ID)
			return err
		}
	}

	if err := d.plumb(spec, host, ip, ip6, identity); err != nil {
		d.teardownPartial(spec.ID, host, ip, ip6)
		return err
	}

	d.log.Info("alloc attached",
		"alloc", spec.ID, "project", spec.Project, "service", spec.Service,
		"ip", ip, "ip6", ip6, "dev", host)
	return nil
}

// plumb performs the attach steps in their load-bearing order. The v6 half
// (a zero ip6 means v4-only) rides inside the same steps rather than adding
// new ones: identities for both families land before the veth exists, the
// peer's addresses and neighbors for both are configured before the link
// comes up, and the host routes stay last.
func (d *Datapath) plumb(spec runtime.AllocSpec, host string, ip, ip6 netip.Addr, identity dpmap.Identity) error {
	// Identity first: from the moment the veth exists, the tc program answers
	// for it, and an identity miss is a drop.
	if err := d.maps.PutIdentity(ip, identity); err != nil {
		return fmt.Errorf("datapath: identity for %s: %w", spec.ID, err)
	}
	if ip6.IsValid() {
		if err := d.maps.PutIdentity(ip6, identity); err != nil {
			return fmt.Errorf("datapath: v6 identity for %s: %w", spec.ID, err)
		}
	}
	hostMAC, peerMAC, err := d.nl.CreateVeth(host, peerDevName(spec.ID), aliasFor(spec.ID, ip, ip6))
	if err != nil {
		return fmt.Errorf("datapath: veth for %s: %w", spec.ID, err)
	}
	// Policy before the peer can emit a packet toward the host.
	if err := d.nl.AttachPrograms(host); err != nil {
		return fmt.Errorf("datapath: tc programs for %s: %w", spec.ID, err)
	}
	netnsPath, err := d.netns.Create(spec.ID)
	if err != nil {
		return fmt.Errorf("datapath: netns for %s: %w", spec.ID, err)
	}
	if err := d.nl.MovePeer(peerDevName(spec.ID), netnsPath); err != nil {
		return fmt.Errorf("datapath: move peer for %s: %w", spec.ID, err)
	}
	if err := d.nl.ConfigurePeer(netnsPath, ip, d.hostIP, ip6, d.hostIP6, hostMAC); err != nil {
		return fmt.Errorf("datapath: configure peer for %s: %w", spec.ID, err)
	}
	if err := d.nl.SetHostUp(host, ip, ip6, peerMAC); err != nil {
		return fmt.Errorf("datapath: host side for %s: %w", spec.ID, err)
	}
	// The host routes last: they are the step that makes the alloc reachable,
	// so everything reachability implies is already true when they land.
	if err := d.nl.InstallRoute(ip, host, d.hostIP); err != nil {
		return fmt.Errorf("datapath: route for %s: %w", spec.ID, err)
	}
	if ip6.IsValid() {
		if err := d.nl.InstallRoute(ip6, host, d.hostIP6); err != nil {
			return fmt.Errorf("datapath: v6 route for %s: %w", spec.ID, err)
		}
	}
	return nil
}

// reuseExisting handles the retry case: a marked link that already exists. A
// matching alias with the v4 identity present means the attach completed —
// InstallRoute is the last step, so an existing *complete* attach is exactly
// "return nil". Anything else — foreign alias, missing identity — is stale
// state from an interrupted attempt; it is torn down and the attach redone,
// because a half-plumbed link that is left standing looks attached and passes
// nothing.
//
// The adopt gate is deliberately the v4 identity alone (PRD v1.41): a
// v4-only alias on a node whose v6 was just enabled is a COMPLETE pre-v1.41
// attachment, and re-plumbing it would yank the veth under a running
// workload. It is adopted as it stands; the alloc gains v6 at its next
// replacement, and the v6 backend set simply omits it until then.
func (d *Datapath) reuseExisting(allocID, host string, want dpmap.Identity) (bool, error) {
	links, err := d.nl.List()
	if err != nil {
		return false, fmt.Errorf("datapath: list links: %w", err)
	}
	var existing *Link
	for i := range links {
		if links[i].Name == host {
			existing = &links[i]
			break
		}
	}
	if existing == nil {
		return false, nil
	}

	if id, ip, ip6, ok := parseAlias(existing.Alias); ok && id == allocID {
		idents, err := d.maps.Identities()
		if err != nil {
			return false, fmt.Errorf("datapath: read identities: %w", err)
		}
		if got, present := idents[ip]; present && got == want {
			d.ipam.Adopt(allocID, ip)
			if ip6.IsValid() && d.ipam6 != nil {
				d.ipam6.Adopt(allocID, ip6)
			}
			return true, nil
		}
	}

	d.log.Warn("replacing stale datapath link", "alloc", allocID, "dev", host, "alias", existing.Alias)
	if err := d.nl.DeleteVeth(host); err != nil {
		return false, fmt.Errorf("datapath: remove stale link %s: %w", host, err)
	}
	d.ipam.Release(allocID)
	if d.ipam6 != nil {
		d.ipam6.Release(allocID)
	}
	return false, nil
}

// teardownPartial unwinds a failed attach, best effort: every step logs
// instead of failing, because the attach error is the one worth reporting and
// the reconciler will retry into an idempotent Attach anyway.
func (d *Datapath) teardownPartial(allocID, host string, ip, ip6 netip.Addr) {
	if err := d.nl.DeleteVeth(host); err != nil {
		d.log.Warn("partial teardown: delete veth", "alloc", allocID, "error", err)
	}
	if err := d.maps.DeleteIdentity(ip); err != nil {
		d.log.Warn("partial teardown: delete identity", "alloc", allocID, "error", err)
	}
	if ip6.IsValid() {
		if err := d.maps.DeleteIdentity(ip6); err != nil {
			d.log.Warn("partial teardown: delete v6 identity", "alloc", allocID, "error", err)
		}
	}
	d.ipam.Release(allocID)
	if d.ipam6 != nil {
		d.ipam6.Release(allocID)
	}
	if err := d.netns.Delete(allocID); err != nil {
		d.log.Warn("partial teardown: delete netns", "alloc", allocID, "error", err)
	}
}

// Detach removes the alloc from the datapath: veth, identity, reservation,
// netns — the attach in reverse, tolerant of absence at every step, because
// teardown runs on paths where part of it already happened. An empty alloc id
// is a silent no-op, matching the previous driver's contract.
func (d *Datapath) Detach(ctx context.Context, spec runtime.AllocSpec) error {
	if spec.ID == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	host := hostDevName(spec.ID)
	ip, known := d.ipam.Lookup(spec.ID)
	var ip6 netip.Addr
	if d.ipam6 != nil {
		ip6, _ = d.ipam6.Lookup(spec.ID)
	}
	if !known {
		// A restart lost the in-memory reservation; the link's alias is the
		// durable copy — and it carries both families, so a dual-stack
		// attachment's v6 identity is deleted even when v6 has since been
		// turned off (ipam6 nil). List failing is not fatal — the identity
		// delete is then skipped, and an identity without an interface denies
		// traffic rather than passing it.
		if links, err := d.nl.List(); err == nil {
			for _, l := range links {
				if l.Name != host {
					continue
				}
				if id, addr, addr6, ok := parseAlias(l.Alias); ok && id == spec.ID {
					ip, known = addr, true
					ip6 = addr6
				}
				break
			}
		} else {
			d.log.Warn("detach: list links", "alloc", spec.ID, "error", err)
		}
	}

	if err := d.nl.DeleteVeth(host); err != nil {
		return fmt.Errorf("datapath: delete veth for %s: %w", spec.ID, err)
	}
	if known {
		if err := d.maps.DeleteIdentity(ip); err != nil {
			return fmt.Errorf("datapath: delete identity for %s: %w", spec.ID, err)
		}
	}
	if ip6.IsValid() {
		if err := d.maps.DeleteIdentity(ip6); err != nil {
			return fmt.Errorf("datapath: delete v6 identity for %s: %w", spec.ID, err)
		}
	}
	d.ipam.Release(spec.ID)
	if d.ipam6 != nil {
		d.ipam6.Release(spec.ID)
	}
	if err := d.netns.Delete(spec.ID); err != nil {
		return fmt.Errorf("datapath: delete netns for %s: %w", spec.ID, err)
	}
	d.log.Debug("alloc detached", "alloc", spec.ID)
	return nil
}

// validateAttach rejects specs the datapath cannot represent.
func validateAttach(spec runtime.AllocSpec) error {
	if len(spec.ID) < runtime.MinAllocIDLength {
		return fmt.Errorf("datapath: alloc id %q is %d characters, need at least %d",
			spec.ID, len(spec.ID), runtime.MinAllocIDLength)
	}
	if strings.Contains(spec.ID, "/") {
		// The alias is "kanea/<alloc>/<ip>"; a slash in the id would make it
		// parse as a different alloc's.
		return fmt.Errorf("datapath: alloc id %q contains a %q", spec.ID, "/")
	}
	if err := validateName("project", spec.Project); err != nil {
		return err
	}
	return validateName("service", spec.Service)
}

// validateName is the last-line assertion project/service names get — they are
// DNS-1123 labels by the time they reach here (jobspec R1), but a bad one
// would corrupt id keys and aliases, which fails silently and denies traffic.
func validateName(kind, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("datapath: empty %s name", kind)
	case strings.ContainsAny(value, "/=:;, \t\n"):
		return fmt.Errorf("datapath: %s name %q contains a character that is not valid in a name", kind, value)
	}
	return nil
}
