package reconciler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/m18h/kanea/internal/runtime"
)

// ChangeKind is what an apply would do to one service.
type ChangeKind string

// The three things an apply can do.
const (
	ChangeCreate  ChangeKind = "create"
	ChangeUpdate  ChangeKind = "update"
	ChangeDestroy ChangeKind = "destroy"
)

// FieldChange is one labelled row under a service header: a field of the spec,
// the detail of what would happen to it, and whether applying it replaces the
// running containers.
//
// Lines is a slice rather than a string because most of what a spec declares is
// a *set* - volumes, routes, ports, files, grants - and folding six volume
// changes into one line is how the pre-v1.90 diff became unreadable at exactly
// the moment it mattered.
type FieldChange struct {
	// Field is the spec's own word for what changed ("volumes", "expose").
	Field string
	// Lines are the rendered detail, one per resource for a set-valued field.
	Lines []string
	// Rolls records that this field is SpecHash material, so applying it
	// replaces every running alloc of the service.
	Rolls bool
}

// ServiceChange is everything an apply would do to one service.
type ServiceChange struct {
	Project string
	Service string
	Kind    ChangeKind
	// Count and Image describe the service as the header line names it: the
	// declared values for a create, the stored ones for a destroy.
	Count  int
	Image  string
	Fields []FieldChange
	// Rolls is true when any field rolls: the service's containers would be
	// replaced, not reconfigured in place.
	Rolls bool
}

// Key is the "<project>/<service>" form every surface names a service by.
func (c ServiceChange) Key() string { return c.Project + "/" + c.Service }

// Changes is the one implementation of "what would an apply do".
//
// It lives here rather than in the CLI because more than the CLI asks: `kanea
// plan`, `kanea run`'s pre-apply preview and the MCP plan_spec tool. Two
// implementations of "what would change" drift, and they drift into a plan that
// does not match the apply that follows it.
//
// It compares only what a *user* declares. Server-owned fields (Generation,
// PinnedImage and the auto-update bookkeeping beside it) are never compared,
// because the client's desired state has them zeroed and applyServices carries
// them over from the stored record: comparing them would report a change on
// every service that has ever been restarted or is following a tag.
//
// pruneProjects is the scope a --remove-orphans apply claims authority over;
// stored services in one of those that the spec no longer declares are rendered
// as destroyed. Callers that cannot prune pass nothing.
func Changes(current, desired []Desired, pruneProjects []string) []ServiceChange {
	byKey := make(map[string]Desired, len(current))
	for _, svc := range current {
		byKey[svc.Project+"/"+svc.Service] = svc
	}

	var out []ServiceChange
	for _, want := range desired {
		have, exists := byKey[want.Project+"/"+want.Service]
		if !exists {
			out = append(out, creation(want))
			continue
		}
		if change, changed := update(have, want); changed {
			out = append(out, change)
		}
	}
	out = append(out, destructions(current, desired, pruneProjects)...)

	// By name, not by the symbol the line happens to start with. Sorting the
	// rendered strings (which is what this did before v1.90) put every create
	// before every destroy before every update, so one service's changes were
	// scattered across the output of a spec that touched several.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Service < out[j].Service
	})
	return out
}

// creation describes a service the spec declares and the node does not have.
//
// The header carries count and image, and the fields enumerate the resources
// the service brings with it: what is about to exist that does not yet.
func creation(want Desired) ServiceChange {
	c := ServiceChange{
		Project: want.Project, Service: want.Service, Kind: ChangeCreate,
		Count: want.Count, Image: want.RunImage(),
	}
	// No field of a create is marked as rolling. Rolls means "running
	// containers are replaced", and a service that does not exist has none:
	// annotating every line of a create would be noise on the one change whose
	// consequence is already in its verb.
	add := func(field string, lines []string) {
		if len(lines) > 0 {
			c.Fields = append(c.Fields, FieldChange{Field: field, Lines: lines})
		}
	}
	add("volumes", prefixed("+", flatten(volumeMap(want.Volumes))))
	add("files", prefixed("+", flatten(fileMap(want.Files))))
	add("ports", prefixed("+", flatten(portMap(want.Ports))))
	add("devices", prefixed("+", flatten(deviceMap(want.Devices))))
	add("sockets", prefixed("+", flatten(socketMap(want.Sockets))))
	add("init", prefixed("+", flatten(initMap(want.Init))))
	add("env", oneLine(fmt.Sprintf("%d variable(s)", len(want.Env)), len(want.Env) > 0))
	add("expose", prefixed("+", flatten(routeMap(want.AllExposes()))))
	add("publish", prefixed("+", flatten(publishMap(want.Publish))))
	add("depends_on", prefixed("+", want.DependsOn))
	add("check", oneLine(describeCheck(want.Check), want.Check != nil))
	add("scaling", oneLine(describeScaling(want.Scaling), want.Scaling != nil))
	add("function", oneLine(describeFunction(want.Function), want.Function != nil))
	return c
}

// update describes a service both sides have, field by field. The bool reports
// whether anything differs at all.
func update(have, want Desired) (ServiceChange, bool) {
	c := ServiceChange{
		Project: want.Project, Service: want.Service, Kind: ChangeUpdate,
		Count: want.Count, Image: want.RunImage(),
	}
	// scalar compares two rendered values and records the difference.
	scalar := func(field string, rolls bool, before, after string) {
		if before != after {
			c.Fields = append(c.Fields, FieldChange{
				Field: field, Rolls: rolls, Lines: []string{before + " -> " + after},
			})
		}
	}
	// keyed renders the additions, removals and edits of a resource family.
	keyed := func(field string, rolls bool, before, after map[string]string) {
		if lines := keyedDiff(before, after); len(lines) > 0 {
			c.Fields = append(c.Fields, FieldChange{Field: field, Rolls: rolls, Lines: lines})
		}
	}
	// set is keyed's degenerate case: a family of bare names with no detail.
	set := func(field string, rolls bool, before, after []string) {
		if lines := keyedDiff(names(before), names(after)); len(lines) > 0 {
			c.Fields = append(c.Fields, FieldChange{Field: field, Rolls: rolls, Lines: lines})
		}
	}

	// Rolling: SpecHash material. Editing any of these replaces the containers.
	scalar("image", true, have.Image, want.Image)
	scalar("runtime", true, describeRuntime(have.Runtime), describeRuntime(want.Runtime))
	scalar("command", true, describeCommand(have.Command), describeCommand(want.Command))
	scalar("capabilities", true,
		describeCapabilities(have.Capabilities), describeCapabilities(want.Capabilities))
	scalar("user", true, describeUser(have.User), describeUser(want.User))
	scalar("resources", true, describeResources(have.Resources), describeResources(want.Resources))
	scalar("read_only_rootfs", true, onOff(have.ReadOnlyRootfs), onOff(want.ReadOnlyRootfs))
	if lines := envDiff(have.Env, want.Env); len(lines) > 0 {
		c.Fields = append(c.Fields, FieldChange{Field: "env", Rolls: true, Lines: lines})
	}
	// A file's detail is derived from hashableFiles, so a renamed block or a
	// re-parsed nonce produces nothing and an edited byte produces a line.
	keyed("files", true, fileMap(have.Files), fileMap(want.Files))
	// Volumes are the one family whose rendered detail is wider than its hash
	// material: hashableVolumes strips SizeBytes and Resource.Create, so a
	// budget edit must appear *and* must not claim to roll a database.
	keyed("volumes",
		!reflect.DeepEqual(hashableVolumes(have.Volumes), hashableVolumes(want.Volumes)),
		volumeMap(have.Volumes), volumeMap(want.Volumes))
	keyed("ports", true, portMap(have.Ports), portMap(want.Ports))
	keyed("devices", true, deviceMap(have.Devices), deviceMap(want.Devices))
	keyed("sockets", true, socketMap(have.Sockets), socketMap(want.Sockets))
	// Init steps are ordered - the order *is* the semantics, unlike a volume or
	// a file - so the key carries the ordinal and reordering two steps reads as
	// two edits. Built from hashableInit, so adjusting a step's timeout or pull
	// policy, neither of which rolls anything, does not print here; the
	// non-rolling "init settings" line below reports that instead.
	keyed("init", true, initMap(have.Init), initMap(want.Init))

	// Non-rolling: applied to the running service, or republished to the edge.
	scalar("count", false, fmt.Sprint(have.Count), fmt.Sprint(want.Count))
	scalar("registry_auth", false,
		orDefault(have.RegistryAuthRef, "none"), orDefault(want.RegistryAuthRef, "none"))
	scalar("pull_policy", false,
		orDefault(have.PullPolicy, "node default"), orDefault(want.PullPolicy, "node default"))
	keyed("expose", false, routeMap(have.AllExposes()), routeMap(want.AllExposes()))
	keyed("publish", false, publishMap(have.Publish), publishMap(want.Publish))
	set("allow_from", false, describePeers(have.AllowFrom), describePeers(want.AllowFrom))
	set("depends_on", false, have.DependsOn, want.DependsOn)
	scalar("check", false, describeCheck(have.Check), describeCheck(want.Check))
	scalar("scaling", false, describeScaling(have.Scaling), describeScaling(want.Scaling))
	scalar("restart", false, describeRestart(have.Restart), describeRestart(want.Restart))
	scalar("update", false, describeUpdate(have.Update), describeUpdate(want.Update))
	scalar("function", false, describeFunction(have.Function), describeFunction(want.Function))
	// The step detail hashableInit strips: worth reporting, and worth reporting
	// as something that does *not* roll, which is the whole point of the flag.
	scalar("init settings", false, describeInitSettings(have.Init), describeInitSettings(want.Init))

	if len(c.Fields) == 0 {
		return ServiceChange{}, false
	}
	c.Rolls = rollsAny(c.Fields)
	return c, true
}

// destructions renders what a prune-scoped apply would remove: a stored service
// in a project the spec owns that the spec no longer declares.
//
// A destroy line shown where no prune will happen would be worse than no line
// at all: the reader has no way to tell a warning from a plan.
func destructions(current, desired []Desired, pruneProjects []string) []ServiceChange {
	if len(pruneProjects) == 0 {
		return nil
	}
	scope := make(map[string]struct{}, len(pruneProjects))
	for _, p := range pruneProjects {
		scope[p] = struct{}{}
	}
	declared := make(map[string]struct{}, len(desired))
	for _, want := range desired {
		declared[want.Project+"/"+want.Service] = struct{}{}
	}

	var out []ServiceChange
	for _, have := range current {
		if _, ours := scope[have.Project]; !ours {
			continue
		}
		if _, kept := declared[have.Project+"/"+have.Service]; kept {
			continue
		}
		c := ServiceChange{
			Project: have.Project, Service: have.Service, Kind: ChangeDestroy,
			Count: have.Count, Image: have.RunImage(),
		}
		drop := func(field string, lines []string) {
			if len(lines) > 0 {
				c.Fields = append(c.Fields, FieldChange{Field: field, Lines: prefixed("-", lines)})
			}
		}
		drop("expose", flatten(routeMap(have.AllExposes())))
		drop("publish", flatten(publishMap(have.Publish)))
		// Said on every destroy, because it is the reason a mistaken prune is
		// survivable and the reason a deliberate one frees no disk.
		if lines := flatten(volumeMap(have.Volumes)); len(lines) > 0 {
			c.Fields = append(c.Fields, FieldChange{
				Field: "volumes",
				Lines: append(prefixed("-", lines), "  (the mount goes; the volume's data is NOT deleted)"),
			})
		}
		out = append(out, c)
	}
	return out
}

// rollsAny reports whether any field of a change replaces running containers.
//
// The verdict is the OR of the fields actually compared, and deliberately NOT
// SpecHash(have) != SpecHash(want). Generation and PinnedImage are hash material
// *and* server-owned: applyServices carries both over from the stored record,
// while a client's desired state has them zeroed, so a hash comparison here
// would call every restarted or auto-updating service a roll on every plan.
// TestEveryHashedFieldRollsAndNothingElseDoes pins the two lists together.
func rollsAny(fields []FieldChange) bool {
	for _, f := range fields {
		if f.Rolls {
			return true
		}
	}
	return false
}

// RenderChanges turns a change set into the lines a terminal prints: a header
// per service, then one indented row per field.
func RenderChanges(changes []ServiceChange) []string {
	const (
		indent = "    "
		// Wide enough for the longest field name ("read_only_rootfs"), so the
		// detail column starts in the same place for every service.
		label = 18
	)
	var out []string
	for i, c := range changes {
		if i > 0 {
			out = append(out, "")
		}
		switch c.Kind {
		case ChangeCreate:
			out = append(out, fmt.Sprintf("+ create %s (count %d, image %s)", c.Key(), c.Count, c.Image))
		case ChangeDestroy:
			out = append(out, fmt.Sprintf("- destroy %s (count %d, image %s)", c.Key(), c.Count, c.Image))
		case ChangeUpdate:
			out = append(out, fmt.Sprintf("~ update %s", c.Key()))
		}
		for _, f := range c.Fields {
			for j, line := range f.Lines {
				name := ""
				if j == 0 {
					name = f.Field
				}
				row := indent + fmt.Sprintf("%-*s", label, name) + line
				// The marker rides the field's first line, so a reader asking
				// "why is this rolling?" gets the answer beside the cause.
				if j == 0 && f.Rolls {
					row += "  (rolls allocs)"
				}
				out = append(out, row)
			}
		}
	}
	return out
}

// Diff renders a create/change summary between what is declared now and what a
// spec would declare. It is RenderChanges over Changes; the structured form is
// what carries the change *count*, since one service is now several lines.
func Diff(current, desired []Desired) []string {
	return DiffScoped(current, desired, nil)
}

// DiffScoped is Diff with a prune scope (see Changes).
func DiffScoped(current, desired []Desired, pruneProjects []string) []string {
	return RenderChanges(Changes(current, desired, pruneProjects))
}

// keyedDiff renders the additions, removals and edits of one resource family.
//
// Keyed rather than a plain set difference because a resource has an identity a
// spec author recognises - a volume's name, a file's path, a listener's host
// port - and an edit reported as an unrelated removal beside an unrelated
// addition is exactly the output this feature exists to stop producing.
func keyedDiff(before, after map[string]string) []string {
	keys := make([]string, 0, len(before)+len(after))
	for k := range before {
		keys = append(keys, k)
	}
	for k := range after {
		if _, both := before[k]; !both {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var out []string
	for _, k := range keys {
		b, hadBefore := before[k]
		a, hadAfter := after[k]
		switch {
		case !hadBefore:
			out = append(out, "+ "+join(k, a))
		case !hadAfter:
			out = append(out, "- "+join(k, b))
		case b != a:
			out = append(out, "~ "+k+"  "+b+" -> "+a)
		}
	}
	return out
}

// flatten renders a whole family, for a create or a destroy where every member
// is arriving or going and there is nothing to compare it against.
func flatten(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, join(k, v))
	}
	sort.Strings(out)
	return out
}

// names turns a family that is only names into the keyed form.
func names(list []string) map[string]string {
	m := make(map[string]string, len(list))
	for _, s := range list {
		m[s] = ""
	}
	return m
}

func join(key, detail string) string {
	if detail == "" {
		return key
	}
	return key + "  " + detail
}

// prefixed marks every line of a list, for a create or a destroy where the
// whole set is arriving or going.
func prefixed(sign string, lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, sign+" "+l)
	}
	return out
}

// oneLine wraps a single rendered value, or nothing when there is nothing to say.
func oneLine(s string, present bool) []string {
	if !present {
		return nil
	}
	return []string{s}
}

// envDiff names the environment keys that were added, changed and removed.
//
// Keys only, never values: an env value may be a `secret-env:` reference whose
// resolved form is a credential (constraint #4), and a plan is printed to a
// terminal and pasted into issues. The count of what changed is the useful
// part anyway; the value is in the file the operator is holding.
func envDiff(have, want map[string]string) []string {
	var added, changed, removed []string
	for k, v := range want {
		old, ok := have[k]
		switch {
		case !ok:
			added = append(added, "+ "+k)
		case old != v:
			changed = append(changed, "~ "+k)
		}
	}
	for k := range have {
		if _, ok := want[k]; !ok {
			removed = append(removed, "- "+k)
		}
	}
	sort.Strings(added)
	sort.Strings(changed)
	sort.Strings(removed)
	all := append(append(added, changed...), removed...)
	if len(all) == 0 {
		return nil
	}
	// Wrapped rather than truncated: a plan that hides half the change is the
	// problem this whole feature exists to fix.
	return wrap(all, 6)
}

// wrap groups short items into lines of at most n, joined with commas.
func wrap(items []string, n int) []string {
	var out []string
	for i := 0; i < len(items); i += n {
		end := min(i+n, len(items))
		out = append(out, strings.Join(items[i:end], ", "))
	}
	return out
}

// describeVolumes renders one line per volume: what it is, where it mounts, and
// the budget, which is reported *and* correctly non-rolling (hashableVolumes
// strips SizeBytes from the material, so declaring one must not roll a database).
func volumeMap(vols []Volume) map[string]string {
	out := make(map[string]string, len(vols))
	for _, v := range vols {
		kind := v.Resource.Type
		if kind == "" {
			kind = "local"
		}
		if v.Storage != "" {
			kind += ":" + v.Storage
		}
		parts := []string{kind, v.MountPath, rwRO(v.ReadOnly)}
		if v.Owned() {
			parts = append(parts, "owner "+describeOwner(v))
		}
		if v.SizeBytes > 0 {
			parts = append(parts, mebibytes(uint64(v.SizeBytes))+" budget")
		}
		if v.Resource.Create {
			parts = append(parts, "create")
		}
		out[v.Name] = strings.Join(parts, " ")
	}
	return out
}

// describeOwner renders a volume's ownership. An undeclared half is chown(2)'s
// -1, not zero, so it renders as a dash rather than as root.
func describeOwner(v Volume) string {
	half := func(p *uint32) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprint(*p)
	}
	s := half(v.UID) + ":" + half(v.GID)
	if v.Mode != nil {
		s += fmt.Sprintf(" mode %04o", *v.Mode)
	}
	return s
}

// describeFiles renders one line per config file. Never the content: it carries
// secret placeholders (R35) and is bytes nobody wants in a terminal. The block's
// Name is not rendered either, which is what makes a rename produce no change,
// matching hashableFiles clearing it.
func fileMap(files []FileMount) map[string]string {
	out := make(map[string]string, len(files))
	// Built from the canonical form, which is what makes a renamed block and a
	// re-parsed nonce produce nothing: hashableFiles clears Name and rewrites
	// the placeholders, and the same canonicalisation decides the hash.
	for _, f := range hashableFiles(files) {
		sum := sha256.Sum256(f.Content)
		parts := []string{
			fmt.Sprintf("%d B", len(f.Content)),
			"content " + hex.EncodeToString(sum[:4]),
		}
		if f.Mode != "" {
			parts = append(parts, "mode "+f.Mode)
		}
		if n := len(f.SecretRefs); n > 0 {
			parts = append(parts, fmt.Sprintf("%d secret ref(s)", n))
		}
		out[f.Path] = "(" + strings.Join(parts, ", ") + ")"
	}
	return out
}

// initMap renders a service's init sequence, one entry per step (R32).
//
// Keyed by ordinal *and* name because the order is the semantics: swapping two
// migrations is a different sequence, not the same set rearranged. Built from
// hashableInit so the two sub-fields that do not roll - a step's timeout and
// pull policy - are reported by describeInitSettings instead of here.
func initMap(inits []InitContainer) map[string]string {
	out := make(map[string]string, len(inits))
	for i, step := range hashableInit(inits) {
		parts := []string{step.Image}
		if len(step.Command) > 0 {
			parts = append(parts, describeCommand(step.Command))
		}
		if step.User != nil {
			parts = append(parts, "as "+describeUser(step.User))
		}
		if len(step.Capabilities) > 0 {
			parts = append(parts, describeCapabilities(step.Capabilities))
		}
		if n := len(step.Env); n > 0 {
			parts = append(parts, fmt.Sprintf("%d env var(s)", n))
		}
		if step.RegistryAuthRef != "" {
			parts = append(parts, "auth "+step.RegistryAuthRef)
		}
		out[fmt.Sprintf("%d. %s", i+1, step.Name)] = strings.Join(parts, " ")
	}
	return out
}

// describePorts renders declared container ports.
func portMap(ports []Port) map[string]string {
	out := make(map[string]string, len(ports))
	for _, p := range ports {
		detail := fmt.Sprint(p.Container)
		if p.IsUDP() {
			detail += "/udp"
		}
		out[p.Name] = detail
	}
	return out
}

// describePublishedPorts renders node ports, one per listener.
func publishMap(ports []PublishedPort) map[string]string {
	out := make(map[string]string, len(ports))
	for _, p := range ports {
		mode := orDefault(p.Mode, "http")
		// Keyed by the listener, which is what a node port collision is about:
		// one host port may carry one http/tcp listener and one udp listener.
		detail := "port " + p.Port
		if extra := middleware(p.IPRestriction != nil, p.RateLimit != nil, p.Headers != nil,
			p.MaxConns > 0); extra != "" {
			detail += " (" + extra + ")"
		}
		out[fmt.Sprintf("%d/%s", p.Host, mode)] = detail
	}
	return out
}

// describeRoutes renders one line per north-south route, read through
// AllExposes: reading Expose alone silently drops every route after the first.
func routeMap(routes []*Expose) map[string]string {
	out := make(map[string]string, len(routes))
	for _, e := range routes {
		name := strings.Join(e.Domains, ", ")
		if name == "" {
			// The auto-FQDN needs the node's base domain, which desired state
			// does not carry: naming a guess would be worse than naming none.
			name = "(auto FQDN under the node's base domain)"
		}
		attrs := []string{"tls " + describeTLSMode(e)}
		if e.Port > 0 {
			attrs = append(attrs, fmt.Sprintf("port %d", e.Port))
		}
		if e.Protocol != "" {
			attrs = append(attrs, e.Protocol)
		}
		if e.Auth != nil {
			attrs = append(attrs, "auth "+describeAuth(e.Auth))
		}
		if extra := middleware(e.IPRestriction != nil, e.RateLimit != nil, e.Headers != nil,
			false); extra != "" {
			attrs = append(attrs, extra)
		}
		out[name] = "(" + strings.Join(attrs, ", ") + ")"
	}
	return out
}

// describeTLSMode names where a route's certificate comes from. An empty mode
// is the node's decision (R20 resolves it there, not here), and the pre-v1.33
// LetsEncrypt bool still means acme.
func describeTLSMode(e *Expose) string {
	switch {
	case e.TLSMode != "":
		if e.TLSName != "" {
			return e.TLSMode + ":" + e.TLSName
		}
		return e.TLSMode
	case e.LetsEncrypt:
		return "acme"
	default:
		return "node default"
	}
}

// describeAuth names R27's mechanism. References only: nothing here is material.
func describeAuth(a *AuthPolicy) string {
	var kinds []string
	if a.BasicRef != "" {
		kinds = append(kinds, "basic")
	}
	if a.BearerRef != "" {
		kinds = append(kinds, "bearer")
	}
	if a.JWT != nil {
		kinds = append(kinds, "jwt "+a.JWT.Algorithm)
	}
	if len(kinds) == 0 {
		return "none"
	}
	return strings.Join(kinds, "+")
}

// middleware names the edge controls attached to a route or a listener.
func middleware(ip, rate, headers, conns bool) string {
	var on []string
	if ip {
		on = append(on, "ip_restriction")
	}
	if rate {
		on = append(on, "rate_limit")
	}
	if headers {
		on = append(on, "headers")
	}
	if conns {
		on = append(on, "max_conns")
	}
	return strings.Join(on, ", ")
}

// describeGrants renders passthrough grants by name. Never the resolved device
// node or socket path: which hardware a grant means is the node's fact (R17,
// R18), and desired state deliberately does not carry it.
func deviceMap(devices []DeviceRequest) map[string]string {
	out := make(map[string]string, len(devices))
	for _, d := range devices {
		out[d.Name] = "(grant " + d.Grant + ")"
	}
	return out
}

func socketMap(sockets []SocketRequest) map[string]string {
	out := make(map[string]string, len(sockets))
	for _, s := range sockets {
		out[s.Name] = fmt.Sprintf("(grant %s at %s, %s)", s.Grant, s.MountPath, rwRO(s.ReadOnly))
	}
	return out
}

// describePeers renders the network policy's allowed callers.
func describePeers(peers []PeerRef) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.Project+"/"+p.Service)
	}
	sort.Strings(out)
	return out
}

// describeResources renders R11's limits the way a spec declares them, and says
// "unbounded" where a zero means it: since v1.58 an omitted field is the node's
// capacity, and rendering that as 0 would read as "no CPU at all".
func describeResources(r runtime.Resources) string {
	cpu := "unbounded"
	if r.CPUMillis > 0 {
		cpu = fmt.Sprintf("%dm", r.CPUMillis)
	}
	mem := "unbounded"
	if r.MemoryBytes > 0 {
		mem = mebibytes(uint64(r.MemoryBytes))
	}
	pids := "unbounded"
	if r.PidsLimit > 0 {
		pids = fmt.Sprint(r.PidsLimit)
	}
	return fmt.Sprintf("cpu %s, memory %s, pids %s", cpu, mem, pids)
}

// describeUser renders the identity a workload runs as. Nil is the image's own
// USER, and reading it as 0:0 would silently report every workload as root.
func describeUser(u *runtime.User) string {
	if u == nil {
		return "the image's own USER"
	}
	s := fmt.Sprintf("%d:%d", u.UID, u.GID)
	if len(u.AdditionalGIDs) > 0 {
		extra := make([]string, 0, len(u.AdditionalGIDs))
		for _, g := range u.AdditionalGIDs {
			extra = append(extra, fmt.Sprint(g))
		}
		s += " +groups " + strings.Join(extra, ",")
	}
	return s
}

// describeCommand renders an entrypoint override.
func describeCommand(cmd []string) string {
	if len(cmd) == 0 {
		return "the image's own entrypoint"
	}
	return strings.Join(cmd, " ")
}

// describeCheck renders a health probe.
func describeCheck(c *HealthCheck) string {
	if c == nil || c.Type == "" {
		return "none"
	}
	var what string
	switch c.Type {
	case "http":
		what = fmt.Sprintf("http %s on port %d", orDefault(c.Path, "/"), c.Port)
	case "tcp":
		what = fmt.Sprintf("tcp on port %d", c.Port)
	default:
		what = c.Type + " " + strings.Join(c.Command, " ")
	}
	return fmt.Sprintf("%s every %s, timeout %s, %d failure(s)",
		what, c.interval(), c.timeout(), c.failureThreshold())
}

// describeScaling renders an autoscaling policy.
func describeScaling(s *ScalingPolicy) string {
	if s == nil {
		return "none"
	}
	metrics := make([]string, 0, len(s.Metrics))
	for _, m := range s.Metrics {
		metrics = append(metrics, fmt.Sprintf("%s %g", m.Name, m.Target))
	}
	if len(metrics) == 0 {
		// A policy with no metric can never fire, whatever min and max say.
		return fmt.Sprintf("min %d, max %d, no metrics (never fires)", s.Min, s.Max)
	}
	line := fmt.Sprintf("min %d, max %d, %s", s.Min, s.Max, strings.Join(metrics, ", "))
	if s.Cooldown != "" {
		line += ", cooldown " + s.Cooldown
	}
	return line
}

// describeRestart renders R29's crash-restart budget, resolving the defaults so
// a plan shows what will actually apply rather than a zero.
func describeRestart(p RestartPolicy) string {
	schedule := p.Backoff
	if len(schedule) == 0 {
		schedule = DefaultRestartBackoff
	}
	parts := make([]string, 0, len(schedule))
	for _, d := range schedule {
		parts = append(parts, d.String())
	}
	return fmt.Sprintf("%d attempt(s), backoff %s", p.attempts(), strings.Join(parts, ","))
}

// describeUpdate renders the rolling-deploy policy.
func describeUpdate(p UpdatePolicy) string {
	parts := []string{orDefault(p.Strategy, StrategyRolling)}
	if p.MaxParallel > 0 {
		parts = append(parts, fmt.Sprintf("max_parallel %d", p.MaxParallel))
	}
	if p.MinHealthy > 0 {
		parts = append(parts, "min_healthy "+p.MinHealthy.String())
	}
	if p.Auto {
		auto := "auto on"
		if p.Interval > 0 {
			auto += " every " + p.Interval.String()
		}
		if p.Deadline > 0 {
			auto += ", deadline " + p.Deadline.String()
		}
		parts = append(parts, auto)
	}
	return strings.Join(parts, ", ")
}

// describeFunction renders a lowered function's triggers (R26). Trigger config
// is deliberately not SpecHash material: nothing about a cron schedule is baked
// into a container, so changing an invocation time must not roll the alloc.
func describeFunction(f *FunctionMeta) string {
	if f == nil {
		return "none"
	}
	var parts []string
	if f.HTTP {
		parts = append(parts, "http")
	}
	for _, e := range f.Events {
		parts = append(parts, "on "+strings.Join(e.On, "|")+orPrefixed(" -> ", e.Path))
	}
	for _, c := range f.Crons {
		parts = append(parts, "cron "+c.Schedule+orPrefixed(" -> ", c.Path))
	}
	if f.SigningRef != "" {
		parts = append(parts, "signed by "+f.SigningRef)
	}
	if len(parts) == 0 {
		return "no triggers"
	}
	return strings.Join(parts, ", ")
}

// describeInitSettings renders the per-step detail hashableInit strips, so a
// timeout or pull-policy edit is visible *and* visibly non-rolling.
func describeInitSettings(inits []InitContainer) string {
	parts := make([]string, 0, len(inits))
	for _, i := range inits {
		detail := []string{}
		if i.Timeout > 0 {
			detail = append(detail, "timeout "+i.Timeout.String())
		}
		if i.PullPolicy != "" {
			detail = append(detail, "pull "+i.PullPolicy)
		}
		if len(detail) > 0 {
			parts = append(parts, i.Name+" ("+strings.Join(detail, ", ")+")")
		}
	}
	if len(parts) == 0 {
		return "defaults"
	}
	return strings.Join(parts, ", ")
}

// describeRuntime names a runtime for a plan line; the empty default reads as
// what it is rather than as a blank.
func describeRuntime(r string) string { return orDefault(r, "default") }

func rwRO(readOnly bool) string {
	if readOnly {
		return "ro"
	}
	return "rw"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func orPrefixed(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

// ChangeCounts is a change set reduced to the numbers a one-line verdict needs.
type ChangeCounts struct {
	Create  int
	Update  int
	Destroy int
	// Rolling is how many services would have their running containers
	// replaced. A create is never counted: it has none to replace.
	Rolling int
}

// CountChanges summarises a change set.
func CountChanges(changes []ServiceChange) ChangeCounts {
	var n ChangeCounts
	for _, c := range changes {
		switch c.Kind {
		case ChangeCreate:
			n.Create++
		case ChangeUpdate:
			n.Update++
		case ChangeDestroy:
			n.Destroy++
		}
		if c.Rolls {
			n.Rolling++
		}
	}
	return n
}
