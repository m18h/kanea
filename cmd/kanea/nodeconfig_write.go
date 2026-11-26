package main

import (
	"bytes"

	"github.com/zclconf/go-cty/cty"

	"github.com/m18h/kanea/internal/nodeconfig"
	"github.com/m18h/kanea/internal/provision"
)

// nodeConfigWrite is what `kanea init` settled, on its way into the node
// config (PRD §15.1, v1.115). The string fields are effective values: the
// flag where one was passed, the file's own otherwise.
type nodeConfigWrite struct {
	path string
	// source is the file as it was read; nil when there was none.
	source []byte
	// explicit is the set of flags the operator typed.
	explicit map[string]bool

	dataDir, logDir       string
	nodeCIDR, clusterCIDR string

	nodeCIDR6, clusterCIDR6, serviceCIDR6 string

	// listener is init's decision about the API/dashboard listener, or nil
	// when the file's own bind stanza owns it and must be left as written.
	listener *listenDecision
}

// writeNodeConfig records init's decisions in kanea.hcl, editing the file
// that is there rather than replacing it: comments, ordering and every
// setting init knows nothing about survive.
//
// Three rules decide what is written:
//
//   - A flag that was typed is written, always.
//   - The settings the unit's ExecStart used to pin (the directories and
//     the two subnets) are written on a fresh node even
//     when defaulted. A node's subnets are part of its identity: with them
//     in the file, a release that changed a default could not renumber a
//     running node.
//   - Everything else is left out, so it keeps tracking its default.
//
// A run that changes nothing writes nothing.
func writeNodeConfig(o *out, w nodeConfigWrite) error {
	edit, err := nodeconfig.NewEditor(w.path, w.source)
	if err != nil {
		return err
	}
	// The comparison baseline is the file as the editor renders it untouched,
	// so a file that is merely formatted differently is not "changed".
	before := edit.Bytes()

	for _, pin := range []struct {
		flag  string
		value string
		path  []string
	}{
		{"data-dir", w.dataDir, []string{"data_dir"}},
		{"log-dir", w.logDir, []string{"alloc_log_dir"}},
		{"node-cidr", w.nodeCIDR, []string{"network", "node_cidr"}},
		{"cluster-cidr", w.clusterCIDR, []string{"network", "cluster_cidr"}},
	} {
		if w.explicit[pin.flag] || !edit.Has(pin.path...) {
			edit.Set(cty.StringVal(pin.value), pin.path...)
		}
	}
	// The dual-stack trio has no default to pin: written when asked for,
	// never as an empty string.
	for _, v6 := range []struct {
		flag  string
		value string
		attr  string
	}{
		{"node-cidr6", w.nodeCIDR6, "node_cidr6"},
		{"cluster-cidr6", w.clusterCIDR6, "cluster_cidr6"},
		{"service-cidr6", w.serviceCIDR6, "service_cidr6"},
	} {
		if w.explicit[v6.flag] && v6.value != "" {
			edit.Set(cty.StringVal(v6.value), "network", v6.attr)
		}
	}
	// The certificate bundle is group-readable by the edge's own account
	// (PRD §5.2.6). The unit used to pass this; a node without it publishes
	// a bundle the edge cannot open.
	if !edit.Has("edge", "certs_group") {
		edit.Set(cty.StringVal(provision.EdgeUser), "edge", "certs_group")
	}

	if w.listener != nil {
		// The API half of bind is one declaration: replaced whole, so an old
		// api_tls cannot outlive the address it described.
		for _, attr := range []string{"api_addr", "api_tls", "api_domain", "api_cert", "api_key"} {
			edit.Unset("bind", attr)
		}
		if w.listener.addr != "" {
			edit.Set(cty.StringVal(w.listener.addr), "bind", "api_addr")
			if w.listener.cert != "" {
				edit.Set(cty.StringVal(w.listener.cert), "bind", "api_cert")
				edit.Set(cty.StringVal(w.listener.key), "bind", "api_key")
			}
		}
	}

	after := edit.Bytes()
	if bytes.Equal(before, after) {
		return nil
	}
	if err := nodeconfig.WriteFile(w.path, after); err != nil {
		return err
	}
	o.printf("Wrote %s\n", w.path)
	return o.Err()
}
