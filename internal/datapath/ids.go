package datapath

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/m18h/kanea/internal/network"
	"github.com/m18h/kanea/internal/store"
)

// IDStore is the slice of the state store id allocation needs; the same
// consumer-side shape reconciler.Store has, for the same reason: the
// dependency stays honest and a test substitutes a map.
type IDStore interface {
	Get(ctx context.Context, kind store.Kind, key string) (store.Record, error)
	List(ctx context.Context, kind store.Kind, opts store.ListOptions) (store.Page, error)
	Apply(ctx context.Context, muts ...store.Mutation) (uint64, error)
}

// KV keys for the numeric id space. One monotonic sequence covers all three
// namespaces, so no id is ever minted twice: a reused id would make a pinned
// map lie after a restart (AGENTS.md, PRD v1.36).
const (
	idSeqKey         = "net/id/seq"
	idProjectPrefix  = "net/id/project/"
	idServicePrefix  = "net/id/service/"
	idFrontendPrefix = "net/id/frontend/"
)

// idAllocator hands out Store-backed monotonic numeric ids.
//
// Three namespaces share the sequence: project ids and service ids (uint32,
// what identity_v4 and allow_v4 speak) and frontend ids (uint16, what svc_v4
// and svc_backends speak; one per service *port*, because svc_backends keys
// entries by (svc_id, index, gen) and two ports of one service have different
// target ports, so sharing an id would collide their backend sets).
//
// Mappings are never deleted: "never reused" is cheaper to guarantee by
// keeping them than by tombstoning them, and the space is 32 bits wide.
type idAllocator struct {
	store IDStore

	mu     sync.Mutex
	loaded bool
	seq    uint32
	byKey  map[string]uint32 // full KV key -> id
	// Reverse maps, for Attachments and CounterSource.
	serviceNames  map[uint32]network.ServiceRef // service id -> project/service
	frontendNames map[uint16]network.ServiceRef // frontend id -> project/service
}

func newIDAllocator(st IDStore) *idAllocator {
	return &idAllocator{
		store:         st,
		byKey:         map[string]uint32{},
		serviceNames:  map[uint32]network.ServiceRef{},
		frontendNames: map[uint16]network.ServiceRef{},
	}
}

// ProjectID returns the project's numeric id, minting one if needed.
func (a *idAllocator) ProjectID(ctx context.Context, project string) (uint32, error) {
	return a.idFor(ctx, idProjectPrefix+project)
}

// ServiceID returns the service's numeric identity id, minting one if needed.
func (a *idAllocator) ServiceID(ctx context.Context, project, service string) (uint32, error) {
	return a.idFor(ctx, idServicePrefix+project+"/"+service)
}

// FrontendID returns the numeric id for one service port frontend, minting one
// if needed. svc_val.svc_id is a __u16, so the shared sequence running past
// 65535 makes new frontends unrepresentable: an error, not a wrap.
func (a *idAllocator) FrontendID(ctx context.Context, project, service, port string) (uint16, error) {
	id, err := a.idFor(ctx, idFrontendPrefix+project+"/"+service+"/"+port)
	if err != nil {
		return 0, err
	}
	if id > math.MaxUint16 {
		return 0, fmt.Errorf("datapath: frontend id %d for %s/%s port %q exceeds the datapath's 16-bit id space",
			id, project, service, port)
	}
	return uint16(id), nil
}

// ServiceName resolves a service id back to its name.
func (a *idAllocator) ServiceName(ctx context.Context, id uint32) (network.ServiceRef, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.load(ctx); err != nil {
		return network.ServiceRef{}, false, err
	}
	ref, ok := a.serviceNames[id]
	return ref, ok, nil
}

// FrontendService resolves a frontend id back to the service it belongs to.
// Ports fold into their service: the metrics consumer counts per service.
func (a *idAllocator) FrontendService(ctx context.Context, id uint16) (network.ServiceRef, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.load(ctx); err != nil {
		return network.ServiceRef{}, false, err
	}
	ref, ok := a.frontendNames[id]
	return ref, ok, nil
}

// idFor returns the id stored under key, minting the next sequence value when
// there is none. The sequence bump and the mapping commit in one Apply, so a
// crash between them cannot mint the same id twice.
func (a *idAllocator) idFor(ctx context.Context, key string) (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.load(ctx); err != nil {
		return 0, err
	}
	if id, ok := a.byKey[key]; ok {
		return id, nil
	}
	if a.seq == math.MaxUint32 {
		return 0, fmt.Errorf("datapath: numeric id space exhausted")
	}
	next := a.seq + 1

	seqMut, err := store.PutMutation(store.KindKV, idSeqKey, next)
	if err != nil {
		return 0, err
	}
	idMut, err := store.PutMutation(store.KindKV, key, next)
	if err != nil {
		return 0, err
	}
	if _, err := a.store.Apply(ctx, seqMut, idMut); err != nil {
		return 0, fmt.Errorf("datapath: persist id for %s: %w", key, err)
	}

	a.seq = next
	a.record(key, next)
	return next, nil
}

// load reads the whole id space once. Ids are append-only, so the cache never
// goes stale within a process: everything new goes through idFor.
func (a *idAllocator) load(ctx context.Context) error {
	if a.loaded {
		return nil
	}
	opts := store.ListOptions{Prefix: "net/id/"}
	for {
		page, err := a.store.List(ctx, store.KindKV, opts)
		if err != nil {
			return fmt.Errorf("datapath: load ids: %w", err)
		}
		for _, rec := range page.Records {
			var v uint32
			if err := json.Unmarshal(rec.Value, &v); err != nil {
				return fmt.Errorf("datapath: decode id %s: %w", rec.Key, err)
			}
			if rec.Key == idSeqKey {
				a.seq = v
				continue
			}
			a.record(rec.Key, v)
		}
		if !page.More {
			break
		}
		opts.After = page.NextAfter
	}
	a.loaded = true
	return nil
}

// record caches one mapping and its reverse.
func (a *idAllocator) record(key string, id uint32) {
	a.byKey[key] = id
	switch {
	case strings.HasPrefix(key, idServicePrefix):
		if ref, ok := refFrom(strings.TrimPrefix(key, idServicePrefix), 2); ok {
			a.serviceNames[id] = ref
		}
	case strings.HasPrefix(key, idFrontendPrefix):
		if ref, ok := refFrom(strings.TrimPrefix(key, idFrontendPrefix), 3); ok && id <= math.MaxUint16 {
			a.frontendNames[uint16(id)] = ref
		}
	}
}

// refFrom parses "project/service[/port]" with the expected number of parts.
func refFrom(s string, parts int) (network.ServiceRef, bool) {
	fields := strings.Split(s, "/")
	if len(fields) != parts || fields[0] == "" || fields[1] == "" {
		return network.ServiceRef{}, false
	}
	return network.ServiceRef{Project: fields[0], Service: fields[1]}, true
}
