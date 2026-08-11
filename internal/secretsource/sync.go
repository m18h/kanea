package secretsource

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/m18h/kanea/internal/secrets"
)

// The pass (§5.2.13). Per value: resolve the current local record, compare in
// memory, and write only on a difference — an unchanged value producing a
// Store write per poll would be CDC/S3 write amplification, which is the one
// way this feature could violate the spirit of constraint #2. A stored
// plaintext hash was rejected for the comparison: beside the ciphertext it is
// an offline dictionary oracle against a stolen state.db.

// providerTimeout bounds one provider's whole pass; the HTTP client's own
// timeout bounds each dial underneath it.
const providerTimeout = 30 * time.Second

// Target is the slice of the secrets store the sync writes through.
// Consumer-defined, satisfied by *secrets.Store.
type Target interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
	PutManaged(ctx context.Context, path string, value []byte, source string) error
	Describe(ctx context.Context, ref string) (secrets.Info, error)
}

// ProviderSet hands out the current providers — *Providers in the daemon,
// a fixture in tests.
type ProviderSet interface {
	Current() []Provider
}

// SyncerConfig configures a Syncer.
type SyncerConfig struct {
	Providers ProviderSet
	Target    Target
	Logger    *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
}

// Syncer runs passes and remembers what happened for the status surface.
type Syncer struct {
	providers ProviderSet
	target    Target
	log       *slog.Logger
	now       func() time.Time

	mu sync.Mutex
	// status is keyed "<kind>/<name>", ordered by first appearance.
	status map[string]*ProviderStatus
	order  []string
	// reasserted marks paths already warned about a manual overwrite, so a
	// mapping nobody removes is one line, not one per pass.
	reasserted map[string]bool
}

// NewSyncer builds a Syncer.
func NewSyncer(cfg SyncerConfig) *Syncer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Syncer{
		providers: cfg.Providers, target: cfg.Target, log: cfg.Logger, now: cfg.Now,
		status: make(map[string]*ProviderStatus), reasserted: make(map[string]bool),
	}
}

// ProviderPass is what one provider did in one pass, for events and logs.
type ProviderPass struct {
	Kind Kind
	Name string
	// Changed lists the local paths this pass actually wrote.
	Changed []string
	// Unchanged counts values fetched and found identical.
	Unchanged int
	Failures  []Failure
	// applied is every success with its external ref, for the status surface.
	applied []appliedMapping
}

type appliedMapping struct{ to, ref string }

// Failed reports whether anything in the pass went wrong.
func (p ProviderPass) Failed() bool { return len(p.Failures) > 0 }

// PassResult is one whole pass over every provider.
type PassResult struct {
	PerProvider []ProviderPass
}

// Failed reports whether any provider had any failure.
func (r PassResult) Failed() bool {
	for _, p := range r.PerProvider {
		if p.Failed() {
			return true
		}
	}
	return false
}

// MappingStatus is one mapping's last known state — metadata only, the API's
// view.
type MappingStatus struct {
	To         string    `json:"to"`
	Ref        string    `json:"ref"`
	LastSynced time.Time `json:"last_synced,omitzero"`
	Error      string    `json:"error,omitempty"`
}

// ProviderStatus is one provider's last known state.
type ProviderStatus struct {
	Kind        Kind            `json:"kind"`
	Name        string          `json:"name"`
	Mappings    int             `json:"mappings"`
	LastAttempt time.Time       `json:"last_attempt,omitzero"`
	LastSuccess time.Time       `json:"last_success,omitzero"`
	Entries     []MappingStatus `json:"entries,omitempty"`
}

// SyncOnce runs one pass over every provider. A provider failing entirely
// records its failures and the loop moves to the next — one broken endpoint
// must not stop the others (the certificate sources' isolation rule).
func (s *Syncer) SyncOnce(ctx context.Context) PassResult {
	var result PassResult
	for _, prov := range s.providers.Current() {
		pctx, cancel := context.WithTimeout(ctx, providerTimeout)
		pass := s.syncProvider(pctx, prov)
		cancel()
		result.PerProvider = append(result.PerProvider, pass)
		s.record(prov, pass)
	}
	return result
}

func (s *Syncer) syncProvider(ctx context.Context, prov Provider) ProviderPass {
	pass := ProviderPass{Kind: prov.Kind(), Name: prov.Name()}
	res := prov.Fetch(ctx)
	pass.Failures = append(pass.Failures, res.Failures...)

	source := string(prov.Kind()) + "/" + prov.Name()
	for _, v := range res.Values {
		changed, err := s.apply(ctx, v, source)
		if err != nil {
			pass.Failures = append(pass.Failures, Failure{To: v.To, Ref: v.Ref, Err: err})
			continue
		}
		pass.applied = append(pass.applied, appliedMapping{to: v.To, ref: v.Ref})
		if changed {
			pass.Changed = append(pass.Changed, v.To)
		} else {
			pass.Unchanged++
		}
	}
	return pass
}

// apply writes one fetched value if it differs from what is stored.
func (s *Syncer) apply(ctx context.Context, v Value, source string) (changed bool, err error) {
	current, err := s.target.Resolve(ctx, v.To)
	switch {
	case err == nil:
		if bytes.Equal(current, v.Data) {
			// Steady state: no write, so CDC replication stays quiet.
			s.clearReasserted(v.To)
			return false, nil
		}
		s.warnIfReasserting(ctx, v.To, source)
	case errors.Is(err, secrets.ErrNotFound):
		// First sync of this mapping.
	case errors.Is(err, secrets.ErrUndecryptable):
		// A record under a dead master key. A fresh external value is the one
		// legitimate repair, and this is the only writer positioned to make it.
		s.log.Warn("replacing an undecryptable secret with the provider's value",
			"path", v.To, "source", source)
	default:
		return false, err
	}

	if err := s.target.PutManaged(ctx, v.To, v.Data, source); err != nil {
		return false, err
	}
	return true, nil
}

// warnIfReasserting logs — once per path — when the sync overwrites a value
// an operator put by hand. The mapping is declarative intent and always wins;
// what the operator needs is to be told which knob actually controls the path.
func (s *Syncer) warnIfReasserting(ctx context.Context, path, source string) {
	info, err := s.target.Describe(ctx, path)
	if err != nil || info.Source != "" {
		// A stamped record is ordinary rotation, not a contested write.
		return
	}
	s.mu.Lock()
	warned := s.reasserted[path]
	s.reasserted[path] = true
	s.mu.Unlock()
	if !warned {
		s.log.Warn("a manually written secret was reasserted by its sync mapping",
			"path", path, "source", source,
			"detail", "remove the sync mapping from the provider config if manual control is wanted")
	}
}

func (s *Syncer) clearReasserted(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.reasserted, path)
}

// record folds one provider's pass into the status the API serves. Entries
// are rebuilt from the pass — a mapping removed from the config disappears
// from status (the local secret does not, §5.2.13) — and a failing mapping
// keeps its previous last-synced time, because "when did this last work" is
// the question the status answers.
func (s *Syncer) record(prov Provider, pass ProviderPass) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := string(prov.Kind()) + "/" + prov.Name()
	st, ok := s.status[key]
	if !ok {
		st = &ProviderStatus{Kind: prov.Kind(), Name: prov.Name()}
		s.status[key] = st
		s.order = append(s.order, key)
	}

	now := s.now()
	st.LastAttempt = now
	if !pass.Failed() {
		st.LastSuccess = now
	}

	prevSynced := make(map[string]time.Time, len(st.Entries))
	for _, e := range st.Entries {
		prevSynced[e.To] = e.LastSynced
	}

	entries := make([]MappingStatus, 0, len(pass.applied)+len(pass.Failures))
	for _, a := range pass.applied {
		// An unchanged value is also a successful sync: without stamping it,
		// a stable secret would read as never having synced since it last
		// changed.
		entries = append(entries, MappingStatus{To: a.to, Ref: a.ref, LastSynced: now})
	}
	for _, f := range pass.Failures {
		entries = append(entries, MappingStatus{
			To: f.To, Ref: f.Ref, LastSynced: prevSynced[f.To], Error: f.Err.Error(),
		})
	}
	st.Entries = entries
	st.Mappings = len(entries)
}

// Status is the metadata-only view the API serves: paths, refs, timestamps
// and error strings — never values, structurally (nothing here holds one).
func (s *Syncer) Status() []ProviderStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ProviderStatus, 0, len(s.order))
	for _, key := range s.order {
		st := *s.status[key]
		st.Entries = append([]MappingStatus(nil), s.status[key].Entries...)
		out = append(out, st)
	}
	return out
}
