package registry

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
)

// The /v2/ handler: the subset containerd's remotes/docker code emits, which
// is both clients (buildkitd vendors it for the push, kanead uses it for the
// pull). Everything else answers UNSUPPORTED, stated rather than
// half-implemented.

// refusals counts what the registry said no to. A cap nobody can see is
// indistinguishable from a leak (the attacker-chosen-keys rule), so every
// refusal class is counted and visible to tests and logs.
type refusals struct {
	auth    atomic.Int64
	name    atomic.Int64
	digest  atomic.Int64
	bounds  atomic.Int64
	unknown atomic.Int64
}

// Refusals reports the refusal counts: writes refused for credentials, names
// refused by shape or by the pipeline bound, digest mismatches, bound caps
// hit, and requests for the unimplemented remainder of the protocol.
func (r *Registry) Refusals() (auth, name, digest, bounds, unknown int64) {
	return r.refusals.auth.Load(), r.refusals.name.Load(),
		r.refusals.digest.Load(), r.refusals.bounds.Load(), r.refusals.unknown.Load()
}

// ociError is the distribution error body.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, err := json.Marshal(map[string]any{
		"errors": []map[string]string{{"code": code, "message": message}},
	})
	if err != nil {
		return
	}
	_, _ = w.Write(body) //nolint:errcheck // the client hanging up on its own error is its business
}

// handler builds the mux.
func (r *Registry) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/{$}", r.ping)
	mux.HandleFunc("GET /v2/{project}/{service}/blobs/uploads/{id}", r.statUpload)
	mux.HandleFunc("GET /v2/{project}/{service}/blobs/{digest}", r.getBlob)
	mux.HandleFunc("POST /v2/{project}/{service}/blobs/uploads/{$}", r.auth(r.startUpload))
	mux.HandleFunc("PATCH /v2/{project}/{service}/blobs/uploads/{id}", r.auth(r.patchUpload))
	mux.HandleFunc("PUT /v2/{project}/{service}/blobs/uploads/{id}", r.auth(r.putUpload))
	mux.HandleFunc("GET /v2/{project}/{service}/manifests/{ref}", r.getManifest)
	mux.HandleFunc("PUT /v2/{project}/{service}/manifests/{ref}", r.auth(r.putManifest))
	mux.HandleFunc("/", r.unsupported)
	return mux
}

func (r *Registry) ping(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}")) //nolint:errcheck // a ping the client abandoned
}

func (r *Registry) unsupported(w http.ResponseWriter, req *http.Request) {
	r.refusals.unknown.Add(1)
	r.log.Debug("registry refused an unsupported request",
		"method", req.Method, "path", req.URL.Path)
	writeError(w, http.StatusNotFound, "UNSUPPORTED",
		"this registry serves only what a BuildKit push and a containerd pull use")
}

// auth gates every write behind the per-boot credential.
//
// Basic with constant-time comparison: containerd's authorizer (inside
// buildkitd) answers a Basic challenge from the materialised config.json, so
// no token service needs to exist. Reads are anonymous by design; the
// residual (a host-networked RUN step can read images) is stated in the
// threat model.
func (r *Registry) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		user, pass, ok := req.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(pushUser)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(r.password)) == 1
		if !ok || !userOK || !passOK {
			r.refusals.auth.Add(1)
			r.log.Debug("registry refused a write without the push credential",
				"method", req.Method, "path", req.URL.Path)
			w.Header().Set("WWW-Authenticate", `Basic realm="kanea-internal-registry"`)
			writeError(w, http.StatusUnauthorized, "DENIED",
				"writes require this node's per-boot push credential")
			return
		}
		next(w, req)
	}
}

// repo validates the repository path segments and, for writes, the pipeline
// bound: a pushed repository must be a declared <project>/<service> pipeline.
func (r *Registry) repo(w http.ResponseWriter, req *http.Request, write bool) (string, string, bool) {
	project, service := req.PathValue("project"), req.PathValue("service")
	if !validLabel(project) || !validLabel(service) {
		r.refusals.name.Add(1)
		writeError(w, http.StatusBadRequest, "NAME_INVALID",
			"a repository is <project>/<service>, both DNS-1123 labels")
		return "", "", false
	}
	if write {
		if r.allowed == nil || !r.allowed(req.Context(), project, service) {
			r.refusals.name.Add(1)
			r.log.Debug("registry refused a push to an undeclared repository",
				"project", project, "service", service)
			writeError(w, http.StatusForbidden, "DENIED",
				fmt.Sprintf("%s/%s is not a declared build pipeline on this node", project, service))
			return "", "", false
		}
	}
	return project, service, true
}

// pathDigest validates the {digest} path segment.
func (r *Registry) pathDigest(w http.ResponseWriter, raw string) (string, bool) {
	if !validDigest(raw) {
		r.refusals.digest.Add(1)
		writeError(w, http.StatusBadRequest, "DIGEST_INVALID", "only sha256 digests are served")
		return "", false
	}
	return raw, true
}

// getBlob serves blob GET and HEAD.
//
// http.ServeContent supplies Content-Length, HEAD semantics and the Range
// handling containerd's fetcher uses to resume (`bytes=N-`).
func (r *Registry) getBlob(w http.ResponseWriter, req *http.Request) {
	if _, _, ok := r.repo(w, req, false); !ok {
		return
	}
	dgst, ok := r.pathDigest(w, req.PathValue("digest"))
	if !ok {
		return
	}
	_, modTime, ok := r.store.statBlob(dgst)
	if !ok {
		writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not present: "+dgst)
		return
	}
	f, err := os.Open(r.store.blobFile(dgst)) // #nosec G304; a path composed from a validated digest
	if err != nil {
		writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not present: "+dgst)
		return
	}
	defer f.Close() //nolint:errcheck // read-only file

	w.Header().Set("Docker-Content-Digest", dgst)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, req, "", modTime, f)
}

// startUpload opens an upload session, or answers a cross-repo mount.
func (r *Registry) startUpload(w http.ResponseWriter, req *http.Request) {
	project, service, ok := r.repo(w, req, true)
	if !ok {
		return
	}

	// A mount, or a monolithic POST naming a digest that already exists:
	// blobs are one global content-addressed set, so any present blob
	// answers 201 with no copying.
	for _, key := range []string{"mount", "digest"} {
		dgst := req.URL.Query().Get(key)
		if dgst == "" || !validDigest(dgst) {
			continue
		}
		if _, _, ok := r.store.statBlob(dgst); ok {
			w.Header().Set("Docker-Content-Digest", dgst)
			w.Header().Set("Location", blobLocation(project, service, dgst))
			w.WriteHeader(http.StatusCreated)
			return
		}
	}

	u, err := r.store.startUpload()
	if errors.Is(err, errTooManyUploads) {
		r.refusals.bounds.Add(1)
		writeError(w, http.StatusTooManyRequests, "TOOMANYREQUESTS",
			fmt.Sprintf("at most %d concurrent uploads", maxUploads))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "UNKNOWN", "cannot open an upload session")
		return
	}
	// Relative, with no query: containerd's pusher resolves the Location per
	// RFC and appends `?digest=` itself, and a query here would make that
	// append ambiguous.
	w.Header().Set("Location", uploadLocation(project, service, u.id))
	w.Header().Set("Docker-Upload-UUID", u.id)
	w.Header().Set("Range", "0-0")
	w.WriteHeader(http.StatusAccepted)
}

// patchUpload appends a chunk.
//
// Neither containerd nor buildkit sends PATCH (the pusher does POST then one
// monolithic PUT); crane and regctl do, and the sequential-only subset is
// enough for a debugging push.
func (r *Registry) patchUpload(w http.ResponseWriter, req *http.Request) {
	if _, _, ok := r.repo(w, req, true); !ok {
		return
	}
	u, ok := r.store.getUpload(req.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload session")
		return
	}
	if cr := req.Header.Get("Content-Range"); cr != "" {
		var start, end int64
		if _, err := fmt.Sscanf(cr, "%d-%d", &start, &end); err != nil || start != u.offset() {
			r.refusals.bounds.Add(1)
			writeError(w, http.StatusRequestedRangeNotSatisfiable, "BLOB_UPLOAD_INVALID",
				fmt.Sprintf("chunks are sequential; the session is at offset %d", u.offset()))
			return
		}
	}
	size, err := u.append(req.Body)
	if err != nil {
		r.store.dropUpload(u.id)
		writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_INVALID", "cannot write the chunk")
		return
	}
	w.Header().Set("Docker-Upload-UUID", u.id)
	w.Header().Set("Range", fmt.Sprintf("0-%d", max(size-1, 0)))
	w.WriteHeader(http.StatusAccepted)
}

// putUpload takes the final content and commits the blob.
//
// This is the path every BuildKit layer, config and manifest blob takes: one
// POST for the session, one PUT with the whole body and `?digest=`.
func (r *Registry) putUpload(w http.ResponseWriter, req *http.Request) {
	project, service, ok := r.repo(w, req, true)
	if !ok {
		return
	}
	dgst := req.URL.Query().Get("digest")
	if !validDigest(dgst) {
		r.refusals.digest.Add(1)
		writeError(w, http.StatusBadRequest, "DIGEST_INVALID", "the digest query must name a sha256 digest")
		return
	}
	u, ok := r.store.getUpload(req.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload session")
		return
	}
	if _, err := u.append(req.Body); err != nil {
		r.store.dropUpload(u.id)
		writeError(w, http.StatusInternalServerError, "BLOB_UPLOAD_INVALID", "cannot write the content")
		return
	}
	if err := r.store.commitUpload(u, dgst); err != nil {
		if errors.Is(err, errDigestMismatch) {
			// Fail closed: the bytes are already deleted, and the counter is
			// what makes a client pushing garbage visible.
			r.refusals.digest.Add(1)
			r.log.Warn("registry refused a blob whose content did not match its digest",
				"declared", dgst)
			writeError(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "UNKNOWN", "cannot commit the blob")
		return
	}
	w.Header().Set("Docker-Content-Digest", dgst)
	w.Header().Set("Location", blobLocation(project, service, dgst))
	w.WriteHeader(http.StatusCreated)
}

// statUpload reports a session's progress, for a resuming client.
func (r *Registry) statUpload(w http.ResponseWriter, req *http.Request) {
	if _, _, ok := r.repo(w, req, false); !ok {
		return
	}
	u, ok := r.store.getUpload(req.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "no such upload session")
		return
	}
	w.Header().Set("Docker-Upload-UUID", u.id)
	w.Header().Set("Range", fmt.Sprintf("0-%d", max(u.offset()-1, 0)))
	w.WriteHeader(http.StatusNoContent)
}

// getManifest serves manifest GET and HEAD.
//
// The HEAD is *the* resolve path: containerd resolves a tag by HEAD and
// requires Docker-Content-Digest, Content-Length and the stored Content-Type
// in the answer. The GET returns the stored bytes verbatim under the media
// type recorded at push - the digest was computed over exactly these bytes,
// and re-serialising anything breaks the pull.
func (r *Registry) getManifest(w http.ResponseWriter, req *http.Request) {
	project, service, ok := r.repo(w, req, false)
	if !ok {
		return
	}
	dgst, ok := r.resolveRef(w, project, service, req.PathValue("ref"))
	if !ok {
		return
	}
	mediaType, size, ok := r.store.statManifest(project, service, dgst)
	if !ok {
		writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest not present: "+dgst)
		return
	}
	w.Header().Set("Docker-Content-Digest", dgst)
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	f, err := os.Open(r.store.blobFile(dgst)) // #nosec G304; a path composed from a validated digest
	if err != nil {
		writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest not present: "+dgst)
		return
	}
	defer f.Close() //nolint:errcheck // read-only file
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f) //nolint:errcheck // the client hanging up mid-body is its business
}

// resolveRef turns a tag-or-digest path segment into a digest.
func (r *Registry) resolveRef(w http.ResponseWriter, project, service, ref string) (string, bool) {
	switch {
	case validDigest(ref):
		return ref, true
	case validTag(ref):
		dgst, ok := r.store.resolveTag(project, service, ref)
		if !ok {
			writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "no such tag: "+ref)
			return "", false
		}
		return dgst, true
	default:
		r.refusals.name.Add(1)
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID",
			"the reference must be a tag or a sha256 digest")
		return "", false
	}
}

// manifestRefs is the slice of a manifest this registry reads: the digests it
// references, so a PUT can require them present and the sweep can keep them.
type manifestRefs struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}

// referencedDigests lists every digest a manifest body names.
func referencedDigests(body []byte) ([]string, error) {
	var refs manifestRefs
	if err := json.Unmarshal(body, &refs); err != nil {
		return nil, err
	}
	var out []string
	if refs.Config.Digest != "" {
		out = append(out, refs.Config.Digest)
	}
	for _, layer := range refs.Layers {
		out = append(out, layer.Digest)
	}
	for _, m := range refs.Manifests {
		out = append(out, m.Digest)
	}
	return out, nil
}

// putManifest records a manifest.
func (r *Registry) putManifest(w http.ResponseWriter, req *http.Request) {
	project, service, ok := r.repo(w, req, true)
	if !ok {
		return
	}
	ref := req.PathValue("ref")
	if !validDigest(ref) && !validTag(ref) {
		r.refusals.name.Add(1)
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID",
			"the reference must be a tag or a sha256 digest")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxManifestBytes))
	if err != nil {
		r.refusals.bounds.Add(1)
		writeError(w, http.StatusBadRequest, "SIZE_INVALID",
			fmt.Sprintf("a manifest is at most %d bytes", maxManifestBytes))
		return
	}

	sum := sha256.Sum256(body)
	dgst := "sha256:" + hex.EncodeToString(sum[:])
	if validDigest(ref) && ref != dgst {
		r.refusals.digest.Add(1)
		writeError(w, http.StatusBadRequest, "DIGEST_INVALID",
			"the manifest does not match the digest it was pushed under")
		return
	}

	refs, err := referencedDigests(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "the manifest is not JSON")
		return
	}
	// Fail closed: every referenced blob must already be present. BuildKit
	// pushes children first, so this never fires on a healthy push; when it
	// does fire, accepting the manifest would record an image that cannot be
	// pulled.
	for _, child := range refs {
		if !validDigest(child) {
			writeError(w, http.StatusBadRequest, "MANIFEST_INVALID",
				"the manifest references a non-sha256 digest")
			return
		}
		if _, _, ok := r.store.statBlob(child); !ok {
			writeError(w, http.StatusBadRequest, "MANIFEST_BLOB_UNKNOWN",
				"the manifest references an absent blob: "+child)
			return
		}
	}

	mediaType := req.Header.Get("Content-Type")
	if mediaType == "" {
		mediaType = "application/vnd.oci.image.manifest.v1+json"
	}

	// The manifest body is a blob like any other; write it first so the
	// marker never references absent bytes.
	if _, _, ok := r.store.statBlob(dgst); !ok {
		if err := writeFileAtomic(r.store.blobFile(dgst), body); err != nil {
			writeError(w, http.StatusInternalServerError, "UNKNOWN", "cannot store the manifest")
			return
		}
	}
	tag := ""
	if !validDigest(ref) {
		tag = ref
	}
	if err := r.store.putManifest(project, service, dgst, mediaType, tag); err != nil {
		if errors.Is(err, errTooManyTags) {
			r.refusals.bounds.Add(1)
			writeError(w, http.StatusBadRequest, "DENIED",
				fmt.Sprintf("a repository holds at most %d tags", maxTags))
			return
		}
		writeError(w, http.StatusInternalServerError, "UNKNOWN", "cannot record the manifest")
		return
	}

	// Retention runs behind every manifest write (steady state writes
	// nothing, so an idle registry never sweeps); a sweep failure is logged,
	// never surfaced, because losing GC is nothing next to losing the push.
	r.store.sweep(r.log)

	w.Header().Set("Docker-Content-Digest", dgst)
	w.Header().Set("Location", "/v2/"+project+"/"+service+"/manifests/"+dgst)
	w.WriteHeader(http.StatusCreated)
}

func blobLocation(project, service, dgst string) string {
	return "/v2/" + project + "/" + service + "/blobs/" + dgst
}

func uploadLocation(project, service, id string) string {
	return "/v2/" + project + "/" + service + "/blobs/uploads/" + id
}
