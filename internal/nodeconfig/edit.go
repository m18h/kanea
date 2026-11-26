package nodeconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// Editor changes a node config in place: `kanea init` writes what it settled
// through it, and `kanea config migrate` builds a file from an older unit's
// flags. It edits the syntax tree rather than re-rendering a Config, so the
// operator's comments, ordering and formatting survive every edit.
//
// An attribute is addressed by its path: the last element is the attribute,
// the ones before it are unlabelled blocks ("network", "node_cidr";
// "backup", "s3", "url"). Labelled blocks (device, socket, provider,
// certificate) are only ever moved whole, by AppendBlocksFrom and
// RemoveBlocks.
type Editor struct {
	file *hclwrite.File
}

// NewEditor parses src for editing. Empty src is an empty document.
func NewEditor(filename string, src []byte) (*Editor, error) {
	file, diags := hclwrite.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("nodeconfig: %s", diags.Error())
	}
	return &Editor{file: file}, nil
}

// body walks path's block elements. create makes the missing ones; without
// it a missing block is a nil body.
func (e *Editor) body(blocks []string, create bool) *hclwrite.Body {
	body := e.file.Body()
	for _, name := range blocks {
		block := body.FirstMatchingBlock(name, nil)
		if block == nil {
			if !create {
				return nil
			}
			// A blank line before a new top-level stanza, as a person would
			// leave one; hclwrite appends blocks flush otherwise.
			if body == e.file.Body() && len(body.BuildTokens(nil)) > 0 {
				body.AppendNewline()
			}
			block = body.AppendNewBlock(name, nil)
		}
		body = block.Body()
	}
	return body
}

// Has reports whether the attribute at path is written in the document.
func (e *Editor) Has(path ...string) bool {
	if len(path) == 0 {
		return false
	}
	body := e.body(path[:len(path)-1], false)
	return body != nil && body.GetAttribute(path[len(path)-1]) != nil
}

// Set writes the attribute at path, creating the blocks before it on demand
// and replacing the value in place when the attribute already exists.
func (e *Editor) Set(v cty.Value, path ...string) {
	if len(path) == 0 {
		return
	}
	e.body(path[:len(path)-1], true).SetAttributeValue(path[len(path)-1], v)
}

// Unset removes the attribute at path. Absent is a no-op; the block it lived
// in is left where it is, empty or not.
func (e *Editor) Unset(path ...string) {
	if len(path) == 0 {
		return
	}
	if body := e.body(path[:len(path)-1], false); body != nil {
		body.RemoveAttribute(path[len(path)-1])
	}
}

// RemoveBlocks removes every top-level block of blockType, whatever its
// labels.
func (e *Editor) RemoveBlocks(blockType string) {
	body := e.file.Body()
	for _, block := range body.Blocks() {
		if block.Type() == blockType {
			body.RemoveBlock(block)
		}
	}
}

// AppendBlocksFrom copies every top-level block of the named types out of
// another document, labels and body verbatim. The block is rebuilt here from
// the source's tokens, never re-parented: an hclwrite node belongs to the
// file it was parsed from.
func (e *Editor) AppendBlocksFrom(filename string, src []byte, types ...string) error {
	from, diags := hclwrite.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return fmt.Errorf("nodeconfig: %s", diags.Error())
	}
	want := make(map[string]bool, len(types))
	for _, t := range types {
		want[t] = true
	}
	body := e.file.Body()
	for _, block := range from.Body().Blocks() {
		if !want[block.Type()] {
			continue
		}
		if len(body.BuildTokens(nil)) > 0 {
			body.AppendNewline()
		}
		copied := body.AppendNewBlock(block.Type(), block.Labels())
		copied.Body().AppendUnstructuredTokens(block.Body().BuildTokens(nil))
	}
	return nil
}

// Bytes renders the document, canonically formatted.
func (e *Editor) Bytes() []byte {
	return hclwrite.Format(e.file.Bytes())
}

// WriteFile replaces the node config at path with src, atomically, and only
// if src is a config the daemons would accept: a file this function wrote is
// never the reason kanead refuses to start.
//
// The third small copy of write-temp-then-rename in the tree (provision and
// registry hold the others, unexported and package-local): sharing one would
// make this leaf package import a sibling for fifteen lines.
func WriteFile(path string, src []byte) error {
	if _, err := Parse(path, src); err != nil {
		return fmt.Errorf("refusing to write %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kanea.hcl.*")
	if err != nil {
		return fmt.Errorf("nodeconfig: write %s: %w", path, err)
	}
	// A failure below leaves the old file exactly as it was; the temporary
	// one is removed rather than left to be mistaken for a config.
	fail := func(err error) error {
		return errors.Join(fmt.Errorf("nodeconfig: write %s: %w", path, err),
			tmp.Close(), os.Remove(tmp.Name()))
	}
	if _, err := tmp.Write(src); err != nil {
		return fail(err)
	}
	// 0644: policy, not a secret, and CheckTrusted refuses anything a group
	// or the world could write. CreateTemp's 0600 would lock the edge's own
	// user out of the file it is configured from.
	if err := tmp.Chmod(0o644); err != nil { // #nosec G302; the node config is world-readable by design
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("nodeconfig: write %s: %w", path, err), os.Remove(tmp.Name()))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.Join(fmt.Errorf("nodeconfig: write %s: %w", path, err), os.Remove(tmp.Name()))
	}
	return nil
}
