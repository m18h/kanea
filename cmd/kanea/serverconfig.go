package main

import (
	"strings"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// serverConfigForRun decides whether the §15.1 server config is consulted at
// all, and loads it. wellKnown is nodeconfig.DefaultPath in production; a
// parameter so tests can point it at a temp file.
//
// When both halves the file can feed are flag-overridden and no --config was
// asked for, the probe is skipped entirely: nothing would read the file, so a
// stray or malformed one must not be able to refuse startup — a node upgraded
// with its unit flags intact behaves byte-identically to the release before
// the file existed.
func serverConfigForRun(configFlag, hostPathsFlag, passthroughFlag, wellKnown string) (*nodeconfig.Config, error) {
	configFlag = strings.TrimSpace(configFlag)
	if configFlag == "" && hostPathsFlag != "" && passthroughFlag != "" {
		return &nodeconfig.Config{}, nil
	}
	switch configFlag {
	case "off":
		return &nodeconfig.Config{}, nil
	case "":
		return nodeconfig.Probe(wellKnown)
	default:
		return nodeconfig.Load(configFlag)
	}
}

// resolveHostPaths picks the R15 allowlist source: the flag when set ("off"
// disables), the server config's storage stanza otherwise. source is for the
// startup log — where a security policy came from should never need guessing.
func resolveHostPaths(flagValue string, cfg *nodeconfig.Config) (paths []string, source string) {
	switch flagValue = strings.TrimSpace(flagValue); flagValue {
	case "off":
		return nil, "off"
	case "":
		return cfg.AllowedHostPaths, cfg.Path
	default:
		return splitList(flagValue), "--allowed-host-paths"
	}
}

// resolvePassthroughPath picks the file the R17/R18 grants are parsed from:
// the flag's file when set ("off" disables), the server config itself
// otherwise — internal/passthrough decodes its blocks straight out of
// kanea.hcl. An explicitly flagged file gets the same trust check the probed
// one got in nodeconfig.Load: the boundary claim does not weaken because the
// path arrived by argv.
func resolvePassthroughPath(flagValue string, cfg *nodeconfig.Config) (path, source string, err error) {
	switch flagValue = strings.TrimSpace(flagValue); flagValue {
	case "off":
		return "", "off", nil
	case "":
		if cfg.Path == "" {
			return "", "", nil
		}
		return cfg.Path, cfg.Path, nil
	default:
		if err := nodeconfig.CheckTrusted(flagValue); err != nil {
			return "", "", err
		}
		return flagValue, "--passthrough-config", nil
	}
}
