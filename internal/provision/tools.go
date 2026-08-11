package provision

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// sbinDirs are the canonical homes of system administration binaries. On
// Debian a non-root user's PATH does not include them, and a sudo that does
// not apply secure_path hands that PATH straight to this process — so
// exec.LookPath declares useradd missing on a node where /usr/sbin/useradd
// has existed for decades. Field report: a stock Debian 12 install failed
// `kanea init` exactly this way.
var sbinDirs = []string{"/usr/sbin", "/sbin", "/usr/local/sbin"}

// lookupTool resolves an executable the way exec.LookPath does, then keeps
// looking where LookPath cannot: PATH is an environment variable, not a
// statement about what is installed.
func lookupTool(name string) (string, error) {
	return lookupToolIn(name, sbinDirs)
}

func lookupToolIn(name string, dirs []string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range dirs {
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		return p, nil
	}
	return "", fmt.Errorf("%s not found on PATH or in %v", name, dirs)
}
