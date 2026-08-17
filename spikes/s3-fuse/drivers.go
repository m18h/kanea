package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// driver is one candidate S3 FUSE implementation, with the exact command line
// Kanea would use for a `storage "s3"` volume.
type driver struct {
	Name  string
	Mount string
	// args builds the mount command. Each driver daemonizes itself.
	args func(d *driver) []string
	// notes records why the flags are what they are.
	notes string
}

var drivers = []driver{
	{
		Name:  "s3fs",
		Mount: "/mnt/kanea-s3fs",
		args: func(d *driver) []string {
			return []string{"s3fs", bucket, d.Mount,
				"-o", "passwd_file=/etc/kanea-spike-s3fs.passwd",
				"-o", "url=" + s3Endpoint,
				"-o", "use_path_request_style",
				"-o", "allow_other",
				"-o", "umask=0022",
				"-o", "dbglevel=err",
			}
		},
		notes: "writes go through a local temp file per open (needs disk headroom)",
	},
	{
		Name:  "rclone",
		Mount: "/mnt/kanea-rclone",
		args: func(d *driver) []string {
			return []string{"rclone", "mount", "kaneaspike:" + bucket, d.Mount,
				"--daemon",
				"--allow-other",
				"--vfs-cache-mode", "writes",
				"--dir-cache-time", "5s",
				"--log-level", "ERROR",
			}
		},
		notes: "--vfs-cache-mode writes is the minimum for random writes; full needs a disk budget",
	},
	{
		Name:  "mount-s3",
		Mount: "/mnt/kanea-mounts3",
		args: func(d *driver) []string {
			return []string{"mount-s3", bucket, d.Mount,
				"--endpoint-url", s3Endpoint,
				"--force-path-style",
				"--region", "us-east-1",
				"--allow-other",
				"--allow-delete",
				"--allow-overwrite",
			}
		},
		notes: "AWS mountpoint-s3; deliberately not a POSIX filesystem",
	},
}

func (d *driver) mounted() bool {
	out, err := exec.Command("findmnt", "-n", "-o", "SOURCE,FSTYPE", d.Mount).CombinedOutput()
	return err == nil && len(bytes.TrimSpace(out)) > 0
}

func (d *driver) mount() error {
	_ = d.unmount()
	if err := os.MkdirAll(d.Mount, 0o755); err != nil {
		return err
	}
	argv := d.args(d)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204; spike
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(argv, " "), err, bytes.TrimSpace(out))
	}
	// All three daemonize; wait for the mount to actually appear.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if d.mounted() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s: mount point never appeared at %s", d.Name, d.Mount)
}

func (d *driver) unmount() error {
	if !d.mounted() {
		return nil
	}
	if out, err := exec.Command("fusermount3", "-u", d.Mount).CombinedOutput(); err != nil {
		// Lazy detach as a fallback: a wedged FUSE daemon must not strand the run.
		if out2, err2 := exec.Command("umount", "-l", d.Mount).CombinedOutput(); err2 != nil {
			return fmt.Errorf("fusermount3: %v (%s); umount -l: %v (%s)",
				err, bytes.TrimSpace(out), err2, bytes.TrimSpace(out2))
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !d.mounted() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s: still mounted at %s", d.Name, d.Mount)
}

func (d *driver) path(elem ...string) string {
	return filepath.Join(append([]string{d.Mount}, elem...)...)
}

// mc runs the MinIO client against the bucket: the "out of band" writer used to
// test whether a mount sees objects it did not create itself. The alias is
// passed through the environment so the spike does not depend on whose $HOME
// holds an `mc alias set` config (root's does not).
func mc(args ...string) (string, error) {
	cmd := exec.Command("mc", args...) // #nosec G204; spike
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("MC_HOST_kaneaspike=http://%s:%s@127.0.0.1:9000", accessKey, secretKey))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(bytes.TrimSpace(out)),
			fmt.Errorf("mc %s: %w (%s)", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return string(bytes.TrimSpace(out)), nil
}

// resetBucket empties the bucket so each phase starts from a known state.
func resetBucket() error {
	if _, err := mc("rm", "--recursive", "--force", "kaneaspike/"+bucket); err != nil {
		return err
	}
	_, err := mc("mb", "--ignore-existing", "kaneaspike/"+bucket)
	return err
}

func systemctl(action, unit string) error {
	out, err := exec.Command("systemctl", action, unit).CombinedOutput() // #nosec G204; spike
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w (%s)", action, unit, err, bytes.TrimSpace(out))
	}
	return nil
}
