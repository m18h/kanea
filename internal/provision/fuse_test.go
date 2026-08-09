package provision

import "testing"

// Every distribution ships /etc/fuse.conf with user_allow_other present and
// commented out. Treating that as "set" is the one mistake this check exists
// to avoid — it would leave every S3 volume failing at the first deploy with
// an error about a mount option.
func TestFuseAllowOtherDetection(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"empty file", "", false},
		{"the distribution default", "# mount_max = 1000\n#user_allow_other\n", false},
		{"commented with a space", "# user_allow_other\n", false},
		{"set", "user_allow_other\n", true},
		{"set with other options", "mount_max = 1000\nuser_allow_other\n", true},
		{"set with surrounding whitespace", "   user_allow_other   \n", true},
		{"a similar but different option", "user_allow_root\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fuseAllowOtherSet(tt.body); got != tt.want {
				t.Errorf("fuseAllowOtherSet(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
