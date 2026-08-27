package reconciler_test

import (
	"reflect"
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
)

func TestRetargetImage(t *testing.T) {
	cases := []struct {
		name       string
		image      string // the task's current image
		init       []reconciler.InitContainer
		deploy     string // the new image
		wantMoved  []string
		wantImages []string // init images after the call
	}{
		{
			name:  "an init step on the task's image follows",
			image: "ghcr.io/acme/web:v1",
			init: []reconciler.InitContainer{
				{Name: "migrate", Image: "ghcr.io/acme/web:v1"},
			},
			deploy:     "ghcr.io/acme/web:v2",
			wantMoved:  []string{"migrate"},
			wantImages: []string{"ghcr.io/acme/web:v2"},
		},
		{
			name:  "a step on its own image is untouched",
			image: "ghcr.io/acme/web:v1",
			init: []reconciler.InitContainer{
				{Name: "chown", Image: "busybox:1.36"},
			},
			deploy:     "ghcr.io/acme/web:v2",
			wantMoved:  nil,
			wantImages: []string{"busybox:1.36"},
		},
		{
			name:  "mixed steps: only the matching ones move, in order",
			image: "ghcr.io/acme/web:v1",
			init: []reconciler.InitContainer{
				{Name: "chown", Image: "busybox:1.36"},
				{Name: "migrate", Image: "ghcr.io/acme/web:v1"},
				{Name: "seed", Image: "ghcr.io/acme/web:v1"},
			},
			deploy:     "ghcr.io/acme/web@sha256:abc",
			wantMoved:  []string{"migrate", "seed"},
			wantImages: []string{"busybox:1.36", "ghcr.io/acme/web@sha256:abc", "ghcr.io/acme/web@sha256:abc"},
		},
		{
			// Byte equality, never normalisation: an author who writes the
			// same image two ways has said two things (PRD v1.99).
			name:  "a differently spelled reference does not match",
			image: "ghcr.io/acme/web:v1",
			init: []reconciler.InitContainer{
				{Name: "migrate", Image: "ghcr.io/acme/web:v1 "},
			},
			deploy:     "ghcr.io/acme/web:v2",
			wantMoved:  nil,
			wantImages: []string{"ghcr.io/acme/web:v1 "},
		},
		{
			// A build-block service can carry an empty declared image before
			// its first build; an init image can never be empty (R32), so
			// nothing can match and nothing must move.
			name:  "an empty previous image matches nothing",
			image: "",
			init: []reconciler.InitContainer{
				{Name: "migrate", Image: "ghcr.io/acme/web:v1"},
			},
			deploy:     "ghcr.io/acme/web:v2",
			wantMoved:  nil,
			wantImages: []string{"ghcr.io/acme/web:v1"},
		},
		{
			name:  "deploying the image already declared moves nothing",
			image: "ghcr.io/acme/web:v1",
			init: []reconciler.InitContainer{
				{Name: "migrate", Image: "ghcr.io/acme/web:v1"},
			},
			deploy:     "ghcr.io/acme/web:v1",
			wantMoved:  nil,
			wantImages: []string{"ghcr.io/acme/web:v1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := desired(1)
			d.Image = tc.image
			d.Init = tc.init

			moved := reconciler.RetargetImage(&d, tc.deploy)

			if d.Image != tc.deploy {
				t.Errorf("task image = %q, want %q", d.Image, tc.deploy)
			}
			if !reflect.DeepEqual(moved, tc.wantMoved) {
				t.Errorf("moved = %v, want %v", moved, tc.wantMoved)
			}
			for i, want := range tc.wantImages {
				if got := d.Init[i].Image; got != want {
					t.Errorf("init %q image = %q, want %q", d.Init[i].Name, got, want)
				}
			}
		})
	}
}
