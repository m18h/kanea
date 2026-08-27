package reconciler

// RetargetImage points d's task at image and follows every init step whose
// image is byte-equal to the task's previous one (PRD v1.99). The common init
// shape is the application image with a different command - a migration run
// by the app's own CLI - and a deploy that moved the task alone re-ran
// yesterday's migrations against today's application; a step declaring any
// other image (a busybox chown, a dedicated migrator) is untouched.
//
// Byte equality on the declared reference, deliberately: no normalisation and
// no resolution, because this runs client-side in the CLI and MCP as well as
// in the daemon's GitOps deployer, and a comparison that resolved anything
// would make one spec mean different things on two machines. All three deploy
// sites call this one helper, which is what keeps a step that starts equal to
// the task equal through every subsequent deploy: each call matches against
// the reference the previous one wrote.
//
// It returns the names of the steps that moved; every caller reports them,
// because a spec field changing without a spec edit must say so.
func RetargetImage(d *Desired, image string) []string {
	previous := d.Image
	d.Image = image
	if previous == "" || previous == image {
		return nil
	}
	var moved []string
	for i := range d.Init {
		if d.Init[i].Image == previous {
			d.Init[i].Image = image
			moved = append(moved, d.Init[i].Name)
		}
	}
	return moved
}
