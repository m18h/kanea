package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/reconciler"
)

// The default is yes, so the common case is one keypress on a preview of
// something the operator just typed.
func TestConfirmApplyDefaultsToYes(t *testing.T) {
	for _, answer := range []string{"\n", "y\n", "Y\n", "yes\n", "YES\n", "  y  \n"} {
		var buf bytes.Buffer
		ok, err := confirmApply(&out{w: &buf}, bufio.NewReader(strings.NewReader(answer)), true)
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if !ok {
			t.Errorf("answer %q did not apply", answer)
		}
	}
}

// Anything that is not a yes aborts, a typo included: re-running `kanea run`
// costs a second and a wrong yes costs a rolling restart.
func TestConfirmApplyAbortsOnAnythingElse(t *testing.T) {
	for _, answer := range []string{"n\n", "no\n", "N\n", "q\n", "yes please\n", "\x00\n"} {
		var buf bytes.Buffer
		ok, err := confirmApply(&out{w: &buf}, bufio.NewReader(strings.NewReader(answer)), true)
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if ok {
			t.Errorf("answer %q applied", answer)
		}
	}
}

// A last line with no trailing newline is still an answer: a terminal that is
// closed mid-answer must not be read as consent, but "y" followed by EOF is
// what a `printf y | kanea run` produces and it means yes.
func TestConfirmApplyAcceptsAnUnterminatedLine(t *testing.T) {
	var buf bytes.Buffer
	ok, err := confirmApply(&out{w: &buf}, bufio.NewReader(strings.NewReader("y")), true)
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v; want an unterminated \"y\" to apply", ok, err)
	}
}

// The most important case in this file. A piped or redirected stdin is a
// script, and a script must never be asked a question: every CI recipe written
// against an older kanea has to keep working byte for byte. Reading even one
// byte here would eat input meant for something else.
func TestConfirmApplyNeverReadsWhenNotInteractive(t *testing.T) {
	var buf bytes.Buffer
	reader := bufio.NewReader(strings.NewReader("this line must not be consumed\n"))
	ok, err := confirmApply(&out{w: &buf}, reader, false)
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v; want a non-interactive run to apply", ok, err)
	}
	if buf.Len() != 0 {
		t.Errorf("a non-interactive run printed a prompt: %q", buf.String())
	}
	line, _ := reader.ReadString('\n')
	if line != "this line must not be consumed\n" {
		t.Errorf("the prompt consumed stdin: next line is %q", line)
	}
}

// The prompt says what it defaults to, or the capital in [Y/n] is the only
// thing telling a reader that Enter applies.
func TestConfirmApplyNamesItsDefault(t *testing.T) {
	var buf bytes.Buffer
	if _, err := confirmApply(&out{w: &buf}, bufio.NewReader(strings.NewReader("\n")), true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "[Y/n]") {
		t.Errorf("prompt = %q, want it to name the default", buf.String())
	}
}

// The default is no, confirmApply's opposite (PRD v1.100): this gates a
// destruction, not a preview, so an empty line aborts and only a yes proceeds.
func TestConfirmRemoveDefaultsToNo(t *testing.T) {
	for _, answer := range []string{"\n", "n\n", "no\n", "N\n", "q\n", "yes please\n", "y y\n"} {
		var buf bytes.Buffer
		ok, err := confirmRemove(&out{w: &buf}, bufio.NewReader(strings.NewReader(answer)), "shop/web", true)
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if ok {
			t.Errorf("answer %q removed", answer)
		}
	}
}

func TestConfirmRemoveAcceptsAYes(t *testing.T) {
	// The unterminated "y" is what `printf y | kanea remove …` produces, and it
	// means yes.
	for _, answer := range []string{"y\n", "Y\n", "yes\n", "YES\n", "  y  \n", "y"} {
		var buf bytes.Buffer
		ok, err := confirmRemove(&out{w: &buf}, bufio.NewReader(strings.NewReader(answer)), "shop/web", true)
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if !ok {
			t.Errorf("answer %q did not remove", answer)
		}
	}
}

// A closed stdin with nothing typed is an abort, not an error: the default is
// no, and no is always a safe answer here.
func TestConfirmRemoveAbortsOnEOF(t *testing.T) {
	var buf bytes.Buffer
	ok, err := confirmRemove(&out{w: &buf}, bufio.NewReader(strings.NewReader("")), "shop/web", true)
	if err != nil || ok {
		t.Fatalf("ok = %v, err = %v; want EOF to abort cleanly", ok, err)
	}
}

// The most important case, same as confirmApply's: a piped stdin is a script,
// scripts are never asked, and `kanea stop --rm` has worked in scripts since
// v1.83 - byte for byte, nothing consumed.
func TestConfirmRemoveNeverReadsWhenNotInteractive(t *testing.T) {
	var buf bytes.Buffer
	reader := bufio.NewReader(strings.NewReader("this line must not be consumed\n"))
	ok, err := confirmRemove(&out{w: &buf}, reader, "shop/web", false)
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v; want a non-interactive remove to proceed", ok, err)
	}
	if buf.Len() != 0 {
		t.Errorf("a non-interactive remove printed a prompt: %q", buf.String())
	}
	line, _ := reader.ReadString('\n')
	if line != "this line must not be consumed\n" {
		t.Errorf("the prompt consumed stdin: next line is %q", line)
	}
}

// The prompt names its target and its default: [y/N]'s capital is what tells a
// reader that Enter aborts, and the name is what stops a wrong-tab removal.
func TestConfirmRemoveNamesTheTargetAndItsDefault(t *testing.T) {
	var buf bytes.Buffer
	if _, err := confirmRemove(&out{w: &buf}, bufio.NewReader(strings.NewReader("\n")), "shop/web", true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[y/N]", "shop/web", "volume data is kept"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("prompt = %q, want it to carry %q", buf.String(), want)
		}
	}
}

func changeSet(t *testing.T) []reconciler.ServiceChange {
	t.Helper()
	current := []reconciler.Desired{
		{Project: "shop", Service: "web", Image: "web:v1", Count: 1},
		{Project: "shop", Service: "legacy", Image: "legacy:v1", Count: 1},
	}
	desired := []reconciler.Desired{
		{Project: "shop", Service: "web", Image: "web:v2", Count: 1},
		{Project: "shop", Service: "worker", Image: "worker:v1", Count: 2},
	}
	return reconciler.Changes(current, desired, []string{"shop"})
}

// The verdict has to carry the number that decides whether to type y: how much
// of this replaces containers that are serving traffic right now.
func TestPlanSummaryNamesWhatWouldRoll(t *testing.T) {
	got := planSummary(changeSet(t))
	for _, want := range []string{"3 change(s)", "1 create", "1 update", "1 destroy",
		"1 replace running allocs"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q does not carry %q", got, want)
		}
	}
}

// A converged spec must stay quiet: "no changes" is what makes re-running
// `kanea run` safe to type.
func TestWriteChangesSaysNothingWhenNothingChanges(t *testing.T) {
	var buf bytes.Buffer
	o := &out{w: &buf}
	writeChanges(o, nil, nil)
	if err := o.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No changes") {
		t.Errorf("output = %q", buf.String())
	}
	if strings.Contains(buf.String(), "Plan:") {
		t.Errorf("a converged spec printed a plan summary: %q", buf.String())
	}
}

// An apply also writes each project's git source, build specs and notification
// routes, and nothing reads those back, so the CLI at least says they are being
// sent. Silence there was how a changed build target reached a node unreported.
func TestWriteChangesNamesThePipelinesItWouldWrite(t *testing.T) {
	var buf bytes.Buffer
	o := &out{w: &buf}
	writeChanges(o, changeSet(t), []gitops.Config{{Project: "shop"}, {Project: "data"}})
	if err := o.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "pipelines: data, shop") {
		t.Errorf("output does not name the pipelines being written:\n%s", buf.String())
	}
}

// plan and run render the same preview from the same function. If these ever
// differ, the thing an operator confirms is not the thing they were shown.
func TestPlanAndRunRenderTheSamePreview(t *testing.T) {
	changes, pipelines := changeSet(t), []gitops.Config{{Project: "shop"}}

	var planned, applied bytes.Buffer
	po, ao := &out{w: &planned}, &out{w: &applied}
	writeChanges(po, changes, pipelines) // what `kanea plan` prints
	writeChanges(ao, changes, pipelines) // what `kanea run` prints before asking
	if err := po.Err(); err != nil {
		t.Fatal(err)
	}
	if err := ao.Err(); err != nil {
		t.Fatal(err)
	}
	if planned.String() != applied.String() {
		t.Errorf("plan and run disagree:\n--- plan ---\n%s\n--- run ---\n%s",
			planned.String(), applied.String())
	}
}

// A destroy names the volumes that go and says the data does not, every time.
func TestARunPreviewSaysVolumeDataSurvivesAPrune(t *testing.T) {
	current := []reconciler.Desired{{
		Project: "shop", Service: "legacy", Image: "legacy:v1", Count: 1,
		Volumes: []reconciler.Volume{{Name: "data", MountPath: "/data"}},
	}}
	var buf bytes.Buffer
	o := &out{w: &buf}
	writeChanges(o, reconciler.Changes(current, nil, []string{"shop"}), nil)
	if err := o.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "NOT deleted") {
		t.Errorf("a prune preview does not say the data survives:\n%s", buf.String())
	}
}

// The project prompt names everything its yes would destroy: the services,
// the config, and what survives. Its default is No, in confirmRemove's family
// but through its own helper (v1.104): this gate covers strictly more.
func TestConfirmRemoveProjectDefaultsToNoAndNamesTheServices(t *testing.T) {
	var buf bytes.Buffer
	ok, err := confirmRemoveProject(&out{w: &buf},
		bufio.NewReader(strings.NewReader("\n")), "shop", []string{"api", "web"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("an empty line removed a project; the default must be no")
	}
	for _, want := range []string{"shop", "2 service(s)", "api, web", "pipeline/notification config", "volume data is kept", "[y/N]"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("prompt = %q, want it to carry %q", buf.String(), want)
		}
	}
}

func TestConfirmRemoveProjectAcceptsOnlyYes(t *testing.T) {
	for answer, want := range map[string]bool{
		"y\n": true, "yes\n": true, "Y\n": true,
		"n\n": false, "no\n": false, "q\n": false, "\n": false,
	} {
		var buf bytes.Buffer
		ok, err := confirmRemoveProject(&out{w: &buf},
			bufio.NewReader(strings.NewReader(answer)), "shop", nil, true)
		if err != nil {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if ok != want {
			t.Errorf("answer %q = %v, want %v", answer, ok, want)
		}
	}
}

// A piped stdin is a script, and a script is never asked a question.
func TestConfirmRemoveProjectNeverPromptsANonTerminal(t *testing.T) {
	var buf bytes.Buffer
	reader := bufio.NewReader(strings.NewReader("next\n"))
	ok, err := confirmRemoveProject(&out{w: &buf}, reader, "shop", []string{"web"}, false)
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v; a non-interactive remove proceeds", ok, err)
	}
	if buf.Len() != 0 {
		t.Errorf("a non-interactive run printed a prompt: %q", buf.String())
	}
	if line, _ := reader.ReadString('\n'); line != "next\n" {
		t.Errorf("the prompt consumed stdin: next line is %q", line)
	}
}
