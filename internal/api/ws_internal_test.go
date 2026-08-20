package api

// An internal test, like internal/auth's limiter test and for the same reason:
// subscriptionKey has no exported surface, and exporting one so a test could
// reach it would make a private decision part of the package's API.

import "testing"

// TestASubscriptionKeyDistinguishesContainers (PRD v1.84, §6.2 R32).
//
// `tail` is deliberately *not* part of a subscription key - it asks for more of
// the same stream, so keying on it would make a remount open a second live feed
// - but `container` selects a **different** stream. Keying them together would
// make a log panel switching from an init step back to the task replace a
// subscription that is still wanted.
func TestASubscriptionKeyDistinguishesContainers(t *testing.T) {
	task := ClientFrame{Topic: "logs", Project: "shop", Service: "web"}
	step := ClientFrame{Topic: "logs", Project: "shop", Service: "web", Container: "migrate"}
	other := ClientFrame{Topic: "logs", Project: "shop", Service: "web", Container: "seed"}

	taskKey, stepKey, otherKey := subscriptionKey(task), subscriptionKey(step), subscriptionKey(other)
	if taskKey == stepKey || stepKey == otherKey {
		t.Fatalf("two different log streams share one subscription key: %q %q %q",
			taskKey, stepKey, otherKey)
	}

	// And a pre-v1.84 subscribe frame keeps the key it always had, or every
	// existing client's subscription silently moves on upgrade.
	withTail := task
	withTail.Tail = 200
	if got := subscriptionKey(withTail); got != taskKey {
		t.Errorf("tail changed the key: %q != %q; tail asks for more of one stream, "+
			"not for a different one", got, taskKey)
	}
	if taskKey != "logs:shop/web" {
		t.Errorf("the task's key changed shape: %q; every existing subscription depends on it",
			taskKey)
	}
}
