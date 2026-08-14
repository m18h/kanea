# Check H — the M11 exit criterion, as a spec (PRD §20 M11, v1.39).
#
# The criterion is: "a wasi-http function deploys from a spec, serves through
# the edge (FQDN and functions-port modes), fires on a matching event and a
# cron tick; invocation rate visible from an east-west call; pre-v1.39 Store
# upgrade rolls zero allocs".
#
# Three objects, one per clause that needs one:
#
#   hello    the function under test. Its three triggers are the three
#            invocation paths the criterion names.
#   caller   an ordinary service that dials the function's VIP in a loop. This
#            is what makes the rate an EAST-WEST number: edge rps would miss it
#            entirely, and §9.1 counts a connect to the VIP as an invocation
#            however it arrived.
#   tripwire a service that exists only to be deployed, because deploying it
#            emits deploy.succeeded — the event `hello` triggers on. Firing a
#            real event beats POSTing a synthetic one: the criterion says
#            "fires on a matching event", and a test event would prove the
#            dispatcher, not the vocabulary.
#
# check-h.sh drives this. Nothing here is a product artefact: it is the spike's
# fixture, kept beside the spike it belongs to.
spec_version = 1

project "checkh" {
  description = "M11 check H — functions end to end on a real node"
}

function "hello" {
  project = "checkh"

  # Built by ../modules/hello-http and packaged by ./mkimage.sh, which imports
  # it straight into kanead's own containerd namespace. EnsureImage returns
  # early when an image is present locally, so this ref never has to resolve
  # against a registry — which is what makes the check runnable on a node with
  # no registry at all.
  module = "registry.local/checkh/hello-http:1"

  # Its FQDN through the edge, and the functions port. One trigger, both
  # modes: the dispatcher serves /<project>/<function>/ on the functions port
  # for a node with no base domain, and the criterion wants both exercised.
  trigger "http" {}

  # The event path. deploy.succeeded is in the §11 vocabulary
  # (internal/notify/event.go) and deploying `tripwire` produces one.
  trigger "event" {
    on = ["deploy.succeeded"]
  }

  # The cron path. Every minute, so the check waits ~60s rather than parking
  # until 03:00 — the criterion is that a tick fires, not when.
  trigger "cron" {
    schedule = "* * * * *"
  }

  # A real cgroup cap, not advisory (R25/R11). The spike measured shim RSS at
  # ~20 MiB, so 64 leaves room without hiding a leak.
  resources {
    memory = 64
  }
}

# The east-west caller. busybox because it is already the integration tests'
# image, so a node that has run those has it cached.
service "caller" {
  project = "checkh"
  count   = 1

  task "loop" {
    image = "docker.io/library/busybox:1.37"
    # One connect per second against the function's VIP, by its internal name
    # (<service>.<project>.kanea — internal/network/dns.go). Each connect is an
    # invocation by §9.1's definition, and none of them touch the edge.
    command = [
      "sh", "-c",
      "while true; do wget -q -O- -T 3 http://hello.checkh.kanea/ >/dev/null 2>&1 || true; sleep 1; done",
    ]
    resources {
      memory = 32
    }
  }
}

# Deployed to produce deploy.succeeded. It does nothing else and is not
# required to stay healthy for the check to pass.
service "tripwire" {
  project = "checkh"
  count   = 1

  task "sleep" {
    image   = "docker.io/library/busybox:1.37"
    command = ["sh", "-c", "sleep 86400"]
    resources {
      memory = 16
    }
  }
}
