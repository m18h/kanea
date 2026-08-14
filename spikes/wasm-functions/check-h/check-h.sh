#!/usr/bin/env bash
# Check H — the M11 exit criterion, on a real kanead node (PRD §20 M11).
#
# Checks A–G ran at the containerd level (../REPORT.md, 7/7 GO on 2026-08-10)
# and validated everything below the datapath: the shim takes Kanea's hardening
# and resources spec unchanged, task.Exec is unsupported, the memory cap
# OOM-kills, wasi-http serves, and modules ship as host-platform scratch images.
# H is what a containerd-level harness cannot reach — the edge, the VIP, the
# invokers, the datapath's own counters — so it needs a node.
#
# The exit criterion, verbatim: "a wasi-http function deploys from a spec,
# serves through the edge (FQDN and functions-port modes), fires on a matching
# event and a cron tick; invocation rate visible from an east-west call;
# pre-v1.39 Store upgrade rolls zero allocs". Each clause below is one check,
# and the last is deliberately NOT here — see the note at the end.
#
# Run it on the node, as root, from a checkout:
#
#     sudo ./check-h.sh                      # everything
#     sudo ./check-h.sh --keep               # leave the project deployed
#
# It prints PASS/FAIL per clause in the spike harness's house style and exits
# non-zero if any clause fails. Paste the output into ../REPORT.md.
set -uo pipefail
cd "$(dirname "$0")"

KANEA="${KANEA:-kanea}"
PROJECT=checkh
FUNCTION=hello
KEEP=""
FUNCTIONS_PORT="${FUNCTIONS_PORT:-8081}"

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

PASSES=0
FAILS=0
pass() { printf 'PASS  %s\n' "$*"; PASSES=$((PASSES + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf 'INFO  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

# fn_json prints the function's view from GET /v1/functions.
fn_json() {
  "$KANEA" functions list --json 2>/dev/null |
    python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
for f in d.get('functions',[]):
    if f.get('project')=='$PROJECT' and f.get('service')=='$FUNCTION':
        print(json.dumps(f)); break
"
}

# fn_field reads one field out of that view, '' when absent.
fn_field() {
  fn_json | python3 -c "
import json,sys
s=sys.stdin.read().strip()
if not s: sys.exit(0)
f=json.loads(s)
v=f
for k in '$1'.split('.'):
    if not isinstance(v,dict) or k not in v: sys.exit(0)
    v=v[k]
print(v)
"
}

# ---------------------------------------------------------------- preflight
step "Preflight"

command -v "$KANEA" >/dev/null || { printf 'no kanea on PATH\n' >&2; exit 2; }
"$KANEA" version || { printf 'kanea is not runnable\n' >&2; exit 2; }

if ! "$KANEA" functions list >/dev/null 2>&1; then
  printf 'cannot reach kanead — start it before running check H\n' >&2
  exit 2
fi
info "kanead reachable"

# The shim is the one host component this check depends on. Preflight only
# warns about it (checkWasmShim is never fatal), so say it out loud here.
if [ -x /usr/local/lib/kanea/bin/containerd-shim-wasmtime-v1 ]; then
  info "wasmtime shim present"
else
  info "wasmtime shim NOT at the expected path — kanea doctor will say more"
fi

if [ ! -f ../testdata/hello.wasm ]; then
  printf 'no module at ../testdata/hello.wasm — build it first:\n' >&2
  printf '  rustup target add wasm32-wasip2\n' >&2
  printf '  (cd ../modules/hello-http && cargo build --release --target wasm32-wasip2)\n' >&2
  printf '  cp ../modules/hello-http/target/wasm32-wasip2/release/hellohttp.wasm ../testdata/hello.wasm\n' >&2
  exit 2
fi

# ------------------------------------------------------------------ clause 1
step "Clause 1 — a wasi-http function deploys from a spec"

./mkimage.sh --wasm ../testdata/hello.wasm --project "$PROJECT" ||
  { printf 'could not import the module image\n' >&2; exit 2; }

"$KANEA" apply check-h.hcl || { fail "kanea apply"; exit 1; }

# Converged when the function reports a running alloc. 90s covers an image
# unpack and a first task start with room to spare.
deployed=""
for _ in $(seq 1 90); do
  if [ "$(fn_field running)" = "1" ]; then deployed=1; break; fi
  sleep 1
done
if [ -n "$deployed" ]; then
  pass "the function deploys from a spec and reports a running alloc"
else
  fail "the function never reached a running alloc"
  info "$(fn_json)"
fi

# ------------------------------------------------------------------ clause 2
step "Clause 2 — serves through the edge, FQDN mode"

fqdn="$(fn_json | python3 -c "
import json,sys
s=sys.stdin.read().strip()
f=json.loads(s) if s else {}
d=f.get('domains') or []
print(d[0] if d else '')
")"

if [ -z "$fqdn" ]; then
  info "the function has no domain — a node with no base domain is the"
  info "functions-port case, which clause 3 covers"
else
  # Through the edge's own listener, with the Host header the route matches
  # on, so this is the real routing path and not a direct dial.
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${fqdn}:443:127.0.0.1" "https://${fqdn}/" 2>/dev/null)"
  if [ "$code" = "000" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -H "Host: ${fqdn}" "http://127.0.0.1/" 2>/dev/null)"
  fi
  if [ "$code" = "200" ]; then
    pass "the edge serves the function at ${fqdn} (HTTP ${code})"
  else
    fail "the edge answered ${code} at ${fqdn}, want 200"
  fi
fi

# ------------------------------------------------------------------ clause 3
step "Clause 3 — serves through the edge, functions-port mode"

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    "http://127.0.0.1:${FUNCTIONS_PORT}/${PROJECT}/${FUNCTION}/" 2>/dev/null)"
if [ "$code" = "200" ]; then
  pass "the functions port serves /${PROJECT}/${FUNCTION}/ (HTTP ${code})"
else
  fail "the functions port answered ${code}, want 200 (is kanea-edge running with --functions-port ${FUNCTIONS_PORT}?)"
fi

# ------------------------------------------------------------------ clause 4
step "Clause 4 — fires on a matching event"

# The invoker's own counter, which counts event and cron deliveries and not
# the HTTP ones above — so this measures the path the clause is about.
before="$(fn_field invoker.invocations)"; before="${before:-0}"
info "invoker invocations before: ${before}"

# Deploying tripwire emits deploy.succeeded, which is what `hello` triggers on.
# A generation bump is a spec change (PRD v1.26), so this is a real deploy.
"$KANEA" restart "${PROJECT}/tripwire" >/dev/null 2>&1 ||
  info "could not restart tripwire; falling back to re-apply"
"$KANEA" apply check-h.hcl >/dev/null 2>&1

fired=""
for _ in $(seq 1 60); do
  now="$(fn_field invoker.invocations)"; now="${now:-0}"
  if [ "$now" -gt "$before" ] 2>/dev/null; then fired=1; break; fi
  sleep 1
done
if [ -n "$fired" ]; then
  pass "a deploy.succeeded event invoked the function (invocations ${before} -> ${now})"
else
  fail "no invocation followed a deploy.succeeded within 60s"
fi

# ------------------------------------------------------------------ clause 5
step "Clause 5 — fires on a cron tick"

# The schedule is every minute, so a tick is due within 60s; 90 gives the
# boundary room.
before="$(fn_field invoker.invocations)"; before="${before:-0}"
info "waiting up to 90s for a cron tick (schedule is '* * * * *')"
ticked=""
for _ in $(seq 1 90); do
  now="$(fn_field invoker.invocations)"; now="${now:-0}"
  if [ "$now" -gt "$before" ] 2>/dev/null; then ticked=1; break; fi
  sleep 1
done
if [ -n "$ticked" ]; then
  pass "a cron tick invoked the function (invocations ${before} -> ${now})"
else
  fail "no invocation followed a cron tick within 90s"
fi

# ------------------------------------------------------------------ clause 6
step "Clause 6 — invocation rate visible from an east-west call"

# caller dials the VIP once a second and never touches the edge, so a non-zero
# rate here is the datapath's own per-destination counter (§9.1) and not edge
# rps. "No data" renders as absent, never as zero — an absent field is a
# failure of this clause, not a quiet pass.
info "letting caller run for 60s"
sleep 60
rate="$(fn_field invocations_per_minute)"
if [ -z "$rate" ]; then
  fail "no invocation rate is published (absent, not zero — see §9.1)"
  info "under --network netns the datapath publishes no counters; that is the"
  info "documented partial case and this clause needs the ebpf datapath"
else
  ok="$(python3 -c "print(1 if float('$rate') > 0 else 0)" 2>/dev/null || echo 0)"
  if [ "$ok" = "1" ]; then
    pass "east-west invocation rate is visible (${rate}/min)"
  else
    fail "invocation rate is ${rate}/min with caller dialling once a second"
  fi
fi

# ---------------------------------------------------------------- teardown
if [ -z "$KEEP" ]; then
  step "Teardown"
  "$KANEA" stop "${PROJECT}/caller" >/dev/null 2>&1 || true
  "$KANEA" stop "${PROJECT}/tripwire" >/dev/null 2>&1 || true
  "$KANEA" stop "${PROJECT}/${FUNCTION}" >/dev/null 2>&1 || true
  info "services stopped (pass --keep to leave them running)"
fi

# ----------------------------------------------------------------- summary
step "Summary"
printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
cat <<'NOTE'

The criterion's last clause — "pre-v1.39 Store upgrade rolls zero allocs" — is
not scripted here, because it is a property of an upgrade rather than of a
running node, and it cannot be staged after the fact on a node that has already
been upgraded. It is pinned structurally by
TestSpecHashIsUnchangedForASpecWithNoUserOrOwnership, whose comment records that
v1.39's Runtime holds the same line: an empty string with omitempty vanishes
from the hash material, so a pre-v1.39 record and a post-v1.39 runc service
produce identical bytes. To observe it as well as pin it, capture every alloc's
spec_hash from GET /v1/services before upgrading kanead across a v1.39 boundary
and confirm none are replaced afterwards.
NOTE

[ "$FAILS" -eq 0 ] || exit 1
