# Contributing to Kanea

Thanks for considering it. Kanea is a small, opinionated codebase with an unusual
property: almost every decision in it is written down, with the reasoning
attached. That makes contributing easier than it looks, but it also means the
first step is reading, not writing.

## Before you write any code

1. **[`AGENTS.md`](./AGENTS.md)** is the working guide: conventions, the
   binding constraints, and a long list of decisions a change is most likely to
   trip over. It is addressed to AI agents and humans alike, and it is short
   relative to what it saves you.
2. **[`PRD.md`](./PRD.md)** is the north star. Every architectural decision
   lives there, versioned and amended in place. **Any change that deviates from
   the PRD must amend the PRD first, in the same PR**: bump the version, add an
   amendment note saying what changed and why. This is constraint #1 and it is
   not a formality: it is how the document stays true.
3. Check the **"Deliberately not built"** section of `AGENTS.md` before opening
   a feature PR. Several obvious-looking gaps are decisions with reasoning
   attached, and a PR that "fixes" one will be declined with a pointer to it.

## Development setup

You need Go (the version in [`go.mod`](./go.mod)) and Node (the version in
[`.nvmrc`](./.nvmrc)) for the dashboard. Everything else is a make target:

```bash
make tools      # install dev tools (golangci-lint, gosec, govulncheck, gitleaks)
make build      # build ./bin/kanea
make test       # go test ./... -race -count=1
make check      # ALL gates: vet, test, lint, security, dashboard. CI parity.
```

`make check` is exactly what CI runs. Run it before pushing; a failure there is
a failed PR later, not a failed lint. The eBPF programs are committed as
generated bpf2go output, so `go build` needs no clang: regenerating them
(`make bpf`) does, under the digest-pinned toolchain, and CI verifies the
committed artifacts match.

Note that the runtime targets Linux (kernel ≥ 5.10, cgroups v2, systemd). The
test suite runs fine on macOS; anything that touches containerd, eBPF, or
mounts needs a Linux machine or VM to exercise for real.

## Making changes

- **One logical change per PR.** Reviewability is the constraint; a mixed PR
  will be asked to split.
- **Conventional commits**: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`,
  `test:`, with the package or area in parentheses where it helps
  (`feat(edge): …`). Breaking changes get a `!`.
- **Tests are table-driven**, and the correctness core (`internal/reconciler`
  and `internal/jobspec`) must stay above 80% coverage.
- **Match the codebase's conventions**: dependencies injected (no global
  state), errors wrapped with `%w`, contexts plumbed through blocking calls,
  logging only through `internal/logging`'s `*slog.Logger`. The linters enforce
  most of this; `AGENTS.md` explains the rest.
- The **PR template's checklist** is the binding-constraints list in miniature.
  Fill it in honestly: it is there to catch the violations that compile.

## Security

**Do not open a public issue for a vulnerability.** See
[`SECURITY.md`](./SECURITY.md) for how to report privately, what is in scope,
and what response to expect. Reading
[`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) first will tell you which
assumptions are load-bearing: a report that breaks one of them is exactly the
report worth sending.

## License

Kanea is [Apache-2.0](./LICENSE). By contributing, you agree that your
contributions are licensed under the same terms: the standard
inbound = outbound arrangement, no CLA.
