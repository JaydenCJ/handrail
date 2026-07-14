# Contributing to handrail

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — the module has zero dependencies.

```bash
git clone https://github.com/JaydenCJ/handrail && cd handrail
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives every subcommand against
the shipped example packs and a fabricated broken pack, asserting on real
output and exit codes; it must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (90 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (the engine never touches the filesystem — only `rulepack`
   and the CLI do I/O).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in
  the PR. The built-in YAML subset parser exists precisely to avoid one.
- No network calls, ever, and no telemetry. handrail must keep working
  in an air-gapped deployment.
- Determinism is the contract: identical input must produce
  byte-identical findings, orderings, and reports on every machine.
  Anything that could break that (maps without sorted iteration, locale
  dependence, wall-clock reads) is a bug.
- Schema changes are lint changes: a new rule key lands together with
  its validation, a line in `docs/rule-packs.md`, and tests for both the
  accepting and the rejecting path.
- Code comments and doc comments are written in English.

## Reporting bugs

Include the output of `handrail version`, the pack (or a minimized
version of it), the exact input payload, the full command, and the report
you got versus the one you expected. For lint bugs, the pack file alone
usually suffices — every issue should point at a line.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
