# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- YAML rule packs with three rule kinds: `regex` (RE2, single or multiple
  patterns, case-insensitive flag), `lexicon` (inline terms or sidecar
  `terms_file`, word-boundary or substring matching, Unicode-aware case
  folding), and `threshold` (11 built-in metrics with `min`/`max` bounds).
- A built-in strict YAML subset parser (block mappings/sequences, quoted
  and literal scalars, flow sequences, comments) with a line number on
  every node — this is how the binary ships with zero dependencies.
- Strict pack validation: closed key sets, enum checking, regex
  compilation, empty-match rejection, cross-kind key rejection, duplicate
  ids — every problem reported in one pass as `file:line: message`.
- Deterministic evaluation engine: findings in a documented total order,
  decision = strongest action (`block` > `redact` > `flag` > `pass`),
  span masking with overlap merging and per-rule replacement text.
- Aho–Corasick multi-pattern matcher for lexicons: one pass over the
  input regardless of deny-list size, exact byte offsets under case
  folding and multibyte text.
- `check` subcommand with text and JSON (`schema_version: 1`) reports,
  `--redacted` pipe mode, `--stage pre|post`, and a `--fail-on` exit-code
  gate; `lint` for pack review; `test` for pack-shipped case files;
  `rules` for a one-screen audit table.
- Threshold metrics: bytes, chars, lines, words, urls, longest_line,
  repeated_char_run, non_ascii_ratio, uppercase_ratio, digit_ratio,
  shannon_entropy.
- Example packs (`pii-basics`, `prompt-hygiene`), a shared injection
  lexicon, pack self-test cases, and a runnable pre/post gate script.
- 90 deterministic offline tests (unit + in-process CLI integration)
  and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/handrail/releases/tag/v0.1.0
