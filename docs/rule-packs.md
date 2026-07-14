# Rule pack reference

A rule pack is one YAML file: header keys plus a `rules` sequence. This
page is the complete schema — if a key is not listed here, `handrail lint`
rejects it.

## Pack header

| Key | Required | Effect |
|---|---|---|
| `pack` | yes | pack name, `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | no | free-form version string, echoed in reports |
| `description` | no | one line shown nowhere but the file itself |
| `rules` | yes | non-empty sequence of rules |

## Common rule keys

| Key | Required | Default | Effect |
|---|---|---|---|
| `id` | yes | — | unique per pack, `[a-z0-9][a-z0-9._-]{0,63}` |
| `kind` | yes | — | `regex`, `lexicon`, or `threshold` |
| `action` | yes | — | `flag` (record), `redact` (mask span), `block` (reject payload) |
| `stage` | no | `both` | `pre` (inbound), `post` (outbound), or `both` |
| `severity` | no | `medium` | `info`, `low`, `medium`, `high`, `critical` — reporting only |
| `message` | no | — | human explanation attached to every finding |

The decision for a payload is the strongest action fired:
`block` > `redact` > `flag` > `pass`. Severity never changes the decision.

## `kind: regex`

| Key | Required | Default | Effect |
|---|---|---|---|
| `pattern` | one of | — | a single RE2 pattern |
| `patterns` | one of | — | a list of RE2 patterns (findings deduped per span) |
| `case_insensitive` | no | `false` | prepend `(?i)` to every pattern |
| `replacement` | no | `[REDACTED:<id>]` | mask text when `action: redact` |

Patterns are Go `regexp` (RE2): linear-time by construction, so no pack
can introduce catastrophic backtracking. Patterns that match the empty
string are rejected at lint time. Quote patterns in single quotes so YAML
never eats a backslash.

## `kind: lexicon`

| Key | Required | Default | Effect |
|---|---|---|---|
| `terms` | one of | — | inline list of terms/phrases |
| `terms_file` | one of | — | sidecar file, one term per line, `#` comments; path relative to the pack file |
| `match` | no | `word` | `word` (Unicode word boundaries) or `substring` |
| `case_insensitive` | no | `true` | per-rune simple case folding |
| `replacement` | no | `[REDACTED:<id>]` | mask text when `action: redact` |

All terms of a rule compile into one Aho–Corasick automaton: a 10,000-term
deny list costs the same single pass as a 10-term one. Use
`match: substring` for CJK text, where there are no word separators.

## `kind: threshold`

| Key | Required | Default | Effect |
|---|---|---|---|
| `metric` | yes | — | one of the metrics below |
| `min` / `max` | at least one | — | fire when value < min or > max |

Threshold findings measure the whole payload, so they carry no span and
cannot use `action: redact` (lint rejects it).

| Metric | Meaning |
|---|---|
| `bytes` / `chars` | payload size in bytes / runes |
| `lines` / `words` | logical lines / whitespace-separated words |
| `longest_line` | longest line, in runes |
| `urls` | count of `http://` and `https://` occurrences |
| `repeated_char_run` | longest run of one repeated rune (flood detector) |
| `non_ascii_ratio` | non-ASCII runes over all runes, 0–1 |
| `uppercase_ratio` | upper-case letters over all letters, 0–1 |
| `digit_ratio` | digit runes over all runes, 0–1 |
| `shannon_entropy` | bits per rune; ≳5 suggests encoded blobs or secrets |

## Case files (`handrail test`)

```yaml
cases:
  - name: email is redacted        # unique per file
    stage: pre                     # pre (default) or post
    input: mail sam@example.test
    expect:
      decision: redact             # pass | flag | redact | block
      rules: [email-address]       # optional: exact set of fired rule ids
```

## The YAML subset

Packs are parsed by a built-in strict YAML subset parser (this is how the
binary stays dependency-free). Supported: block mappings and sequences,
plain / `'single'` / `"double"` scalars, flow sequences of scalars
(`[a, b]`), literal blocks (`|`, `|-`), comments, and a leading `---`.
Not supported: anchors, aliases, tags, flow mappings, folded scalars
(`>`), and multi-document streams. Keys must be plain words; every error
comes with a line number. Indent with spaces (tabs are rejected), and
quote any scalar containing `: ` or ` #`.
