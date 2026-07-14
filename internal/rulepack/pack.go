// Package rulepack defines the rule-pack schema and loads pack files into
// validated, typed rules. Validation is strict and total: unknown keys,
// bad enum values, uncompilable regexes and contradictory thresholds are
// all rejected up front with file:line positions, and every problem in a
// pack is reported in one pass — a reviewer fixes the file once, not
// error by error.
package rulepack

import (
	"fmt"
	"strings"
)

// Stage says which side of the model boundary a rule inspects.
type Stage string

const (
	StagePre  Stage = "pre"  // inbound: prompts, user input
	StagePost Stage = "post" // outbound: model output
	StageBoth Stage = "both"
)

// Applies reports whether a rule declared for s runs at eval stage at.
func (s Stage) Applies(at Stage) bool {
	return s == StageBoth || s == at
}

// Action is what firing a rule does to the payload. Ordering matters:
// the strongest action across all findings becomes the decision.
type Action string

const (
	ActionFlag   Action = "flag"   // record the finding, let the payload pass
	ActionRedact Action = "redact" // mask the matched span
	ActionBlock  Action = "block"  // reject the whole payload
)

// Rank orders actions by strength (flag < redact < block).
func (a Action) Rank() int {
	switch a {
	case ActionFlag:
		return 1
	case ActionRedact:
		return 2
	case ActionBlock:
		return 3
	}
	return 0
}

// Severity is reporting metadata only; it never changes the decision.
type Severity string

var severities = []Severity{"info", "low", "medium", "high", "critical"}

// Kind selects the rule implementation.
type Kind string

const (
	KindRegex     Kind = "regex"
	KindLexicon   Kind = "lexicon"
	KindThreshold Kind = "threshold"
)

// Rule is one validated guardrail rule. Only the fields for its Kind are
// populated; Line points at the rule's first line in the pack file.
type Rule struct {
	ID       string
	Kind     Kind
	Stage    Stage
	Action   Action
	Severity Severity
	Message  string
	Line     int

	// regex
	Patterns        []string
	CaseInsensitive bool

	// lexicon
	Terms     []string
	TermsFile string
	Match     string // "word" or "substring"

	// regex + lexicon
	Replacement string // mask text for redact rules; default [REDACTED:<id>]

	// threshold
	Metric string
	Min    *float64
	Max    *float64
}

// ReplacementText is the mask written over a redacted span.
func (r *Rule) ReplacementText() string {
	if r.Replacement != "" {
		return r.Replacement
	}
	return "[REDACTED:" + r.ID + "]"
}

// Pack is a fully validated rule pack.
type Pack struct {
	Name        string
	Version     string
	Description string
	Rules       []Rule
	Path        string // source file, "" when decoded from memory
}

// Issue is one validation problem, positioned in the source file.
type Issue struct {
	Line int
	Msg  string
}

// Issues is the error type returned by Load and Decode: every problem
// found, in source order.
type Issues []Issue

func (is Issues) Error() string {
	parts := make([]string, len(is))
	for i, it := range is {
		parts[i] = fmt.Sprintf("line %d: %s", it.Line, it.Msg)
	}
	return strings.Join(parts, "\n")
}
