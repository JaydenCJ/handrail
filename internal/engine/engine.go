// Package engine compiles a validated rule pack into an immutable
// evaluator and runs text through it. Evaluation is a pure function:
// (pack, stage, text) -> findings, decision, redacted text. Findings come
// back in a total order (start offset, end offset, rule id; span-less
// threshold findings last), so the same input always produces
// byte-identical output — the property every downstream audit log
// depends on.
package engine

import (
	"fmt"
	"regexp"
	"sort"
	"unicode"
	"unicode/utf8"

	"github.com/JaydenCJ/handrail/internal/match"
	"github.com/JaydenCJ/handrail/internal/metric"
	"github.com/JaydenCJ/handrail/internal/rulepack"
)

// excerptLimit caps how much matched text a finding quotes, in runes.
// Long enough to identify the hit, short enough that a finding never
// re-leaks a whole document into the audit log.
const excerptLimit = 60

// Finding is one rule hit. Start/End are byte offsets into the evaluated
// text; both are -1 for threshold findings, which measure the whole text.
type Finding struct {
	Rule     string
	Kind     rulepack.Kind
	Severity rulepack.Severity
	Action   rulepack.Action
	Message  string
	Start    int
	End      int
	Excerpt  string // matched text, truncated to excerptLimit runes
	Detail   string // e.g. `metric chars = 5321 (max 4000)` or `term "…"`

	mask string // resolved replacement text, set for redact-action spans
}

// HasSpan reports whether the finding points at a concrete text span.
func (f *Finding) HasSpan() bool { return f.Start >= 0 }

// Decision is the overall verdict: the strongest action fired, or "pass".
type Decision string

const (
	Pass   Decision = "pass"
	Flag   Decision = "flag"
	Redact Decision = "redact"
	Block  Decision = "block"
)

// Result is one evaluation. Redacted always holds the safe-to-forward
// text: the input with every redact-rule span masked (identical to the
// input when nothing was redacted).
type Result struct {
	Stage    rulepack.Stage
	Findings []Finding
	Decision Decision
	Redacted string
}

// compiledRule pairs a rule with its ready-to-run machinery.
type compiledRule struct {
	rule     *rulepack.Rule
	regexps  []*regexp.Regexp // kind regex
	matcher  *match.Matcher   // kind lexicon
	wordOnly bool
}

// Engine is an immutable compiled pack, safe for concurrent Eval calls.
type Engine struct {
	pack  *rulepack.Pack
	rules []compiledRule
}

// Pack returns the pack this engine was compiled from.
func (e *Engine) Pack() *rulepack.Pack { return e.pack }

// Compile turns a validated pack into an engine. Compilation cannot fail
// on a pack that passed rulepack validation; the error return guards
// against callers constructing packs by hand.
func Compile(p *rulepack.Pack) (*Engine, error) {
	e := &Engine{pack: p}
	for i := range p.Rules {
		r := &p.Rules[i]
		c := compiledRule{rule: r}
		switch r.Kind {
		case rulepack.KindRegex:
			for _, pat := range r.Patterns {
				rx, err := rulepack.CompilePattern(pat, r.CaseInsensitive)
				if err != nil {
					return nil, fmt.Errorf("rule %q: pattern %q: %w", r.ID, pat, err)
				}
				c.regexps = append(c.regexps, rx)
			}
		case rulepack.KindLexicon:
			c.matcher = match.New(r.Terms, r.CaseInsensitive)
			c.wordOnly = r.Match != "substring"
		case rulepack.KindThreshold:
			if !metric.Known(r.Metric) {
				return nil, fmt.Errorf("rule %q: unknown metric %q", r.ID, r.Metric)
			}
		default:
			return nil, fmt.Errorf("rule %q: unknown kind %q", r.ID, r.Kind)
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// Eval runs text through every rule that applies at stage.
func (e *Engine) Eval(text string, stage rulepack.Stage) Result {
	var findings []Finding
	for i := range e.rules {
		c := &e.rules[i]
		if !c.rule.Stage.Applies(stage) {
			continue
		}
		switch c.rule.Kind {
		case rulepack.KindRegex:
			findings = append(findings, evalRegex(c, text)...)
		case rulepack.KindLexicon:
			findings = append(findings, evalLexicon(c, text)...)
		case rulepack.KindThreshold:
			if f := evalThreshold(c.rule, text); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	orderFindings(findings)
	return Result{
		Stage:    stage,
		Findings: findings,
		Decision: decide(findings),
		Redacted: redact(text, findings),
	}
}

func evalRegex(c *compiledRule, text string) []Finding {
	var out []Finding
	seen := map[[2]int]bool{} // dedupe identical spans across sibling patterns
	for _, rx := range c.regexps {
		for _, loc := range rx.FindAllStringIndex(text, -1) {
			key := [2]int{loc[0], loc[1]}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, spanFinding(c.rule, text, loc[0], loc[1], ""))
		}
	}
	return out
}

func evalLexicon(c *compiledRule, text string) []Finding {
	var out []Finding
	seen := map[[2]int]bool{} // overlapping terms can produce duplicate spans
	for _, m := range c.matcher.Find(text) {
		if c.wordOnly && !isWordBounded(text, m.Start, m.End) {
			continue
		}
		key := [2]int{m.Start, m.End}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, spanFinding(c.rule, text, m.Start, m.End, fmt.Sprintf("term %q", m.Term)))
	}
	return out
}

// isWordBounded rejects matches embedded inside a larger word, so a
// lexicon entry "pass" does not fire on "compass". Boundaries are
// letters, digits and underscore, Unicode-aware.
func isWordBounded(text string, start, end int) bool {
	if start > 0 {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); isWordRune(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); isWordRune(r) {
			return false
		}
	}
	return true
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func evalThreshold(r *rulepack.Rule, text string) *Finding {
	v, err := metric.Compute(r.Metric, text)
	if err != nil {
		return nil // unreachable after validation; fail closed to no finding
	}
	var bound string
	switch {
	case r.Max != nil && v > *r.Max:
		bound = fmt.Sprintf("max %s", metric.Format(*r.Max))
	case r.Min != nil && v < *r.Min:
		bound = fmt.Sprintf("min %s", metric.Format(*r.Min))
	default:
		return nil
	}
	return &Finding{
		Rule:     r.ID,
		Kind:     r.Kind,
		Severity: r.Severity,
		Action:   r.Action,
		Message:  r.Message,
		Start:    -1,
		End:      -1,
		Detail:   fmt.Sprintf("metric %s = %s (%s)", r.Metric, metric.Format(v), bound),
	}
}

func spanFinding(r *rulepack.Rule, text string, start, end int, detail string) Finding {
	return Finding{
		Rule:     r.ID,
		Kind:     r.Kind,
		Severity: r.Severity,
		Action:   r.Action,
		Message:  r.Message,
		Start:    start,
		End:      end,
		Excerpt:  truncate(text[start:end], excerptLimit),
		Detail:   detail,
		mask:     r.ReplacementText(),
	}
}

func truncate(s string, limit int) string {
	n := 0
	for i := range s {
		n++
		if n > limit {
			return s[:i] + "…"
		}
	}
	return s
}

// orderFindings imposes the documented total order: span findings by
// (start, end, rule id), then span-less threshold findings by rule id.
func orderFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := &fs[i], &fs[j]
		if a.HasSpan() != b.HasSpan() {
			return a.HasSpan()
		}
		if !a.HasSpan() {
			return a.Rule < b.Rule
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End < b.End
		}
		return a.Rule < b.Rule
	})
}

func decide(fs []Finding) Decision {
	best := 0
	for i := range fs {
		if r := fs[i].Action.Rank(); r > best {
			best = r
		}
	}
	switch best {
	case 3:
		return Block
	case 2:
		return Redact
	case 1:
		return Flag
	}
	return Pass
}
