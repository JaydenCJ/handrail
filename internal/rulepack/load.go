// Pack decoding and validation: yamlite node tree -> typed, checked Pack.
package rulepack

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/JaydenCJ/handrail/internal/metric"
	"github.com/JaydenCJ/handrail/internal/yamlite"
)

// idPattern keeps rule ids grep-friendly and safe to embed in masks,
// filenames and JSON without quoting surprises.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Load reads and validates a pack file. Relative terms_file paths resolve
// against the pack file's directory.
func Load(path string) (*Pack, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Decode(src, path)
}

// Decode validates src. path is used for terms_file resolution and may be
// "" (then terms_file must not be used). On failure the error is an
// Issues value listing every problem found.
func Decode(src []byte, path string) (*Pack, error) {
	root, err := yamlite.Parse(src)
	if err != nil {
		if pe, ok := err.(*yamlite.ParseError); ok {
			return nil, Issues{{Line: pe.Line, Msg: pe.Msg}}
		}
		return nil, Issues{{Line: 1, Msg: err.Error()}}
	}
	d := &decoder{path: path}
	pack := d.pack(root)
	if len(d.issues) > 0 {
		sort.SliceStable(d.issues, func(i, j int) bool { return d.issues[i].Line < d.issues[j].Line })
		return nil, d.issues
	}
	return pack, nil
}

type decoder struct {
	path   string
	issues Issues
}

func (d *decoder) errf(line int, format string, args ...any) {
	d.issues = append(d.issues, Issue{Line: line, Msg: fmt.Sprintf(format, args...)})
}

// packKeys and ruleKeys are the closed key sets; anything else is a typo
// and gets rejected with the nearest context.
var packKeys = keySet("pack", "version", "description", "rules")
var ruleKeys = keySet(
	"id", "kind", "stage", "action", "severity", "message",
	"pattern", "patterns", "case_insensitive",
	"terms", "terms_file", "match",
	"replacement",
	"metric", "min", "max",
)

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func (d *decoder) pack(root *yamlite.Node) *Pack {
	if root.Kind != yamlite.Map {
		d.errf(root.Line, "pack file must be a mapping, got a %s", root.Kind)
		return nil
	}
	for _, k := range root.Keys {
		if !packKeys[k] {
			d.errf(root.Fields[k].Line, "unknown pack key %q (want pack, version, description, rules)", k)
		}
	}
	p := &Pack{Path: d.path}
	p.Name = d.str(root, "pack", true)
	if p.Name != "" && !idPattern.MatchString(p.Name) {
		d.errf(root.Get("pack").Line, "pack name %q must match %s", p.Name, idPattern)
	}
	p.Version = d.str(root, "version", false)
	p.Description = d.str(root, "description", false)

	rules := root.Get("rules")
	switch {
	case rules == nil:
		d.errf(root.Line, "pack has no rules")
	case rules.Kind != yamlite.Seq:
		d.errf(rules.Line, "rules must be a sequence, got a %s", rules.Kind)
	case len(rules.Items) == 0:
		d.errf(rules.Line, "rules sequence is empty")
	default:
		seen := map[string]int{}
		for _, item := range rules.Items {
			r := d.rule(item)
			if r == nil {
				continue
			}
			if prev, dup := seen[r.ID]; dup {
				d.errf(r.Line, "duplicate rule id %q (first defined on line %d)", r.ID, prev)
				continue
			}
			seen[r.ID] = r.Line
			p.Rules = append(p.Rules, *r)
		}
	}
	return p
}

func (d *decoder) rule(node *yamlite.Node) *Rule {
	if node.Kind != yamlite.Map {
		d.errf(node.Line, "each rule must be a mapping, got a %s", node.Kind)
		return nil
	}
	for _, k := range node.Keys {
		if !ruleKeys[k] {
			d.errf(node.Fields[k].Line, "unknown rule key %q", k)
		}
	}
	r := &Rule{Line: node.Line}
	r.ID = d.str(node, "id", true)
	if r.ID != "" && !idPattern.MatchString(r.ID) {
		d.errf(node.Get("id").Line, "rule id %q must match %s", r.ID, idPattern)
	}
	label := r.ID
	if label == "" {
		label = fmt.Sprintf("rule at line %d", node.Line)
	}

	r.Kind = Kind(d.enum(node, "kind", true, "regex", "lexicon", "threshold"))
	r.Stage = Stage(d.enumDefault(node, "stage", string(StageBoth), "pre", "post", "both"))
	r.Action = Action(d.enum(node, "action", true, "flag", "redact", "block"))
	r.Severity = Severity(d.enumDefault(node, "severity", "medium",
		"info", "low", "medium", "high", "critical"))
	r.Message = d.str(node, "message", false)
	r.Replacement = d.str(node, "replacement", false)

	switch r.Kind {
	case KindRegex:
		d.regexRule(node, r, label)
		d.rejectKeys(node, label, "terms", "terms_file", "match", "metric", "min", "max")
	case KindLexicon:
		d.lexiconRule(node, r, label)
		d.rejectKeys(node, label, "pattern", "patterns", "metric", "min", "max")
	case KindThreshold:
		d.thresholdRule(node, r, label)
		d.rejectKeys(node, label,
			"pattern", "patterns", "case_insensitive", "terms", "terms_file", "match", "replacement")
	default:
		return nil // kind error already reported
	}
	return r
}

// rejectKeys flags keys that belong to a different rule kind — the most
// common way a pack silently does nothing is a threshold key on a regex
// rule, so this is an error, not a warning.
func (d *decoder) rejectKeys(node *yamlite.Node, label string, keys ...string) {
	for _, k := range keys {
		if v := node.Get(k); v != nil {
			d.errf(v.Line, "rule %q: key %q does not apply to this kind", label, k)
		}
	}
}

func (d *decoder) regexRule(node *yamlite.Node, r *Rule, label string) {
	if p := d.str(node, "pattern", false); p != "" {
		r.Patterns = append(r.Patterns, p)
	}
	if ps := node.Get("patterns"); ps != nil {
		list, err := ps.StringSeq()
		if err != nil {
			d.errf(ps.Line, "rule %q: patterns: %v", label, err)
		}
		r.Patterns = append(r.Patterns, list...)
	}
	if len(r.Patterns) == 0 {
		d.errf(node.Line, "rule %q: regex rule needs pattern or patterns", label)
	}
	r.CaseInsensitive = d.boolDefault(node, "case_insensitive", false)
	for _, p := range r.Patterns {
		rx, err := compilePattern(p, r.CaseInsensitive)
		if err != nil {
			d.errf(node.Line, "rule %q: invalid pattern %q: %v", label, p, err)
			continue
		}
		if rx.MatchString("") {
			d.errf(node.Line, "rule %q: pattern %q matches the empty string", label, p)
		}
	}
}

// CompilePattern is the single place regex flags are decided, shared with
// the engine so validation and execution can never diverge.
func CompilePattern(pattern string, caseInsensitive bool) (*regexp.Regexp, error) {
	return compilePattern(pattern, caseInsensitive)
}

func compilePattern(pattern string, caseInsensitive bool) (*regexp.Regexp, error) {
	if caseInsensitive {
		pattern = "(?i)" + pattern
	}
	return regexp.Compile(pattern)
}

func (d *decoder) lexiconRule(node *yamlite.Node, r *Rule, label string) {
	sourceFailed := false
	if ts := node.Get("terms"); ts != nil {
		list, err := ts.StringSeq()
		if err != nil {
			d.errf(ts.Line, "rule %q: terms: %v", label, err)
			sourceFailed = true
		}
		r.Terms = append(r.Terms, list...)
	}
	r.TermsFile = d.str(node, "terms_file", false)
	if r.TermsFile != "" {
		terms, err := d.loadTermsFile(r.TermsFile)
		if err != nil {
			d.errf(node.Get("terms_file").Line, "rule %q: %v", label, err)
			sourceFailed = true
		}
		r.Terms = append(r.Terms, terms...)
	}
	for _, t := range r.Terms {
		if strings.TrimSpace(t) == "" {
			d.errf(node.Line, "rule %q: lexicon contains an empty term", label)
			break
		}
	}
	if len(r.Terms) == 0 && !sourceFailed {
		d.errf(node.Line, "rule %q: lexicon rule needs terms or terms_file", label)
	}
	r.Match = d.enumDefault(node, "match", "word", "word", "substring")
	// Lexicons default to case-insensitive: deny lists are almost always
	// meant that way, and the pack can opt out explicitly.
	r.CaseInsensitive = d.boolDefault(node, "case_insensitive", true)
}

// loadTermsFile reads one term per line; blank lines and #-comment lines
// are skipped. Relative paths resolve against the pack file's directory.
func (d *decoder) loadTermsFile(rel string) ([]string, error) {
	if d.path == "" {
		return nil, fmt.Errorf("terms_file needs a pack loaded from disk")
	}
	path := rel
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(d.path), rel)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("terms_file: %v", err)
	}
	var terms []string
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		terms = append(terms, ln)
	}
	if len(terms) == 0 {
		return nil, fmt.Errorf("terms_file %q has no terms", rel)
	}
	return terms, nil
}

func (d *decoder) thresholdRule(node *yamlite.Node, r *Rule, label string) {
	r.Metric = d.str(node, "metric", true)
	if r.Metric != "" && !metric.Known(r.Metric) {
		d.errf(node.Get("metric").Line, "rule %q: unknown metric %q (want one of: %s)",
			label, r.Metric, strings.Join(metric.Names, ", "))
	}
	r.Min = d.float(node, "min")
	r.Max = d.float(node, "max")
	if r.Min == nil && r.Max == nil {
		d.errf(node.Line, "rule %q: threshold rule needs min, max, or both", label)
	}
	if r.Min != nil && r.Max != nil && *r.Min > *r.Max {
		d.errf(node.Get("min").Line, "rule %q: min %s is greater than max %s",
			label, metric.Format(*r.Min), metric.Format(*r.Max))
	}
	if r.Action == ActionRedact {
		d.errf(node.Line, "rule %q: threshold rules have no span to redact; use flag or block", label)
	}
}

// --- typed field readers -------------------------------------------------

func (d *decoder) str(node *yamlite.Node, key string, required bool) string {
	v := node.Get(key)
	if v == nil {
		if required {
			d.errf(node.Line, "missing required key %q", key)
		}
		return ""
	}
	s, err := v.Str()
	if err != nil {
		d.errf(v.Line, "%s: %v", key, err)
		return ""
	}
	if required && s == "" {
		d.errf(v.Line, "%s must not be empty", key)
	}
	return s
}

func (d *decoder) enum(node *yamlite.Node, key string, required bool, allowed ...string) string {
	s := d.str(node, key, required)
	if s == "" {
		return ""
	}
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	d.errf(node.Get(key).Line, "%s: invalid value %q (want %s)", key, s, strings.Join(allowed, ", "))
	return ""
}

func (d *decoder) enumDefault(node *yamlite.Node, key, def string, allowed ...string) string {
	if node.Get(key) == nil {
		return def
	}
	if s := d.enum(node, key, false, allowed...); s != "" {
		return s
	}
	return def
}

func (d *decoder) boolDefault(node *yamlite.Node, key string, def bool) bool {
	v := node.Get(key)
	if v == nil {
		return def
	}
	b, err := v.Bool()
	if err != nil {
		d.errf(v.Line, "%s: %v", key, err)
		return def
	}
	return b
}

func (d *decoder) float(node *yamlite.Node, key string) *float64 {
	v := node.Get(key)
	if v == nil {
		return nil
	}
	f, err := v.Float()
	if err != nil {
		d.errf(v.Line, "%s: %v", key, err)
		return nil
	}
	return &f
}
