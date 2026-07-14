// Package render turns evaluation results into the CLI's three output
// shapes: a human terminal report, stable JSON (schema_version 1) for
// pipelines and SIEM ingestion, and the redacted payload itself. All
// output is deterministic: same result in, same bytes out.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/handrail/internal/engine"
	"github.com/JaydenCJ/handrail/internal/metric"
	"github.com/JaydenCJ/handrail/internal/rulepack"
	"github.com/JaydenCJ/handrail/internal/version"
)

// Text writes the human-readable report.
func Text(w io.Writer, pack *rulepack.Pack, res *engine.Result, inputLen int) {
	name := pack.Name
	if pack.Version != "" {
		name += " v" + pack.Version
	}
	fmt.Fprintf(w, "pack:   %s (%s)\n", name, Count(len(pack.Rules), "rule"))
	fmt.Fprintf(w, "stage:  %s\n", res.Stage)
	fmt.Fprintf(w, "input:  %d bytes\n\n", inputLen)
	if len(res.Findings) == 0 {
		fmt.Fprintf(w, "no findings\n\ndecision: pass\n")
		return
	}
	fmt.Fprintf(w, "findings (%d)\n", len(res.Findings))
	for i := range res.Findings {
		f := &res.Findings[i]
		loc := "whole input"
		if f.HasSpan() {
			loc = fmt.Sprintf("%d..%d", f.Start, f.End)
		}
		fmt.Fprintf(w, "  %-6s  %-8s  %-24s %s", strings.ToUpper(string(f.Action)), f.Severity, f.Rule, loc)
		if f.Excerpt != "" {
			fmt.Fprintf(w, "  %q", f.Excerpt)
		}
		fmt.Fprintln(w)
		if f.Detail != "" {
			fmt.Fprintf(w, "          %s\n", f.Detail)
		}
		if f.Message != "" {
			fmt.Fprintf(w, "          %s\n", f.Message)
		}
	}
	fmt.Fprintf(w, "\ndecision: %s (%s)\n", res.Decision, tally(res.Findings))
}

// Count formats "n noun" with naive English pluralization: "1 rule",
// "3 rules". Every noun the CLI counts pluralizes with a plain "s".
func Count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// tally summarizes findings by action, strongest first, e.g.
// "1 block, 2 redact, 1 flag".
func tally(fs []engine.Finding) string {
	counts := map[rulepack.Action]int{}
	for i := range fs {
		counts[fs[i].Action]++
	}
	var parts []string
	for _, a := range []rulepack.Action{rulepack.ActionBlock, rulepack.ActionRedact, rulepack.ActionFlag} {
		if counts[a] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[a], a))
		}
	}
	return strings.Join(parts, ", ")
}

// jsonFinding mirrors engine.Finding with a stable field order and
// span-less thresholds encoded as absent start/end.
type jsonFinding struct {
	Rule     string `json:"rule"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Start    *int   `json:"start,omitempty"`
	End      *int   `json:"end,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Message  string `json:"message,omitempty"`
}

type jsonReport struct {
	Tool          string        `json:"tool"`
	ToolVersion   string        `json:"tool_version"`
	SchemaVersion int           `json:"schema_version"`
	Pack          string        `json:"pack"`
	PackVersion   string        `json:"pack_version,omitempty"`
	Stage         string        `json:"stage"`
	Decision      string        `json:"decision"`
	Findings      []jsonFinding `json:"findings"`
	Redacted      string        `json:"redacted"`
}

// JSON writes the machine-readable report. The schema is versioned and
// findings keep the engine's deterministic order.
func JSON(w io.Writer, pack *rulepack.Pack, res *engine.Result) error {
	rep := jsonReport{
		Tool:          "handrail",
		ToolVersion:   version.Version,
		SchemaVersion: 1,
		Pack:          pack.Name,
		PackVersion:   pack.Version,
		Stage:         string(res.Stage),
		Decision:      string(res.Decision),
		Findings:      []jsonFinding{},
		Redacted:      res.Redacted,
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		jf := jsonFinding{
			Rule:     f.Rule,
			Kind:     string(f.Kind),
			Severity: string(f.Severity),
			Action:   string(f.Action),
			Excerpt:  f.Excerpt,
			Detail:   f.Detail,
			Message:  f.Message,
		}
		if f.HasSpan() {
			start, end := f.Start, f.End
			jf.Start, jf.End = &start, &end
		}
		rep.Findings = append(rep.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// Rules writes the audit table for `handrail rules`: one line per rule
// with its compiled essentials, so a reviewer can sign off on what a
// pack actually does without reading YAML.
func Rules(w io.Writer, pack *rulepack.Pack) {
	name := pack.Name
	if pack.Version != "" {
		name += " v" + pack.Version
	}
	fmt.Fprintf(w, "pack %s — %s\n\n", name, Count(len(pack.Rules), "rule"))
	fmt.Fprintf(w, "%-24s %-10s %-5s %-7s %-9s %s\n", "ID", "KIND", "STAGE", "ACTION", "SEVERITY", "DETAIL")
	for i := range pack.Rules {
		r := &pack.Rules[i]
		fmt.Fprintf(w, "%-24s %-10s %-5s %-7s %-9s %s\n",
			r.ID, r.Kind, r.Stage, r.Action, r.Severity, ruleDetail(r))
	}
}

func ruleDetail(r *rulepack.Rule) string {
	switch r.Kind {
	case rulepack.KindRegex:
		if len(r.Patterns) == 1 {
			return fmt.Sprintf("1 pattern: %s", r.Patterns[0])
		}
		return Count(len(r.Patterns), "pattern")
	case rulepack.KindLexicon:
		return fmt.Sprintf("%s, %s match", Count(len(r.Terms), "term"), r.Match)
	case rulepack.KindThreshold:
		var parts []string
		if r.Min != nil {
			parts = append(parts, "min "+metric.Format(*r.Min))
		}
		if r.Max != nil {
			parts = append(parts, "max "+metric.Format(*r.Max))
		}
		return fmt.Sprintf("%s %s", r.Metric, strings.Join(parts, ", "))
	}
	return ""
}
