// Package packtest runs a pack's own test cases: a YAML file of inputs
// with expected decisions and expected fired rules. Rule packs are code,
// and code that gates production traffic deserves fixtures that travel
// with it — `handrail test` makes a pack change reviewable by its cases,
// not by trust.
package packtest

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/JaydenCJ/handrail/internal/engine"
	"github.com/JaydenCJ/handrail/internal/rulepack"
	"github.com/JaydenCJ/handrail/internal/yamlite"
)

// Case is one expectation: run Input at Stage, expect Decision and
// (optionally) exactly the set of rule ids in Rules to fire.
type Case struct {
	Name     string
	Stage    rulepack.Stage
	Input    string
	Decision engine.Decision
	Rules    []string // nil = don't check which rules fired
	Line     int
}

// Suite is a parsed cases file.
type Suite struct {
	Cases []Case
}

// Load reads and validates a cases file.
func Load(path string) (*Suite, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Decode(src)
}

// Decode validates a cases document.
func Decode(src []byte) (*Suite, error) {
	root, err := yamlite.Parse(src)
	if err != nil {
		return nil, err
	}
	if root.Kind != yamlite.Map {
		return nil, fmt.Errorf("line %d: cases file must be a mapping with a `cases` key", root.Line)
	}
	for _, k := range root.Keys {
		if k != "cases" {
			return nil, fmt.Errorf("line %d: unknown key %q (want cases)", root.Fields[k].Line, k)
		}
	}
	list := root.Get("cases")
	if list == nil || list.Kind != yamlite.Seq || len(list.Items) == 0 {
		return nil, fmt.Errorf("line %d: cases must be a non-empty sequence", root.Line)
	}
	s := &Suite{}
	seen := map[string]bool{}
	for _, item := range list.Items {
		c, err := decodeCase(item)
		if err != nil {
			return nil, err
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("line %d: duplicate case name %q", c.Line, c.Name)
		}
		seen[c.Name] = true
		s.Cases = append(s.Cases, c)
	}
	return s, nil
}

func decodeCase(node *yamlite.Node) (Case, error) {
	c := Case{Line: node.Line, Stage: rulepack.StagePre}
	if node.Kind != yamlite.Map {
		return c, fmt.Errorf("line %d: each case must be a mapping", node.Line)
	}
	for _, k := range node.Keys {
		v := node.Fields[k]
		var err error
		switch k {
		case "name":
			c.Name, err = v.Str()
		case "stage":
			var s string
			if s, err = v.Str(); err == nil {
				if s != "pre" && s != "post" {
					err = fmt.Errorf("stage must be pre or post, got %q", s)
				}
				c.Stage = rulepack.Stage(s)
			}
		case "input":
			c.Input, err = v.Str()
		case "expect":
			err = decodeExpect(v, &c)
		default:
			err = fmt.Errorf("unknown case key %q", k)
		}
		if err != nil {
			return c, fmt.Errorf("line %d: %v", v.Line, err)
		}
	}
	if c.Name == "" {
		return c, fmt.Errorf("line %d: case needs a name", node.Line)
	}
	if node.Get("input") == nil {
		return c, fmt.Errorf("line %d: case %q needs an input", node.Line, c.Name)
	}
	if c.Decision == "" {
		return c, fmt.Errorf("line %d: case %q needs expect.decision", node.Line, c.Name)
	}
	return c, nil
}

func decodeExpect(node *yamlite.Node, c *Case) error {
	if node.Kind != yamlite.Map {
		return fmt.Errorf("expect must be a mapping")
	}
	for _, k := range node.Keys {
		v := node.Fields[k]
		switch k {
		case "decision":
			s, err := v.Str()
			if err != nil {
				return err
			}
			switch engine.Decision(s) {
			case engine.Pass, engine.Flag, engine.Redact, engine.Block:
				c.Decision = engine.Decision(s)
			default:
				return fmt.Errorf("decision must be pass, flag, redact, or block; got %q", s)
			}
		case "rules":
			list, err := v.StringSeq()
			if err != nil {
				return fmt.Errorf("rules: %v", err)
			}
			if list == nil {
				list = []string{}
			}
			c.Rules = list
		default:
			return fmt.Errorf("unknown expect key %q", k)
		}
	}
	return nil
}

// Outcome is one executed case.
type Outcome struct {
	Case   Case
	Passed bool
	Reason string // human-readable mismatch description when !Passed
}

// Run executes every case against the engine, in file order.
func Run(e *engine.Engine, s *Suite) []Outcome {
	out := make([]Outcome, 0, len(s.Cases))
	for _, c := range s.Cases {
		res := e.Eval(c.Input, c.Stage)
		o := Outcome{Case: c, Passed: true}
		if res.Decision != c.Decision {
			o.Passed = false
			o.Reason = fmt.Sprintf("expected decision %s, got %s", c.Decision, res.Decision)
		} else if c.Rules != nil {
			got := firedRules(res.Findings)
			want := uniqueSorted(c.Rules)
			if !equalStrings(got, want) {
				o.Passed = false
				o.Reason = fmt.Sprintf("expected rules [%s], got [%s]",
					strings.Join(want, ", "), strings.Join(got, ", "))
			}
		}
		out = append(out, o)
	}
	return out
}

func firedRules(fs []engine.Finding) []string {
	var ids []string
	for i := range fs {
		ids = append(ids, fs[i].Rule)
	}
	return uniqueSorted(ids)
}

func uniqueSorted(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
