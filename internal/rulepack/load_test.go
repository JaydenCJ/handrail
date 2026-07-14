// Tests for pack decoding and validation. The failure cases assert both
// that a bad pack is rejected and that the issue points at a useful line
// with a useful message — lint quality is a feature, not a nicety.
package rulepack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPack = `pack: demo
version: "1.0"
description: a demo pack
rules:
  - id: find-email
    kind: regex
    action: redact
    pattern: '[a-z]+@[a-z]+\.[a-z]{2,}'
  - id: deny-terms
    kind: lexicon
    action: block
    severity: high
    terms: [alpha, beta]
  - id: too-long
    kind: threshold
    action: flag
    metric: chars
    max: 100
`

func decode(t *testing.T, src string) *Pack {
	t.Helper()
	p, err := Decode([]byte(src), "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return p
}

// decodeFail returns the issues for a pack that must be rejected.
func decodeFail(t *testing.T, src string) Issues {
	t.Helper()
	_, err := Decode([]byte(src), "")
	if err == nil {
		t.Fatal("Decode succeeded, want issues")
	}
	issues, ok := err.(Issues)
	if !ok {
		t.Fatalf("error type %T, want Issues", err)
	}
	return issues
}

func hasIssue(issues Issues, substr string) bool {
	for _, is := range issues {
		if strings.Contains(is.Msg, substr) {
			return true
		}
	}
	return false
}

func TestDecodeValidPack(t *testing.T) {
	p := decode(t, validPack)
	if p.Name != "demo" || p.Version != "1.0" {
		t.Errorf("pack header = %q v%q", p.Name, p.Version)
	}
	if len(p.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(p.Rules))
	}
	if p.Rules[0].Kind != KindRegex || p.Rules[1].Kind != KindLexicon || p.Rules[2].Kind != KindThreshold {
		t.Errorf("kinds = %v %v %v", p.Rules[0].Kind, p.Rules[1].Kind, p.Rules[2].Kind)
	}
}

func TestDefaultsApplied(t *testing.T) {
	p := decode(t, validPack)
	r := p.Rules[0]
	if r.Stage != StageBoth {
		t.Errorf("default stage = %q, want both", r.Stage)
	}
	if r.Severity != "medium" {
		t.Errorf("default severity = %q, want medium", r.Severity)
	}
	if r.CaseInsensitive {
		t.Error("regex rules default to case-sensitive")
	}
	lex := p.Rules[1]
	if !lex.CaseInsensitive {
		t.Error("lexicon rules default to case-insensitive")
	}
	if lex.Match != "word" {
		t.Errorf("default match = %q, want word", lex.Match)
	}
}

func TestReplacementText(t *testing.T) {
	r := Rule{ID: "email"}
	if got := r.ReplacementText(); got != "[REDACTED:email]" {
		t.Errorf("default mask = %q", got)
	}
	r.Replacement = "[EMAIL]"
	if got := r.ReplacementText(); got != "[EMAIL]" {
		t.Errorf("explicit mask = %q", got)
	}
}

// Structural schema violations, one table row per mistake a pack author
// can make, each asserting on the exact lint message.
func TestSchemaViolations(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"missing pack name",
			"rules:\n  - id: a\n    kind: threshold\n    action: flag\n    metric: chars\n    max: 1\n",
			`missing required key "pack"`},
		{"bad rule id",
			strings.Replace(validPack, "id: find-email", "id: Find Email!", 1),
			"must match"},
		{"unknown rule key typo",
			strings.Replace(validPack, "action: redact", "action: redact\n    paterns: [x]", 1),
			`unknown rule key "paterns"`},
		{"unknown kind",
			strings.Replace(validPack, "kind: regex", "kind: regexp", 1),
			`invalid value "regexp"`},
		{"missing action",
			strings.Replace(validPack, "    action: redact\n", "", 1),
			`missing required key "action"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if issues := decodeFail(t, c.src); !hasIssue(issues, c.want) {
				t.Fatalf("issues = %v, want %q", issues, c.want)
			}
		})
	}
}

func TestDuplicateRuleIDCitesFirstDefinition(t *testing.T) {
	src := strings.Replace(validPack, "id: deny-terms", "id: find-email", 1)
	issues := decodeFail(t, src)
	if !hasIssue(issues, "duplicate rule id") {
		t.Fatalf("issues = %v", issues)
	}
	if !hasIssue(issues, "first defined on line 5") {
		t.Fatalf("duplicate issue should cite the first definition: %v", issues)
	}
}

// Regex rules: a pattern is required, must compile, and must not match
// the empty string (which would fire on every offset of every input).
func TestRegexValidation(t *testing.T) {
	issues := decodeFail(t, "pack: p\nrules:\n  - id: a\n    kind: regex\n    action: flag\n")
	if !hasIssue(issues, "needs pattern or patterns") {
		t.Fatalf("issues = %v", issues)
	}
	src := strings.Replace(validPack, `pattern: '[a-z]+@[a-z]+\.[a-z]{2,}'`, "pattern: '[unclosed'", 1)
	if issues := decodeFail(t, src); !hasIssue(issues, "invalid pattern") {
		t.Fatalf("issues = %v", issues)
	}
	src = strings.Replace(validPack, `pattern: '[a-z]+@[a-z]+\.[a-z]{2,}'`, "pattern: 'a*'", 1)
	if issues := decodeFail(t, src); !hasIssue(issues, "matches the empty string") {
		t.Fatalf("issues = %v", issues)
	}
}

func TestLexiconValidation(t *testing.T) {
	issues := decodeFail(t, "pack: p\nrules:\n  - id: a\n    kind: lexicon\n    action: block\n")
	if !hasIssue(issues, "needs terms or terms_file") {
		t.Fatalf("issues = %v", issues)
	}
	issues = decodeFail(t, "pack: p\nrules:\n  - id: a\n    kind: lexicon\n    action: block\n    terms: [ok, '  ']\n")
	if !hasIssue(issues, "empty term") {
		t.Fatalf("issues = %v", issues)
	}
}

func TestTermsFileLoaded(t *testing.T) {
	dir := t.TempDir()
	lex := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(lex, []byte("# comment\nalpha\n\nbeta gamma\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	packPath := filepath.Join(dir, "pack.yaml")
	src := "pack: p\nrules:\n  - id: a\n    kind: lexicon\n    action: block\n    terms_file: deny.txt\n"
	if err := os.WriteFile(packPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(packPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	terms := p.Rules[0].Terms
	if len(terms) != 2 || terms[0] != "alpha" || terms[1] != "beta gamma" {
		t.Fatalf("terms = %v", terms)
	}
}

func TestTermsFileMissingReported(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.yaml")
	src := "pack: p\nrules:\n  - id: a\n    kind: lexicon\n    action: block\n    terms_file: nope.txt\n"
	if err := os.WriteFile(packPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(packPath)
	if err == nil || !strings.Contains(err.Error(), "terms_file") {
		t.Fatalf("err = %v", err)
	}
}

func TestThresholdValidation(t *testing.T) {
	base := "pack: p\nrules:\n  - id: a\n    kind: threshold\n    action: flag\n"
	issues := decodeFail(t, base+"    metric: word_count\n    max: 1\n")
	if !hasIssue(issues, "unknown metric") {
		t.Fatalf("issues = %v", issues)
	}
	issues = decodeFail(t, base+"    metric: chars\n")
	if !hasIssue(issues, "needs min, max, or both") {
		t.Fatalf("issues = %v", issues)
	}
	issues = decodeFail(t, base+"    metric: chars\n    min: 10\n    max: 5\n")
	if !hasIssue(issues, "min 10 is greater than max 5") {
		t.Fatalf("issues = %v", issues)
	}
}

// Threshold findings measure the whole text — there is no span to mask,
// so action: redact on a threshold is a schema error.
func TestThresholdCannotRedact(t *testing.T) {
	issues := decodeFail(t, "pack: p\nrules:\n  - id: a\n    kind: threshold\n    action: redact\n    metric: chars\n    max: 5\n")
	if !hasIssue(issues, "no span to redact") {
		t.Fatalf("issues = %v", issues)
	}
}

func TestCrossKindKeysRejected(t *testing.T) {
	src := strings.Replace(validPack, "pattern: '[a-z]+@[a-z]+\\.[a-z]{2,}'",
		"pattern: 'x+'\n    metric: chars", 1)
	issues := decodeFail(t, src)
	if !hasIssue(issues, `key "metric" does not apply`) {
		t.Fatalf("issues = %v", issues)
	}
}

// All problems come back in one pass, ordered by line, so an author
// fixes a pack once instead of replaying lint error by error.
func TestAllIssuesReportedSortedByLine(t *testing.T) {
	src := "pack: p\nrules:\n  - id: a\n    kind: regex\n    action: flag\n  - id: b\n    kind: lexicon\n    action: nuke\n    terms: [x]\n"
	issues := decodeFail(t, src)
	if len(issues) < 2 {
		t.Fatalf("want at least 2 issues, got %v", issues)
	}
	for i := 1; i < len(issues); i++ {
		if issues[i].Line < issues[i-1].Line {
			t.Fatalf("issues not sorted by line: %v", issues)
		}
	}
	if !hasIssue(issues, "needs pattern") || !hasIssue(issues, `invalid value "nuke"`) {
		t.Fatalf("issues = %v", issues)
	}
}

func TestYAMLParseErrorBecomesIssue(t *testing.T) {
	issues := decodeFail(t, "pack: p\n\tbad: tab\n")
	if len(issues) != 1 || issues[0].Line != 2 {
		t.Fatalf("issues = %v", issues)
	}
}
