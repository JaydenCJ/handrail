// Tests for the evaluation engine: spans, stages, decisions, ordering,
// and determinism. Packs are built from YAML source through the real
// decoder so these tests exercise exactly what a user's pack exercises.
package engine

import (
	"reflect"
	"strings"
	"testing"

	"github.com/JaydenCJ/handrail/internal/rulepack"
)

// compileSrc builds an engine from pack YAML, failing the test on any
// validation or compile error.
func compileSrc(t *testing.T, src string) *Engine {
	t.Helper()
	p, err := rulepack.Decode([]byte(src), "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	e, err := Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return e
}

const piiSrc = `pack: pii
rules:
  - id: email
    kind: regex
    action: redact
    severity: high
    message: email found
    pattern: '[a-z]+@[a-z]+\.[a-z]{2,}'
    replacement: "[EMAIL]"
  - id: ssn-like
    kind: regex
    action: block
    pattern: '\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
`

func TestRegexFindingSpanAndExcerpt(t *testing.T) {
	e := compileSrc(t, piiSrc)
	res := e.Eval("write to sam@example.test today", rulepack.StagePre)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Rule != "email" || f.Start != 9 || f.End != 25 {
		t.Fatalf("finding = %+v", f)
	}
	if f.Excerpt != "sam@example.test" {
		t.Errorf("excerpt = %q", f.Excerpt)
	}
	if f.Message != "email found" || f.Severity != "high" {
		t.Errorf("metadata = %+v", f)
	}
}

func TestRegexCaseInsensitiveFlag(t *testing.T) {
	e := compileSrc(t, "pack: p\nrules:\n  - id: word\n    kind: regex\n    action: flag\n    case_insensitive: true\n    pattern: 'classified'\n")
	res := e.Eval("This is CLASSIFIED material", rulepack.StagePre)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// Two patterns on one rule that hit the same span must yield one finding.
func TestSiblingPatternsDedupeSpans(t *testing.T) {
	src := "pack: p\nrules:\n  - id: key\n    kind: regex\n    action: flag\n    patterns: ['AKIA[0-9A-Z]{16}', 'AKIA[0-9A-Z]+']\n"
	e := compileSrc(t, src)
	res := e.Eval("AKIAIOSFODNN7EXAMPLE", rulepack.StagePre)
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %+v", res.Findings)
	}
}

const lexiconSrc = `pack: p
rules:
  - id: deny
    kind: lexicon
    action: block
    terms: [pass, "internal only"]
`

func TestLexiconWordBoundary(t *testing.T) {
	e := compileSrc(t, lexiconSrc)
	if res := e.Eval("the compass points north", rulepack.StagePre); len(res.Findings) != 0 {
		t.Fatalf("matched inside a word: %+v", res.Findings)
	}
	res := e.Eval("shall not pass!", rulepack.StagePre)
	if len(res.Findings) != 1 || res.Findings[0].Excerpt != "pass" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	// Multi-word phrases match across the boundary rules too, and the
	// finding quotes the (folded) term as evidence.
	res = e.Eval("marked INTERNAL ONLY, do not share", rulepack.StagePre)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Findings[0].Detail != `term "internal only"` {
		t.Errorf("detail = %q", res.Findings[0].Detail)
	}
}

func TestLexiconSubstringMode(t *testing.T) {
	src := strings.Replace(lexiconSrc, "terms: [pass, \"internal only\"]",
		"terms: [pass]\n    match: substring", 1)
	e := compileSrc(t, src)
	res := e.Eval("the compass points north", rulepack.StagePre)
	if len(res.Findings) != 1 {
		t.Fatalf("substring mode should match inside words: %+v", res.Findings)
	}
}

func TestLexiconCaseSensitiveOptOut(t *testing.T) {
	src := strings.Replace(lexiconSrc, "terms: [pass, \"internal only\"]",
		"terms: [Pass]\n    case_insensitive: false", 1)
	e := compileSrc(t, src)
	if res := e.Eval("pass here", rulepack.StagePre); len(res.Findings) != 0 {
		t.Fatalf("case-sensitive lexicon matched wrong case: %+v", res.Findings)
	}
	if res := e.Eval("Pass here", rulepack.StagePre); len(res.Findings) != 1 {
		t.Fatal("exact case should match")
	}
}

// Word boundaries must be Unicode-aware: letters adjacent to the match
// suppress it, punctuation and CJK-to-ASCII transitions do not.
func TestLexiconUnicodeBoundary(t *testing.T) {
	src := "pack: p\nrules:\n  - id: deny\n    kind: lexicon\n    action: block\n    terms: [secret]\n"
	e := compileSrc(t, src)
	if res := e.Eval("secretë leaked", rulepack.StagePre); len(res.Findings) != 0 {
		t.Fatalf("accented letter should count as word rune: %+v", res.Findings)
	}
	if res := e.Eval("これはsecretです", rulepack.StagePre); len(res.Findings) != 0 {
		t.Fatalf("CJK letters should count as word runes: %+v", res.Findings)
	}
	if res := e.Eval("(secret)", rulepack.StagePre); len(res.Findings) != 1 {
		t.Fatal("punctuation is a boundary")
	}
}

const thresholdSrc = `pack: p
rules:
  - id: too-long
    kind: threshold
    action: block
    metric: chars
    max: 10
  - id: too-short
    kind: threshold
    action: flag
    metric: words
    min: 2
`

func TestThresholdMaxAndDetail(t *testing.T) {
	e := compileSrc(t, thresholdSrc)
	res := e.Eval("this is much longer than ten characters", rulepack.StagePre)
	var hit *Finding
	for i := range res.Findings {
		if res.Findings[i].Rule == "too-long" {
			hit = &res.Findings[i]
		}
	}
	if hit == nil {
		t.Fatalf("too-long did not fire: %+v", res.Findings)
	}
	if hit.Detail != "metric chars = 39 (max 10)" {
		t.Errorf("detail = %q", hit.Detail)
	}
	if hit.HasSpan() {
		t.Errorf("threshold finding must be span-less: %+v", hit)
	}
}

func TestThresholdMinAndQuietInsideBounds(t *testing.T) {
	e := compileSrc(t, thresholdSrc)
	res := e.Eval("hi", rulepack.StagePre)
	if len(res.Findings) != 1 || res.Findings[0].Rule != "too-short" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Findings[0].Detail != "metric words = 1 (min 2)" {
		t.Errorf("detail = %q", res.Findings[0].Detail)
	}
	if res := e.Eval("two words", rulepack.StagePre); len(res.Findings) != 0 {
		t.Fatalf("in-bounds input fired: %+v", res.Findings)
	}
}

func TestStageFiltering(t *testing.T) {
	src := `pack: p
rules:
  - id: pre-only
    kind: lexicon
    stage: pre
    action: flag
    terms: [alpha]
  - id: post-only
    kind: lexicon
    stage: post
    action: flag
    terms: [alpha]
  - id: both-stages
    kind: lexicon
    stage: both
    action: flag
    terms: [alpha]
`
	e := compileSrc(t, src)
	pre := e.Eval("alpha", rulepack.StagePre)
	if got := ruleIDs(pre.Findings); !reflect.DeepEqual(got, []string{"both-stages", "pre-only"}) {
		t.Errorf("pre findings = %v", got)
	}
	post := e.Eval("alpha", rulepack.StagePost)
	if got := ruleIDs(post.Findings); !reflect.DeepEqual(got, []string{"both-stages", "post-only"}) {
		t.Errorf("post findings = %v", got)
	}
}

func ruleIDs(fs []Finding) []string {
	seen := map[string]bool{}
	var ids []string
	for i := range fs {
		if !seen[fs[i].Rule] {
			seen[fs[i].Rule] = true
			ids = append(ids, fs[i].Rule)
		}
	}
	// findings for the same span are ordered by rule id already; make
	// the expectation independent of span order anyway.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

func TestDecisionPrecedence(t *testing.T) {
	src := `pack: p
rules:
  - id: noisy
    kind: lexicon
    action: flag
    terms: [alpha]
  - id: masker
    kind: lexicon
    action: redact
    terms: [beta]
  - id: gate
    kind: lexicon
    action: block
    terms: [gamma]
`
	e := compileSrc(t, src)
	cases := []struct {
		in   string
		want Decision
	}{
		{"nothing here", Pass},
		{"alpha", Flag},
		{"alpha beta", Redact},
		{"alpha beta gamma", Block},
		{"gamma", Block},
	}
	for _, c := range cases {
		if got := e.Eval(c.in, rulepack.StagePre).Decision; got != c.want {
			t.Errorf("Eval(%q).Decision = %s, want %s", c.in, got, c.want)
		}
	}
}

// The documented total order: span findings by (start, end, rule id),
// then span-less threshold findings by rule id.
func TestFindingOrder(t *testing.T) {
	src := `pack: p
rules:
  - id: zz-word
    kind: lexicon
    action: flag
    terms: [alpha]
  - id: aa-word
    kind: lexicon
    action: flag
    terms: [alpha]
  - id: b-limit
    kind: threshold
    action: flag
    metric: chars
    max: 3
  - id: a-limit
    kind: threshold
    action: flag
    metric: chars
    max: 3
`
	e := compileSrc(t, src)
	res := e.Eval("alpha then alpha", rulepack.StagePre)
	got := make([]string, len(res.Findings))
	for i, f := range res.Findings {
		got[i] = f.Rule
	}
	want := []string{"aa-word", "zz-word", "aa-word", "zz-word", "a-limit", "b-limit"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestEvalDeterministic(t *testing.T) {
	e := compileSrc(t, piiSrc)
	in := "sam@example.test and 123-45-6789 twice: pam@example.test"
	first := e.Eval(in, rulepack.StagePre)
	for i := 0; i < 25; i++ {
		if !reflect.DeepEqual(e.Eval(in, rulepack.StagePre), first) {
			t.Fatal("Eval is not deterministic")
		}
	}
}

func TestExcerptTruncated(t *testing.T) {
	src := "pack: p\nrules:\n  - id: run\n    kind: regex\n    action: flag\n    pattern: 'x+'\n"
	e := compileSrc(t, src)
	res := e.Eval(strings.Repeat("x", 200), rulepack.StagePre)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	ex := res.Findings[0].Excerpt
	if !strings.HasSuffix(ex, "…") || len([]rune(ex)) != excerptLimit+1 {
		t.Fatalf("excerpt = %q (%d runes)", ex, len([]rune(ex)))
	}
	// The span still covers the full match even though the quote is cut.
	if res.Findings[0].End-res.Findings[0].Start != 200 {
		t.Errorf("span = %+v", res.Findings[0])
	}
}

func TestRedactDefaultAndCustomMask(t *testing.T) {
	src := `pack: p
rules:
  - id: email
    kind: regex
    action: redact
    pattern: '[a-z]+@[a-z]+\.[a-z]{2,}'
    replacement: "[EMAIL]"
  - id: token
    kind: regex
    action: redact
    pattern: 'tok_[0-9]+'
`
	e := compileSrc(t, src)
	res := e.Eval("mail sam@example.test key tok_123 end", rulepack.StagePre)
	want := "mail [EMAIL] key [REDACTED:token] end"
	if res.Redacted != want {
		t.Fatalf("redacted = %q, want %q", res.Redacted, want)
	}
}

// Overlapping redaction spans merge into one mask; masking twice would
// corrupt offsets or leak the secret's length structure.
func TestRedactOverlappingSpansMerged(t *testing.T) {
	src := `pack: p
rules:
  - id: digits
    kind: regex
    action: redact
    pattern: '[0-9]{4,}'
  - id: card
    kind: regex
    action: redact
    pattern: '4[0-9]{3} [0-9]{4}'
    replacement: "[CARD]"
`
	e := compileSrc(t, src)
	res := e.Eval("card 4111 1111 x", rulepack.StagePre)
	// digits hits 4111 and 1111; card hits "4111 1111"; all overlap into
	// one interval whose mask comes from the leftmost finding.
	want := "card [REDACTED:digits] x"
	if res.Redacted != want {
		t.Fatalf("redacted = %q, want %q", res.Redacted, want)
	}
}

// Only redact-action spans mask; block rejects the payload whole and a
// clean input round-trips byte-identically.
func TestOnlyRedactActionsMask(t *testing.T) {
	e := compileSrc(t, piiSrc)
	res := e.Eval("ssn 123-45-6789", rulepack.StagePre)
	if res.Decision != Block {
		t.Fatalf("decision = %s", res.Decision)
	}
	if res.Redacted != "ssn 123-45-6789" {
		t.Fatalf("block findings must not mask: %q", res.Redacted)
	}
	in := "nothing sensitive here"
	if res := e.Eval(in, rulepack.StagePre); res.Redacted != in || res.Decision != Pass {
		t.Fatalf("clean input: %+v", res)
	}
}

// CJK text has no word separators, so packs use match: substring there;
// the mask must land on exact byte boundaries of the multibyte term.
func TestRedactMultibyteBoundaries(t *testing.T) {
	src := "pack: p\nrules:\n  - id: name\n    kind: lexicon\n    action: redact\n    match: substring\n    terms: [山田太郎]\n    replacement: \"[NAME]\"\n"
	e := compileSrc(t, src)
	res := e.Eval("担当は山田太郎です", rulepack.StagePre)
	if res.Redacted != "担当は[NAME]です" {
		t.Fatalf("redacted = %q", res.Redacted)
	}
}
