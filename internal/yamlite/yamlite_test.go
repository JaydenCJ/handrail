// Tests for the yamlite parser: the strict YAML subset packs are written
// in. Every rejected shape here is a shape a pack author could plausibly
// type, so failure-path tests assert on the reported line number too.
package yamlite

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Node {
	t.Helper()
	n, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return n
}

func mustFail(t *testing.T, src string, wantLine int, wantSubstr string) {
	t.Helper()
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatalf("Parse succeeded, want error containing %q", wantSubstr)
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type %T, want *ParseError", err)
	}
	if pe.Line != wantLine {
		t.Fatalf("error line = %d, want %d (%v)", pe.Line, wantLine, err)
	}
	if !strings.Contains(pe.Msg, wantSubstr) {
		t.Fatalf("error %q does not contain %q", pe.Msg, wantSubstr)
	}
}

func scalar(t *testing.T, n *Node, key string) string {
	t.Helper()
	v := n.Get(key)
	if v == nil {
		t.Fatalf("key %q missing", key)
	}
	s, err := v.Str()
	if err != nil {
		t.Fatalf("key %q: %v", key, err)
	}
	return s
}

func TestParseFlatMapping(t *testing.T) {
	n := mustParse(t, "pack: demo\nversion: \"1.0\"\n")
	if n.Kind != Map {
		t.Fatalf("root kind = %v, want mapping", n.Kind)
	}
	if got := scalar(t, n, "pack"); got != "demo" {
		t.Errorf("pack = %q", got)
	}
	if got := scalar(t, n, "version"); got != "1.0" {
		t.Errorf("version = %q", got)
	}
	if len(n.Keys) != 2 || n.Keys[0] != "pack" || n.Keys[1] != "version" {
		t.Errorf("key order = %v", n.Keys)
	}
}

func TestParseNestedMapping(t *testing.T) {
	n := mustParse(t, "outer:\n  inner: value\n  deeper:\n    leaf: 7\n")
	outer := n.Get("outer")
	if outer.Kind != Map {
		t.Fatalf("outer kind = %v", outer.Kind)
	}
	if got := scalar(t, outer, "inner"); got != "value" {
		t.Errorf("inner = %q", got)
	}
	leaf := outer.Get("deeper").Get("leaf")
	if v, _ := leaf.Int(); v != 7 {
		t.Errorf("leaf = %v", leaf.Value)
	}
}

func TestParseSequenceOfScalars(t *testing.T) {
	n := mustParse(t, "items:\n  - one\n  - two\n  - three\n")
	got, err := n.Get("items").StringSeq()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"one", "two", "three"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("items = %v, want %v", got, want)
		}
	}
}

func TestParseSequenceOfMappings(t *testing.T) {
	src := "rules:\n  - id: a\n    kind: regex\n  - id: b\n    kind: lexicon\n"
	n := mustParse(t, src)
	rules := n.Get("rules")
	if rules.Kind != Seq || len(rules.Items) != 2 {
		t.Fatalf("rules = %+v", rules)
	}
	if got := scalar(t, rules.Items[0], "kind"); got != "regex" {
		t.Errorf("first kind = %q", got)
	}
	if got := scalar(t, rules.Items[1], "id"); got != "b" {
		t.Errorf("second id = %q", got)
	}
}

// YAML allows a sequence under a key at the SAME indent as the key; both
// this and the indented form must parse identically.
func TestParseSequenceAtKeyIndent(t *testing.T) {
	n := mustParse(t, "rules:\n- id: a\n- id: b\n")
	rules := n.Get("rules")
	if rules.Kind != Seq || len(rules.Items) != 2 {
		t.Fatalf("rules = %+v", rules)
	}
	if got := scalar(t, rules.Items[1], "id"); got != "b" {
		t.Errorf("second id = %q", got)
	}
}

func TestParseFlowSequence(t *testing.T) {
	n := mustParse(t, "terms: [alpha, 'b, with comma', \"c #hash\"]\n")
	got, err := n.Get("terms").StringSeq()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "b, with comma", "c #hash"}
	if len(got) != 3 {
		t.Fatalf("terms = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("terms = %v, want %v", got, want)
		}
	}
	// The empty flow sequence is how packs write "no expected rules".
	n = mustParse(t, "terms: []\n")
	if e := n.Get("terms"); e.Kind != Seq || len(e.Items) != 0 {
		t.Fatalf("empty terms = %+v", e)
	}
}

func TestQuotedScalarEscapes(t *testing.T) {
	n := mustParse(t, "msg: 'it''s quoted # not a comment'\n")
	if got := scalar(t, n, "msg"); got != "it's quoted # not a comment" {
		t.Errorf("single-quoted = %q", got)
	}
	n = mustParse(t, `msg: "line1\nline2\ttab \"q\" \\ é"`)
	want := "line1\nline2\ttab \"q\" \\ é"
	if got := scalar(t, n, "msg"); got != want {
		t.Errorf("double-quoted = %q, want %q", got, want)
	}
}

func TestBlockScalarLiteralAndStrip(t *testing.T) {
	n := mustParse(t, "msg: |\n  first line\n  second line\nnext: x\n")
	if got := scalar(t, n, "msg"); got != "first line\nsecond line\n" {
		t.Errorf("msg = %q", got)
	}
	if got := scalar(t, n, "next"); got != "x" {
		t.Errorf("next = %q", got)
	}
	n = mustParse(t, "msg: |-\n  no trailing newline\n")
	if got := scalar(t, n, "msg"); got != "no trailing newline" {
		t.Errorf("|- msg = %q", got)
	}
}

// Inside a literal block, blank lines and lines starting with `#` are
// content, not structure.
func TestBlockScalarKeepsBlanksAndHashes(t *testing.T) {
	n := mustParse(t, "msg: |\n  a\n\n  # not a comment\n")
	if got := scalar(t, n, "msg"); got != "a\n\n# not a comment\n" {
		t.Errorf("msg = %q", got)
	}
}

// Comment handling: full-line and trailing ` #` comments vanish, but a
// `#` with no preceding whitespace stays part of the scalar (YAML rule) —
// this matters for regex patterns like a#b. A leading `---` marker is
// also tolerated.
func TestCommentAndMarkerHandling(t *testing.T) {
	n := mustParse(t, "---\n# header\n\npack: demo  # trailing\n\n# tail\n")
	if got := scalar(t, n, "pack"); got != "demo" {
		t.Errorf("pack = %q", got)
	}
	n = mustParse(t, "pattern: a#b\n")
	if got := scalar(t, n, "pattern"); got != "a#b" {
		t.Errorf("pattern = %q", got)
	}
}

// Values containing colons (URLs, prose) must not be mis-split as keys.
func TestColonInsidePlainValue(t *testing.T) {
	n := mustParse(t, "url: https://example.test/path\nnote: warning: check twice\n")
	if got := scalar(t, n, "url"); got != "https://example.test/path" {
		t.Errorf("url = %q", got)
	}
	if got := scalar(t, n, "note"); got != "warning: check twice" {
		t.Errorf("note = %q", got)
	}
}

// A sequence item that is a phrase with `: ` (like a lexicon term) stays
// a scalar because the would-be key is not a plain word.
func TestSequenceItemPhraseWithColon(t *testing.T) {
	n := mustParse(t, "terms:\n  - note to self: remember\n")
	got, err := n.Get("terms").StringSeq()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "note to self: remember" {
		t.Fatalf("terms = %v", got)
	}
}

func TestLineNumbersRecorded(t *testing.T) {
	n := mustParse(t, "# comment\npack: demo\nrules:\n  - id: a\n")
	if got := n.Get("pack").Line; got != 2 {
		t.Errorf("pack line = %d, want 2", got)
	}
	if got := n.Get("rules").Items[0].Line; got != 4 {
		t.Errorf("first rule line = %d, want 4", got)
	}
}

// Every rejected document shape a pack author could plausibly type, with
// the exact line the error must point at.
func TestRejectedDocuments(t *testing.T) {
	cases := []struct {
		name string
		src  string
		line int
		msg  string
	}{
		{"tab indent", "pack: demo\n\tkind: regex\n", 2, "tab in indentation"},
		{"duplicate key", "pack: demo\npack: again\n", 2, "duplicate key"},
		{"unterminated single quote", "msg: 'never closed\n", 1, "unterminated single-quoted"},
		{"unterminated double quote", "msg: \"never closed\n", 1, "unterminated double-quoted"},
		{"empty document", "", 1, "empty document"},
		{"comments only", "# only comments\n\n", 1, "empty document"},
		{"key without value", "pack: demo\nrules:\n", 2, "key has no value"},
		{"unexpected indent", "a: 1\n    b: 2\n", 2, "unexpected indentation"},
		{"unclosed flow sequence", "terms: [a, b\n", 1, "not closed"},
		{"sequence item without value", "rules:\n  -\n", 2, "sequence item has no value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustFail(t, c.src, c.line, c.msg)
		})
	}
}

func TestTypedAccessors(t *testing.T) {
	n := mustParse(t, "b: true\ni: 42\nf: 2.5\ns: hello\n")
	if v, err := n.Get("b").Bool(); err != nil || v != true {
		t.Errorf("Bool = %v, %v", v, err)
	}
	if v, err := n.Get("i").Int(); err != nil || v != 42 {
		t.Errorf("Int = %v, %v", v, err)
	}
	if v, err := n.Get("f").Float(); err != nil || v != 2.5 {
		t.Errorf("Float = %v, %v", v, err)
	}
	if _, err := n.Get("s").Bool(); err == nil {
		t.Error("Bool on non-bool scalar should fail")
	}
	if _, err := n.Get("s").Int(); err == nil {
		t.Error("Int on non-int scalar should fail")
	}
}
