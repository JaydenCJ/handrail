// Tests for the Aho–Corasick matcher: exact byte offsets, overlapping
// and nested terms, case folding, and Unicode inputs — the properties
// lexicon rules build on.
package match

import (
	"reflect"
	"testing"
)

func spans(ms []Match) [][2]int {
	out := make([][2]int, len(ms))
	for i, m := range ms {
		out[i] = [2]int{m.Start, m.End}
	}
	return out
}

func TestFindSingleTerm(t *testing.T) {
	m := New([]string{"secret"}, false)
	got := m.Find("the secret is out")
	if len(got) != 1 || got[0].Start != 4 || got[0].End != 10 || got[0].Term != "secret" {
		t.Fatalf("got %+v", got)
	}
}

func TestFindMultipleOccurrences(t *testing.T) {
	m := New([]string{"ab"}, false)
	got := spans(m.Find("ab ab abab"))
	want := [][2]int{{0, 2}, {3, 5}, {6, 8}, {8, 10}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("spans = %v, want %v", got, want)
	}
}

// The classic nested-terms case: every one of he/she/his/hers must be
// reported, including matches that end at the same position.
func TestOverlappingTermsAllReported(t *testing.T) {
	m := New([]string{"he", "she", "his", "hers"}, false)
	got := m.Find("ushers")
	terms := map[string]bool{}
	for _, x := range got {
		terms[x.Term] = true
	}
	for _, want := range []string{"he", "she", "hers"} {
		if !terms[want] {
			t.Errorf("term %q not found in %+v", want, got)
		}
	}
	if terms["his"] {
		t.Errorf("term \"his\" should not match in ushers")
	}
}

func TestCaseFolding(t *testing.T) {
	m := New([]string{"Denied Term"}, true)
	got := m.Find("this DENIED term and denied TERM")
	if len(got) != 2 {
		t.Fatalf("got %d matches, want 2: %+v", len(got), got)
	}
	if got[0].Term != "Denied Term" {
		t.Errorf("Term should be the original pattern, got %q", got[0].Term)
	}
}

func TestCaseSensitiveWhenNotFolding(t *testing.T) {
	m := New([]string{"Secret"}, false)
	if got := m.Find("secret SECRET"); len(got) != 0 {
		t.Fatalf("case-sensitive matcher matched %+v", got)
	}
	if got := m.Find("Secret"); len(got) != 1 {
		t.Fatalf("exact case should match, got %+v", got)
	}
}

// Offsets must be byte offsets into the original string even when the
// text mixes multi-byte runes with the match, and case folding must not
// desynchronize them.
func TestUnicodeByteOffsets(t *testing.T) {
	m := New([]string{"極秘"}, false)
	text := "これは極秘です"
	got := m.Find(text)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if text[got[0].Start:got[0].End] != "極秘" {
		t.Fatalf("span %d..%d = %q", got[0].Start, got[0].End, text[got[0].Start:got[0].End])
	}
	m = New([]string{"café"}, true)
	text = "au CAFÉ noir"
	got = m.Find(text)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if text[got[0].Start:got[0].End] != "CAFÉ" {
		t.Fatalf("folded span = %q", text[got[0].Start:got[0].End])
	}
}

func TestDeterministicOrder(t *testing.T) {
	m := New([]string{"bb", "b", "abb"}, false)
	first := m.Find("abb abb")
	for i := 0; i < 50; i++ {
		if !reflect.DeepEqual(m.Find("abb abb"), first) {
			t.Fatal("Find is not deterministic across calls")
		}
	}
	// And the documented order: start, then end, then term index.
	for i := 1; i < len(first); i++ {
		if less(first[i], first[i-1]) {
			t.Fatalf("matches out of order: %+v", first)
		}
	}
}

func TestEmptyTermsAndEmptyText(t *testing.T) {
	m := New([]string{"", "x"}, false)
	if got := m.Find(""); len(got) != 0 {
		t.Fatalf("empty text matched %+v", got)
	}
	if got := m.Find("x"); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
}
