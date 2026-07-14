// Package match implements a deterministic Aho–Corasick multi-pattern
// matcher used by lexicon rules. One pass over the input finds every
// occurrence of every term, so a 10,000-word deny list costs the same
// single scan as a 10-word one. The automaton works on runes (not bytes)
// so case folding never desynchronizes byte offsets, and reported spans
// are exact byte offsets into the original text.
package match

import "unicode"

// Match is one occurrence of a term. Start and End are byte offsets into
// the text passed to Find; Term is the original (unfolded) pattern.
type Match struct {
	Start int
	End   int
	Term  string
	Index int // index of the term in the slice given to New
}

type node struct {
	next map[rune]int32
	fail int32
	out  []int32 // term indexes ending at this node
}

// Matcher is an immutable compiled automaton, safe for concurrent use.
type Matcher struct {
	nodes    []node
	terms    []string
	termLens []int // rune length per term, precomputed for Find
	foldCase bool
}

// New compiles terms into an automaton. Empty terms are ignored. With
// foldCase, matching is case-insensitive via per-rune simple folding
// (unicode.ToLower), which preserves the one-rune-to-one-rune mapping the
// offset bookkeeping relies on.
func New(terms []string, foldCase bool) *Matcher {
	m := &Matcher{
		nodes:    []node{{next: map[rune]int32{}}},
		terms:    terms,
		termLens: make([]int, len(terms)),
		foldCase: foldCase,
	}
	for i, term := range terms {
		m.termLens[i] = runeCount(term)
	}
	for i, term := range terms {
		if term == "" {
			continue
		}
		cur := int32(0)
		for _, r := range term {
			if foldCase {
				r = unicode.ToLower(r)
			}
			nxt, ok := m.nodes[cur].next[r]
			if !ok {
				m.nodes = append(m.nodes, node{next: map[rune]int32{}})
				nxt = int32(len(m.nodes) - 1)
				m.nodes[cur].next[r] = nxt
			}
			cur = nxt
		}
		m.nodes[cur].out = append(m.nodes[cur].out, int32(i))
	}
	m.buildFailure()
	return m
}

// buildFailure wires the classic BFS failure links and merges output sets
// so every match is reported even when terms nest (e.g. "he" inside "she").
func (m *Matcher) buildFailure() {
	queue := make([]int32, 0, len(m.nodes))
	for _, child := range m.nodes[0].next {
		m.nodes[child].fail = 0
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for r, child := range m.nodes[cur].next {
			queue = append(queue, child)
			f := m.nodes[cur].fail
			for f != 0 {
				if nxt, ok := m.nodes[f].next[r]; ok {
					f = nxt
					goto linked
				}
				f = m.nodes[f].fail
			}
			if nxt, ok := m.nodes[0].next[r]; ok && nxt != child {
				f = nxt
			}
		linked:
			m.nodes[child].fail = f
			m.nodes[child].out = append(m.nodes[child].out, m.nodes[f].out...)
		}
	}
}

// Find returns every occurrence of every term in text, ordered by start
// offset, then end offset, then term index — a total, deterministic order.
func (m *Matcher) Find(text string) []Match {
	var out []Match
	cur := int32(0)
	// starts[k] is the byte offset where the rune k steps back began; a
	// small ring buffer sized to the longest term would do, but term
	// lists are short-lived per call, so a slice keeps the code obvious.
	var starts []int
	for i, r := range text {
		if m.foldCase {
			r = unicode.ToLower(r)
		}
		for {
			if nxt, ok := m.nodes[cur].next[r]; ok {
				cur = nxt
				break
			}
			if cur == 0 {
				break
			}
			cur = m.nodes[cur].fail
		}
		starts = append(starts, i)
		end := i + runeLen(r, text[i:])
		for _, ti := range m.nodes[cur].out {
			start := starts[len(starts)-m.termLens[ti]]
			out = append(out, Match{Start: start, End: end, Term: m.terms[ti], Index: int(ti)})
		}
	}
	sortMatches(out)
	return out
}

// runeLen returns the encoded byte length of the rune at the head of s.
// Folding can change the rune, so measure from the original text.
func runeLen(_ rune, s string) int {
	for i := 1; i < len(s); i++ {
		if s[i]&0xC0 != 0x80 { // not a UTF-8 continuation byte
			return i
		}
	}
	return len(s)
}

func runeCount(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

// sortMatches is an insertion sort: match lists are short and already
// nearly ordered (ends are non-decreasing), so this is both simple and
// fast, and it keeps the package free of sort.Slice's reflection.
func sortMatches(ms []Match) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && less(ms[j], ms[j-1]); j-- {
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}

func less(a, b Match) bool {
	if a.Start != b.Start {
		return a.Start < b.Start
	}
	if a.End != b.End {
		return a.End < b.End
	}
	return a.Index < b.Index
}
