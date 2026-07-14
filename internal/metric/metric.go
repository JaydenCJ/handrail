// Package metric computes the built-in text measurements that threshold
// rules compare against. Every metric is a pure function of the input
// string — no locale, no clock, no environment — so a pack evaluates to
// the same findings on every machine, which is the whole point of an
// auditable guardrail.
package metric

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Names lists every supported metric, sorted, for error messages and the
// docs table. Kept in sync with Compute by TestNamesMatchesCompute.
var Names = []string{
	"bytes",
	"chars",
	"digit_ratio",
	"lines",
	"longest_line",
	"non_ascii_ratio",
	"repeated_char_run",
	"shannon_entropy",
	"uppercase_ratio",
	"urls",
	"words",
}

// Known reports whether name is a supported metric.
func Known(name string) bool {
	i := sort.SearchStrings(Names, name)
	return i < len(Names) && Names[i] == name
}

// Compute evaluates metric name against text. All counts are rune-based
// unless the name says otherwise; ratios are in [0, 1].
func Compute(name, text string) (float64, error) {
	switch name {
	case "bytes":
		return float64(len(text)), nil
	case "chars":
		return float64(utf8.RuneCountInString(text)), nil
	case "lines":
		return float64(countLines(text)), nil
	case "words":
		return float64(len(strings.Fields(text))), nil
	case "urls":
		return float64(countURLs(text)), nil
	case "longest_line":
		return float64(longestLine(text)), nil
	case "repeated_char_run":
		return float64(longestRun(text)), nil
	case "non_ascii_ratio":
		return nonASCIIRatio(text), nil
	case "uppercase_ratio":
		return uppercaseRatio(text), nil
	case "digit_ratio":
		return digitRatio(text), nil
	case "shannon_entropy":
		return shannonEntropy(text), nil
	}
	return 0, fmt.Errorf("unknown metric %q (want one of: %s)", name, strings.Join(Names, ", "))
}

// countLines counts logical lines; a trailing newline does not open an
// extra empty line, and the empty string has zero lines.
func countLines(text string) int {
	if text == "" {
		return 0
	}
	n := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		n++
	}
	return n
}

// countURLs counts http:// and https:// scheme occurrences,
// case-insensitively. Deliberately scheme-anchored: bare domains are too
// ambiguous to count deterministically.
func countURLs(text string) int {
	lower := strings.ToLower(text)
	return strings.Count(lower, "http://") + strings.Count(lower, "https://")
}

func longestLine(text string) int {
	best := 0
	for _, ln := range strings.Split(text, "\n") {
		if n := utf8.RuneCountInString(ln); n > best {
			best = n
		}
	}
	return best
}

// longestRun is the length of the longest run of one repeated rune —
// a cheap detector for "aaaaaaaa…" style flood inputs.
func longestRun(text string) int {
	best, cur := 0, 0
	var prev rune = -1
	for _, r := range text {
		if r == prev {
			cur++
		} else {
			cur = 1
			prev = r
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

func nonASCIIRatio(text string) float64 {
	total, non := 0, 0
	for _, r := range text {
		total++
		if r > unicode.MaxASCII {
			non++
		}
	}
	return ratio(non, total)
}

// uppercaseRatio is upper-case letters over all letters (not all runes),
// so "HELLO 123" is 1.0 — the natural reading of a SHOUTING detector.
func uppercaseRatio(text string) float64 {
	letters, upper := 0, 0
	for _, r := range text {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	return ratio(upper, letters)
}

func digitRatio(text string) float64 {
	total, digits := 0, 0
	for _, r := range text {
		total++
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return ratio(digits, total)
}

// shannonEntropy is bits per rune over the rune frequency distribution.
// High-entropy strings (≳4.5 bits) are a strong signal for pasted secrets
// and encoded blobs.
func shannonEntropy(text string) float64 {
	freq := map[rune]int{}
	total := 0
	for _, r := range text {
		freq[r]++
		total++
	}
	if total == 0 {
		return 0
	}
	h := 0.0
	for _, c := range freq {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

func ratio(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole)
}

// Format renders a metric value the way findings display it: integers
// without a decimal point, everything else with three decimals. The
// output is deterministic for a given float64.
func Format(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.3f", v)
}
