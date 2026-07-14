// Tests for the built-in threshold metrics. Each case pins an exact
// value: metrics feed compliance gates, so "roughly right" is not a
// property worth testing.
package metric

import (
	"math"
	"sort"
	"testing"
)

func compute(t *testing.T, name, text string) float64 {
	t.Helper()
	v, err := Compute(name, text)
	if err != nil {
		t.Fatalf("Compute(%q): %v", name, err)
	}
	return v
}

func TestCharsCountsRunesNotBytes(t *testing.T) {
	if got := compute(t, "chars", "日本語abc"); got != 6 {
		t.Errorf("chars = %v, want 6", got)
	}
	if got := compute(t, "bytes", "日本語abc"); got != 12 {
		t.Errorf("bytes = %v, want 12", got)
	}
}

func TestLines(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"one", 1},
		{"one\n", 1}, // trailing newline is not an extra line
		{"one\ntwo", 2},
		{"one\ntwo\n\n", 3},
	}
	for _, c := range cases {
		if got := compute(t, "lines", c.in); got != c.want {
			t.Errorf("lines(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestWords(t *testing.T) {
	if got := compute(t, "words", "  two   words \n"); got != 2 {
		t.Errorf("words = %v, want 2", got)
	}
}

func TestURLsCaseInsensitive(t *testing.T) {
	text := "see https://a.example.test and HTTP://b.example.test plus ftp://ignored"
	if got := compute(t, "urls", text); got != 2 {
		t.Errorf("urls = %v, want 2", got)
	}
}

func TestLongestLine(t *testing.T) {
	if got := compute(t, "longest_line", "ab\n日本語語\nc"); got != 4 {
		t.Errorf("longest_line = %v, want 4 (runes, not bytes)", got)
	}
}

func TestRepeatedCharRun(t *testing.T) {
	if got := compute(t, "repeated_char_run", "aabbbbcc"); got != 4 {
		t.Errorf("repeated_char_run = %v, want 4", got)
	}
	if got := compute(t, "repeated_char_run", ""); got != 0 {
		t.Errorf("repeated_char_run(\"\") = %v, want 0", got)
	}
}

// Ratio metrics: exact fractions, and the empty input is 0, never NaN.
// uppercase_ratio is over letters only, so digits and punctuation cannot
// dilute a SHOUTING detector.
func TestRatios(t *testing.T) {
	cases := []struct {
		metric, in string
		want       float64
	}{
		{"non_ascii_ratio", "ab日本", 0.5},
		{"non_ascii_ratio", "", 0},
		{"uppercase_ratio", "ABC 123!!", 1.0},
		{"uppercase_ratio", "AbCd", 0.5},
		{"uppercase_ratio", "123", 0},
		{"digit_ratio", "a1b2", 0.5},
		{"digit_ratio", "", 0},
	}
	for _, c := range cases {
		if got := compute(t, c.metric, c.in); got != c.want {
			t.Errorf("%s(%q) = %v, want %v", c.metric, c.in, got, c.want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// Four equiprobable symbols: exactly 2 bits.
	if got := compute(t, "shannon_entropy", "abcd"); math.Abs(got-2.0) > 1e-12 {
		t.Errorf("entropy(abcd) = %v, want 2.0", got)
	}
	if got := compute(t, "shannon_entropy", "aaaa"); got != 0 {
		t.Errorf("entropy(aaaa) = %v, want 0", got)
	}
	if got := compute(t, "shannon_entropy", ""); got != 0 {
		t.Errorf("entropy(\"\") = %v, want 0", got)
	}
}

func TestUnknownMetricRejected(t *testing.T) {
	if _, err := Compute("word_count", "x"); err == nil {
		t.Fatal("unknown metric accepted")
	}
}

// Names is the public contract for docs and validation; it must be
// sorted (Known binary-searches it) and every entry must compute.
func TestNamesSortedAndComputable(t *testing.T) {
	if !sort.StringsAreSorted(Names) {
		t.Fatalf("Names not sorted: %v", Names)
	}
	for _, name := range Names {
		if !Known(name) {
			t.Errorf("Known(%q) = false", name)
		}
		if _, err := Compute(name, "sample Text 123\n"); err != nil {
			t.Errorf("Compute(%q): %v", name, err)
		}
	}
	if Known("nope") {
		t.Error("Known(nope) = true")
	}
}

func TestFormat(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{4000, "4000"},
		{0, "0"},
		{0.5, "0.500"},
		{2.0 / 3.0, "0.667"},
	}
	for _, c := range cases {
		if got := Format(c.in); got != c.want {
			t.Errorf("Format(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
