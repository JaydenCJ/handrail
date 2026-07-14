// Span masking for redact-action findings.
package engine

import (
	"sort"
	"strings"

	"github.com/JaydenCJ/handrail/internal/rulepack"
)

// redact rebuilds text with every redact-rule span replaced by its rule's
// mask. Overlapping or nested spans are merged into one interval and
// masked once, using the mask of the interval's first (leftmost, then
// lowest rule id) finding — masking the same bytes twice would corrupt
// offsets and could leak length information about the secret.
func redact(text string, findings []Finding) string {
	type span struct {
		start, end int
		mask       string
	}
	var spans []span
	for i := range findings {
		f := &findings[i]
		if f.Action != rulepack.ActionRedact || !f.HasSpan() {
			continue
		}
		spans = append(spans, span{f.Start, f.End, f.mask})
	}
	if len(spans) == 0 {
		return text
	}
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})
	// Merge overlaps, keeping the first span's mask.
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start < last.end {
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		merged = append(merged, s)
	}
	var b strings.Builder
	b.Grow(len(text))
	prev := 0
	for _, s := range merged {
		b.WriteString(text[prev:s.start])
		b.WriteString(s.mask)
		prev = s.end
	}
	b.WriteString(text[prev:])
	return b.String()
}
