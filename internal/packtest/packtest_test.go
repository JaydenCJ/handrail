// Tests for the pack self-test runner: cases decode strictly, run in
// file order, and mismatches explain exactly what diverged.
package packtest

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/handrail/internal/engine"
	"github.com/JaydenCJ/handrail/internal/rulepack"
)

func testEngine(t *testing.T) *engine.Engine {
	t.Helper()
	src := `pack: p
rules:
  - id: email
    kind: regex
    action: redact
    pattern: '[a-z]+@[a-z]+\.[a-z]{2,}'
  - id: deny
    kind: lexicon
    stage: post
    action: block
    terms: [alpha]
`
	p, err := rulepack.Decode([]byte(src), "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

const validCases = `cases:
  - name: clean passes
    input: nothing here
    expect:
      decision: pass
      rules: []
  - name: email fires
    input: mail sam@example.test
    expect:
      decision: redact
      rules: [email]
  - name: deny only at post
    stage: post
    input: alpha
    expect:
      decision: block
`

func TestDecodeAndRunSuite(t *testing.T) {
	suite, err := Decode([]byte(validCases))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(suite.Cases) != 3 {
		t.Fatalf("cases = %d", len(suite.Cases))
	}
	if suite.Cases[0].Stage != rulepack.StagePre {
		t.Errorf("default stage = %q, want pre", suite.Cases[0].Stage)
	}
	outcomes := Run(testEngine(t), suite)
	for _, o := range outcomes {
		if !o.Passed {
			t.Errorf("case %q failed: %s", o.Case.Name, o.Reason)
		}
	}
}

func TestDecisionMismatchExplained(t *testing.T) {
	src := "cases:\n  - name: wrong\n    input: alpha\n    expect:\n      decision: block\n"
	suite, err := Decode([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	// deny is stage post; at the default pre stage nothing fires.
	out := Run(testEngine(t), suite)
	if out[0].Passed {
		t.Fatal("case should fail")
	}
	if out[0].Reason != "expected decision block, got pass" {
		t.Errorf("reason = %q", out[0].Reason)
	}
}

// The rules expectation is set-based: order and duplicates in the case
// file must not matter, but a missing or extra rule must.
func TestRulesExpectationIsASet(t *testing.T) {
	e := testEngine(t)
	src := "cases:\n  - name: dup order\n    input: mail sam@example.test and pam@example.test\n    expect:\n      decision: redact\n      rules: [email, email]\n"
	suite, _ := Decode([]byte(src))
	if out := Run(e, suite); !out[0].Passed {
		t.Fatalf("set semantics: %s", out[0].Reason)
	}
	src = "cases:\n  - name: extra\n    input: mail sam@example.test\n    expect:\n      decision: redact\n      rules: [email, deny]\n"
	suite, _ = Decode([]byte(src))
	out := Run(e, suite)
	if out[0].Passed {
		t.Fatal("extra expected rule should fail")
	}
	if !strings.Contains(out[0].Reason, "expected rules [deny, email], got [email]") {
		t.Errorf("reason = %q", out[0].Reason)
	}
}

func TestCaseRequiredFields(t *testing.T) {
	bad := []struct {
		src  string
		want string
	}{
		{"cases:\n  - input: x\n    expect:\n      decision: pass\n", "needs a name"},
		{"cases:\n  - name: n\n    expect:\n      decision: pass\n", "needs an input"},
		{"cases:\n  - name: n\n    input: x\n", "needs expect.decision"},
		{"cases:\n  - name: n\n    input: x\n    expect:\n      decision: maybe\n", "decision must be"},
		{"cases:\n  - name: n\n    stage: both\n    input: x\n    expect:\n      decision: pass\n", "stage must be pre or post"},
	}
	for _, c := range bad {
		if _, err := Decode([]byte(c.src)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Decode(%q) err = %v, want %q", c.src, err, c.want)
		}
	}
}

func TestUnknownCaseKeyRejected(t *testing.T) {
	src := "cases:\n  - name: n\n    inptu: typo\n    expect:\n      decision: pass\n"
	if _, err := Decode([]byte(src)); err == nil || !strings.Contains(err.Error(), `unknown case key "inptu"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplicateCaseNameRejected(t *testing.T) {
	src := "cases:\n  - name: same\n    input: x\n    expect:\n      decision: pass\n  - name: same\n    input: y\n    expect:\n      decision: pass\n"
	if _, err := Decode([]byte(src)); err == nil || !strings.Contains(err.Error(), "duplicate case name") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptySuiteRejected(t *testing.T) {
	if _, err := Decode([]byte("cases: []\n")); err == nil {
		t.Fatal("empty cases accepted")
	}
}
