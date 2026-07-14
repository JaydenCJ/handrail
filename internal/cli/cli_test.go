// End-to-end tests: write real pack, lexicon, and cases files into a
// temp dir, then run the CLI in-process and assert on stdout, stderr,
// and exit codes. No binary build, no network, fully deterministic.
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const packSrc = `pack: demo
version: "2.3"
description: test pack
rules:
  - id: email
    kind: regex
    stage: both
    action: redact
    severity: high
    message: email in payload
    pattern: '[a-z]+@[a-z]+\.[a-z]{2,}'
    replacement: "[EMAIL]"
  - id: deny-word
    kind: lexicon
    stage: pre
    action: block
    terms_file: deny.txt
  - id: too-long
    kind: threshold
    stage: both
    action: flag
    metric: chars
    max: 80
`

// writePack materializes the standard test pack and returns its path.
func writePack(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, "deny.txt", "# deny list\nforbidden\n")
	return write(t, dir, "pack.yaml", packSrc)
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// run executes the CLI in-process with stdin content and returns
// (stdout, stderr, exit code).
func run(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	var out, errBuf strings.Builder
	code := Run(args, strings.NewReader(stdin), &out, &errBuf)
	return out.String(), errBuf.String(), code
}

func TestVersion(t *testing.T) {
	out, _, code := run(t, "", "version")
	if code != ExitOK || out != "handrail 0.1.0\n" {
		t.Fatalf("out = %q, code = %d", out, code)
	}
}

func TestHelpListsCommands(t *testing.T) {
	out, _, code := run(t, "", "help")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	for _, want := range []string{"check", "lint", "test", "rules", "Exit codes"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q", want)
		}
	}
}

func TestUnknownCommandAndNoArgsAreUsageErrors(t *testing.T) {
	_, errOut, code := run(t, "", "chekc")
	if code != ExitUsage || !strings.Contains(errOut, `unknown command "chekc"`) {
		t.Fatalf("errOut = %q, code = %d", errOut, code)
	}
	if _, _, code := run(t, ""); code != ExitUsage {
		t.Fatalf("no-args code = %d", code)
	}
}

func TestCheckTextReport(t *testing.T) {
	pack := writePack(t)
	out, _, code := run(t, "mail sam@example.test now", "check", "--pack", pack)
	if code != ExitOK {
		t.Fatalf("code = %d, out = %q", code, out)
	}
	for _, want := range []string{
		"pack:   demo v2.3 (3 rules)",
		"stage:  pre",
		"REDACT",
		"email",
		"5..21",
		`"sam@example.test"`,
		"decision: redact (1 redact)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q in:\n%s", want, out)
		}
	}
	out, _, code = run(t, "all clear", "check", "--pack", pack)
	if code != ExitOK || !strings.Contains(out, "decision: pass") {
		t.Fatalf("clean input: out = %q, code = %d", out, code)
	}
}

func TestCheckJSONReport(t *testing.T) {
	pack := writePack(t)
	out, _, code := run(t, "mail sam@example.test now", "check", "--pack", pack, "--format", "json")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	var rep struct {
		Tool          string `json:"tool"`
		SchemaVersion int    `json:"schema_version"`
		Pack          string `json:"pack"`
		Decision      string `json:"decision"`
		Findings      []struct {
			Rule  string `json:"rule"`
			Start *int   `json:"start"`
			End   *int   `json:"end"`
		} `json:"findings"`
		Redacted string `json:"redacted"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if rep.Tool != "handrail" || rep.SchemaVersion != 1 || rep.Pack != "demo" {
		t.Errorf("envelope = %+v", rep)
	}
	if rep.Decision != "redact" || len(rep.Findings) != 1 || rep.Findings[0].Rule != "email" {
		t.Errorf("findings = %+v", rep)
	}
	if *rep.Findings[0].Start != 5 || *rep.Findings[0].End != 21 {
		t.Errorf("span = %d..%d", *rep.Findings[0].Start, *rep.Findings[0].End)
	}
	if rep.Redacted != "mail [EMAIL] now" {
		t.Errorf("redacted = %q", rep.Redacted)
	}
}

// Threshold findings must appear in JSON without start/end keys.
func TestCheckJSONThresholdHasNoSpan(t *testing.T) {
	pack := writePack(t)
	long := strings.Repeat("a ", 60)
	out, _, _ := run(t, long, "check", "--pack", pack, "--format", "json")
	if !strings.Contains(out, `"rule": "too-long"`) {
		t.Fatalf("threshold finding missing:\n%s", out)
	}
	if strings.Contains(out, `"start"`) {
		t.Errorf("span keys present on threshold finding:\n%s", out)
	}
}

func TestCheckRedactedPipeMode(t *testing.T) {
	pack := writePack(t)
	out, _, code := run(t, "mail sam@example.test now", "check", "--pack", pack, "--redacted")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	if out != "mail [EMAIL] now" {
		t.Fatalf("stdout must be only the redacted payload, got %q", out)
	}
}

func TestCheckBlockExitsOne(t *testing.T) {
	pack := writePack(t)
	_, _, code := run(t, "this is forbidden", "check", "--pack", pack)
	if code != ExitBreach {
		t.Fatalf("code = %d, want %d", code, ExitBreach)
	}
}

func TestCheckFailOnTightensGate(t *testing.T) {
	pack := writePack(t)
	// Default gate (block): a redact decision passes.
	if _, _, code := run(t, "mail sam@example.test", "check", "--pack", pack); code != ExitOK {
		t.Fatalf("default gate tripped on redact: %d", code)
	}
	// --fail-on redact: the same input now exits 1.
	if _, _, code := run(t, "mail sam@example.test", "check", "--pack", pack, "--fail-on", "redact"); code != ExitBreach {
		t.Fatal("--fail-on redact did not trip")
	}
	// --fail-on flag: even a threshold flag trips.
	long := strings.Repeat("a ", 60)
	if _, _, code := run(t, long, "check", "--pack", pack, "--fail-on", "flag"); code != ExitBreach {
		t.Fatal("--fail-on flag did not trip")
	}
}

// deny-word is stage pre; at post it must not fire.
func TestCheckStageSelectsRules(t *testing.T) {
	pack := writePack(t)
	if _, _, code := run(t, "forbidden", "check", "--pack", pack, "--stage", "pre"); code != ExitBreach {
		t.Fatal("pre stage should block")
	}
	out, _, code := run(t, "forbidden", "check", "--pack", pack, "--stage", "post")
	if code != ExitOK || !strings.Contains(out, "decision: pass") {
		t.Fatalf("post stage fired a pre rule: %q code=%d", out, code)
	}
}

func TestCheckReadsFileArgument(t *testing.T) {
	pack := writePack(t)
	input := write(t, t.TempDir(), "payload.txt", "mail sam@example.test now")
	out, _, code := run(t, "", "check", "--pack", pack, input)
	if code != ExitOK || !strings.Contains(out, "decision: redact") {
		t.Fatalf("out = %q, code = %d", out, code)
	}
}

func TestCheckUsageErrors(t *testing.T) {
	pack := writePack(t)
	cases := [][]string{
		{"check"}, // missing --pack
		{"check", "--pack", pack, "--stage", "x"},  // bad stage
		{"check", "--pack", pack, "--format", "x"}, // bad format
		{"check", "--pack", pack, "--fail-on", "x"},
		{"check", "--pack", pack, "a", "b"}, // two inputs
	}
	for _, args := range cases {
		if _, _, code := run(t, "", args...); code != ExitUsage {
			t.Errorf("%v: code = %d, want %d", args, code, ExitUsage)
		}
	}
	// A pack that cannot be loaded is a runtime error (3), not usage (2).
	if _, _, code := run(t, "x", "check", "--pack", "/nonexistent/pack.yaml"); code != ExitRuntime {
		t.Errorf("missing pack: code = %d, want %d", code, ExitRuntime)
	}
}

func TestLintReportsOK(t *testing.T) {
	pack := writePack(t)
	out, _, code := run(t, "", "lint", pack)
	if code != ExitOK || !strings.Contains(out, "ok (3 rules)") {
		t.Fatalf("out = %q, code = %d", out, code)
	}
	// A one-rule pack reports the singular form.
	single := write(t, t.TempDir(), "one.yaml",
		"pack: one\nrules:\n  - id: a\n    kind: lexicon\n    action: block\n    terms: [x]\n")
	out, _, code = run(t, "", "lint", single)
	if code != ExitOK || !strings.Contains(out, "ok (1 rule)") {
		t.Fatalf("singular: out = %q, code = %d", out, code)
	}
}

func TestLintReportsEveryIssueWithPosition(t *testing.T) {
	dir := t.TempDir()
	bad := write(t, dir, "bad.yaml", "pack: p\nrules:\n  - id: a\n    kind: regex\n    action: flag\n  - id: a\n    kind: lexicon\n    action: block\n    terms: [x]\n")
	out, _, code := run(t, "", "lint", bad)
	if code != ExitBreach {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, bad+":3: ") && !strings.Contains(out, bad+":6: ") {
		t.Errorf("issues not positioned as file:line:\n%s", out)
	}
	if !strings.Contains(out, "needs pattern") || !strings.Contains(out, "duplicate rule id") {
		t.Errorf("missing issues:\n%s", out)
	}
	// One bad pack in a batch fails the whole lint, but good packs still
	// report ok so the author sees the full picture.
	good := writePack(t)
	out, _, code = run(t, "", "lint", good, bad)
	if code != ExitBreach {
		t.Fatalf("mixed lint code = %d", code)
	}
	if !strings.Contains(out, "ok (3 rules)") {
		t.Errorf("good pack result missing:\n%s", out)
	}
}

func TestTestCommandRunsCases(t *testing.T) {
	pack := writePack(t)
	cases := write(t, filepath.Dir(pack), "cases.yaml", `cases:
  - name: email redacts
    input: mail sam@example.test
    expect:
      decision: redact
      rules: [email]
  - name: post lets deny word through
    stage: post
    input: forbidden
    expect:
      decision: pass
`)
	out, _, code := run(t, "", "test", "--pack", pack, cases)
	if code != ExitOK {
		t.Fatalf("code = %d\n%s", code, out)
	}
	if !strings.Contains(out, "PASS  email redacts") || !strings.Contains(out, "2 passed, 0 failed") {
		t.Fatalf("out = %q", out)
	}
}

func TestTestCommandFailureExplainsAndExitsOne(t *testing.T) {
	pack := writePack(t)
	cases := write(t, filepath.Dir(pack), "cases.yaml", `cases:
  - name: wrong expectation
    input: all clear
    expect:
      decision: block
`)
	out, _, code := run(t, "", "test", "--pack", pack, cases)
	if code != ExitBreach {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "FAIL  wrong expectation") ||
		!strings.Contains(out, "expected decision block, got pass") ||
		!strings.Contains(out, "0 passed, 1 failed") {
		t.Fatalf("out = %q", out)
	}
}

func TestRulesAuditTable(t *testing.T) {
	pack := writePack(t)
	out, _, code := run(t, "", "rules", pack)
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	for _, want := range []string{
		"pack demo v2.3 — 3 rules",
		"ID", "KIND", "STAGE", "ACTION",
		"email", "regex", "redact",
		"deny-word", "1 term, word match",
		"too-long", "chars max 80",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rules table missing %q:\n%s", want, out)
		}
	}
}
