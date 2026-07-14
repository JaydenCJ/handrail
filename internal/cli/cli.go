// Package cli implements the handrail command-line interface. Run takes
// argv and two writers and returns an exit code, so the whole surface is
// testable in-process without building a binary.
package cli

import (
	"fmt"
	"io"

	"github.com/JaydenCJ/handrail/internal/version"
)

// Exit codes. Documented in the README; `check` uses ExitBreach as its
// machine-readable verdict, so gates can be a one-line shell condition.
const (
	ExitOK      = 0
	ExitBreach  = 1 // check gate tripped, lint found issues, test cases failed
	ExitUsage   = 2
	ExitRuntime = 3
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdin, stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	case "test":
		return runTest(args[1:], stdout, stderr)
	case "rules":
		return runRules(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "handrail %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "handrail: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `handrail — deterministic pre/post guardrails from YAML rule packs

Usage:
  handrail check --pack PACK [--stage pre|post] [--format text|json]
                 [--redacted] [--fail-on flag|redact|block] [FILE|-]
  handrail lint  PACK...
  handrail test  --pack PACK CASES...
  handrail rules PACK
  handrail version

Commands:
  check   evaluate input (file or stdin) against a pack
  lint    validate pack files and report every problem with line numbers
  test    run a pack's own case files against it
  rules   print the audit table of a pack's compiled rules
  version print the handrail version

Exit codes: 0 ok, 1 gate breach / lint issues / failed cases,
2 usage error, 3 runtime error.
`)
}
