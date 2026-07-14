// The check subcommand: evaluate one payload against a pack and gate on
// the decision.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/JaydenCJ/handrail/internal/engine"
	"github.com/JaydenCJ/handrail/internal/render"
	"github.com/JaydenCJ/handrail/internal/rulepack"
)

func runCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	packPath := fs.String("pack", "", "rule pack file (required)")
	stage := fs.String("stage", "pre", "evaluation stage: pre or post")
	format := fs.String("format", "text", "output format: text or json")
	redacted := fs.Bool("redacted", false, "print only the redacted payload to stdout")
	failOn := fs.String("fail-on", "block", "weakest decision that exits 1: flag, redact, or block")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK // asking for help is not a usage error
		}
		return ExitUsage
	}
	if *packPath == "" {
		fmt.Fprintln(stderr, "handrail check: --pack is required")
		return ExitUsage
	}
	if *stage != "pre" && *stage != "post" {
		fmt.Fprintf(stderr, "handrail check: --stage must be pre or post, got %q\n", *stage)
		return ExitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "handrail check: --format must be text or json, got %q\n", *format)
		return ExitUsage
	}
	gate := rulepack.Action(*failOn)
	if gate.Rank() == 0 {
		fmt.Fprintf(stderr, "handrail check: --fail-on must be flag, redact, or block, got %q\n", *failOn)
		return ExitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "handrail check: at most one input file")
		return ExitUsage
	}

	eng, code := loadEngine(*packPath, stderr)
	if code != ExitOK {
		return code
	}
	input, err := readInput(fs.Arg(0), stdin)
	if err != nil {
		fmt.Fprintf(stderr, "handrail check: %v\n", err)
		return ExitRuntime
	}

	res := eng.Eval(input, rulepack.Stage(*stage))
	switch {
	case *redacted:
		// Pipe mode: stdout carries the payload, nothing else.
		fmt.Fprint(stdout, res.Redacted)
	case *format == "json":
		if err := render.JSON(stdout, eng.Pack(), &res); err != nil {
			fmt.Fprintf(stderr, "handrail check: %v\n", err)
			return ExitRuntime
		}
	default:
		render.Text(stdout, eng.Pack(), &res, len(input))
	}
	if decisionRank(res.Decision) >= gate.Rank() {
		return ExitBreach
	}
	return ExitOK
}

func decisionRank(d engine.Decision) int {
	return rulepack.Action(d).Rank() // pass -> 0, others align with Action
}

// loadEngine loads, validates, and compiles a pack, reporting issues in
// the same file:line format lint uses.
func loadEngine(path string, stderr io.Writer) (*engine.Engine, int) {
	pack, err := rulepack.Load(path)
	if err != nil {
		if issues, ok := err.(rulepack.Issues); ok {
			for _, is := range issues {
				fmt.Fprintf(stderr, "%s:%d: %s\n", path, is.Line, is.Msg)
			}
			return nil, ExitRuntime
		}
		fmt.Fprintf(stderr, "handrail: %v\n", err)
		return nil, ExitRuntime
	}
	eng, err := engine.Compile(pack)
	if err != nil {
		fmt.Fprintf(stderr, "handrail: %v\n", err)
		return nil, ExitRuntime
	}
	return eng, ExitOK
}

// readInput reads the payload from a file, or stdin when path is "" / "-".
func readInput(path string, stdin io.Reader) (string, error) {
	if path == "" || path == "-" {
		data, err := io.ReadAll(stdin)
		return string(data), err
	}
	data, err := os.ReadFile(path)
	return string(data), err
}
