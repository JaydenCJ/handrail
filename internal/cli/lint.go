// The lint and rules subcommands: static pack review without evaluating
// any payload.
package cli

import (
	"fmt"
	"io"

	"github.com/JaydenCJ/handrail/internal/render"
	"github.com/JaydenCJ/handrail/internal/rulepack"
)

func runLint(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "handrail lint: at least one pack file is required")
		return ExitUsage
	}
	bad := false
	for _, path := range args {
		pack, err := rulepack.Load(path)
		if err != nil {
			bad = true
			if issues, ok := err.(rulepack.Issues); ok {
				for _, is := range issues {
					fmt.Fprintf(stdout, "%s:%d: %s\n", path, is.Line, is.Msg)
				}
				continue
			}
			fmt.Fprintf(stderr, "handrail lint: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stdout, "%s: ok (%s)\n", path, render.Count(len(pack.Rules), "rule"))
	}
	if bad {
		return ExitBreach
	}
	return ExitOK
}

func runRules(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "handrail rules: exactly one pack file is required")
		return ExitUsage
	}
	eng, code := loadEngine(args[0], stderr)
	if code != ExitOK {
		return code
	}
	render.Rules(stdout, eng.Pack())
	return ExitOK
}
