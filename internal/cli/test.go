// The test subcommand: run a pack's own case files against it.
package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/JaydenCJ/handrail/internal/packtest"
)

func runTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	packPath := fs.String("pack", "", "rule pack file (required)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK // asking for help is not a usage error
		}
		return ExitUsage
	}
	if *packPath == "" {
		fmt.Fprintln(stderr, "handrail test: --pack is required")
		return ExitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "handrail test: at least one cases file is required")
		return ExitUsage
	}
	eng, code := loadEngine(*packPath, stderr)
	if code != ExitOK {
		return code
	}
	passed, failed := 0, 0
	for _, path := range fs.Args() {
		suite, err := packtest.Load(path)
		if err != nil {
			fmt.Fprintf(stderr, "handrail test: %s: %v\n", path, err)
			return ExitRuntime
		}
		for _, o := range packtest.Run(eng, suite) {
			if o.Passed {
				passed++
				fmt.Fprintf(stdout, "PASS  %s\n", o.Case.Name)
			} else {
				failed++
				fmt.Fprintf(stdout, "FAIL  %s\n      %s (%s:%d)\n",
					o.Case.Name, o.Reason, path, o.Case.Line)
			}
		}
	}
	fmt.Fprintf(stdout, "\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return ExitBreach
	}
	return ExitOK
}
