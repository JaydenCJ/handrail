// Command handrail compiles YAML rule packs into a deterministic pre/post
// guardrail engine — regex, lexicons and thresholds, no models, no network.
package main

import (
	"os"

	"github.com/JaydenCJ/handrail/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
