// Command hashvault is the operator command line. See internal/cli.
package main

import (
	"os"

	"github.com/MakFly/hashvault/cmd/internal/tty"
	"github.com/MakFly/hashvault/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.IO{
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Getenv:   os.Getenv,
		Prompter: tty.Prompter(os.Stderr),
	}))
}
