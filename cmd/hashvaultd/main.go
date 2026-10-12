// Command hashvaultd is the hashvault daemon. See internal/daemoncli.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/MakFly/hashvault/cmd/internal/tty"
	"github.com/MakFly/hashvault/internal/daemoncli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(daemoncli.Main(os.Args[1:], daemoncli.IO{
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Prompter: tty.Prompter(os.Stderr),
		Ctx:      ctx,
	}))
}
