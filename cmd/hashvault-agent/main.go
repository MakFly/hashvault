// Command hashvault-agent is the root helper installed on Docker hosts and
// SSH-deployed servers. See internal/agentcli for the commands.
package main

import (
	"os"
	"syscall"

	"github.com/MakFly/hashvault/internal/agentcli"
)

func main() {
	os.Exit(agentcli.Main(os.Args[1:], agentcli.IO{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Exec:    syscall.Exec,
		Environ: os.Environ(),
	}))
}
