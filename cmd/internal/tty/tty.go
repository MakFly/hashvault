// Package tty reads operator input from the controlling terminal, for the
// hashvault binaries (PIN prompts of hardware keys, confirmations).
package tty

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/MakFly/hashvault/internal/agekeys"
)

// Prompter reads from the controlling terminal, without echo for secrets (the
// YubiKey PIN), whatever stdin is.
func Prompter(out io.Writer) agekeys.Prompter {
	return agekeys.Prompter{
		Out: out,
		ReadLine: func() (string, error) {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				return "", err
			}
			defer tty.Close()
			line, err := bufio.NewReader(tty).ReadString('\n')
			return strings.TrimSpace(line), err
		},
		ReadSecret: func() (string, error) {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				return "", err
			}
			defer tty.Close()
			v, err := term.ReadPassword(int(tty.Fd())) // #nosec G115 -- a file descriptor fits in an int
			fmt.Fprintln(out)
			return string(v), err
		},
	}
}
