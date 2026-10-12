// Package agekeys reads age recipients and identities, native (X25519,
// hybrid ML-KEM-768 + X25519) or through plugins such as
// age-plugin-yubikey, which asks for the PIN and a touch.
package agekeys

import (
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// Prompter is how plugins reach the operator.
type Prompter struct {
	Out        io.Writer
	ReadLine   func() (string, error)
	ReadSecret func() (string, error)
}

// UI returns the plugin callbacks.
func (p Prompter) UI() *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			_, err := fmt.Fprintf(p.Out, "[%s] %s\n", name, message)
			return err
		},
		RequestValue: func(name, prompt string, secret bool) (string, error) {
			fmt.Fprintf(p.Out, "[%s] %s: ", name, prompt)
			if secret {
				return p.ReadSecret()
			}
			return p.ReadLine()
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			fmt.Fprintf(p.Out, "[%s] %s [%s/%s]: ", name, prompt, yes, no)
			line, err := p.ReadLine()
			return err == nil && line == yes, err
		},
		WaitTimer: func(name string) {
			fmt.Fprintf(p.Out, "[%s] waiting for the hardware key (touch it)\n", name)
		},
	}
}

// ParseRecipient accepts "age1pq1..." (hybrid), "age1..." (X25519) and
// plugin recipients ("age1yubikey1..."): native parsers first, a plugin
// otherwise.
func ParseRecipient(s string, ui *plugin.ClientUI) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "age1pq1") {
		return age.ParseHybridRecipient(s)
	}
	if r, err := age.ParseX25519Recipient(s); err == nil {
		return r, nil
	}
	return plugin.NewRecipient(s, ui)
}

// ParseIdentities reads an identity file: native identities
// ("AGE-SECRET-KEY-...") and plugin identities ("AGE-PLUGIN-...").
func ParseIdentities(data []byte, ui *plugin.ClientUI) ([]age.Identity, error) {
	var out []age.Identity
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "AGE-PLUGIN-"):
			id, err := plugin.NewIdentity(line, ui)
			if err != nil {
				return nil, err
			}
			out = append(out, id)
		default:
			ids, err := age.ParseIdentities(strings.NewReader(line))
			if err != nil {
				return nil, err
			}
			out = append(out, ids...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("agekeys: no identity found")
	}
	return out, nil
}
