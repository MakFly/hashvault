package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"

	"github.com/MakFly/hashvault/internal/target"
)

func (c *client) render(args []string) error {
	if len(args) == 0 {
		return errors.New("render FILE --format json|stack|compose|systemd [--service SVC]")
	}
	filename := args[0]
	fs := newFlags("render", c.io)
	format, service := fs.String("format", "json", "runtime output"), fs.String("service", "", "systemd service")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	raw, err := os.ReadFile(filename) // #nosec G304 -- operator-selected descriptor path, never supplied by the API or browser
	if err != nil {
		return err
	}
	var p target.Preparation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return err
	}
	return target.Render(c.io.Stdout, p, *format, *service)
}
