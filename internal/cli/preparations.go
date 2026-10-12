package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/MakFly/hashvault/internal/target"
)

func (c *client) prepare(args []string) error {
	fs := newFlags("prepare", c.io)
	tgt := fs.String("target", "", "registered target")
	manifest := fs.String("manifest", "hashvault.json", "application manifest")
	output := fs.String("output", "", "write a descriptor with no secret values")
	rollback := fs.Bool("rollback", false, "prepare pinned previous versions")
	var pins multi
	fs.Var(&pins, "version", "pin KEY=N (repeat)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tgt == "" || fs.NArg() != 0 {
		return errors.New("prepare needs --target and --manifest")
	}
	m, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	if _, err := target.ParseManifest(m); err != nil {
		return err
	}
	versions := map[string]uint64{}
	for _, pin := range pins {
		var key string
		var n uint64
		for i, ch := range pin {
			if ch == '=' {
				key = pin[:i]
				n, err = strconv.ParseUint(pin[i+1:], 10, 64)
				break
			}
		}
		if key == "" || n == 0 || err != nil {
			return fmt.Errorf("--version %q is not KEY=N", pin)
		}
		versions[key] = n
	}
	out, err := c.call("POST", "/v1/preparations", map[string]any{"target": *tgt, "manifest": json.RawMessage(m), "versions": versions, "rollback": *rollback}, true)
	if err != nil {
		return err
	}
	if *output != "" {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*output, append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	return c.printJSON(out)
}

func (c *client) preparation(args []string) error {
	if len(args) == 2 && args[0] == "get" {
		if !target.ValidPreparationID(args[1]) {
			return errors.New("invalid preparation id")
		}
		out, err := c.call("GET", "/v1/preparations/"+args[1], nil, true)
		if err != nil {
			return err
		}
		return c.printJSON(out)
	}
	if len(args) > 0 && args[0] == "list" {
		fs := newFlags("preparation list", c.io)
		tgt, app := fs.String("target", "", "target"), fs.String("app", "", "application")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *tgt == "" || *app == "" {
			return errors.New("preparation list needs --target and --app")
		}
		out, err := c.call("GET", "/v1/preparations?"+url.Values{"target": {*tgt}, "app": {*app}}.Encode(), nil, true)
		if err != nil {
			return err
		}
		return c.printJSON(out)
	}
	return errors.New("preparation get ID | list --target T --app APP")
}

func (c *client) confirm(args []string) error {
	if len(args) == 0 || !target.ValidPreparationID(args[0]) {
		return errors.New("confirm ID --release RELEASE [--previous ID]")
	}
	id := args[0]
	fs := newFlags("confirm", c.io)
	release := fs.String("release", "", "deployer release identity")
	previous := fs.String("previous", "", "expected active preparation")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *release == "" {
		return errors.New("confirm needs --release")
	}
	out, err := c.call("POST", "/v1/preparations/"+id+"/confirm", map[string]string{"release": *release, "previous": *previous}, true)
	if err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *client) publication(args []string) error {
	fs := newFlags("publication", c.io)
	tgt, app := fs.String("target", "", "target"), fs.String("app", "", "application")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tgt == "" || *app == "" {
		return errors.New("publication --target T --app APP")
	}
	out, err := c.call("GET", "/v1/publications/"+url.PathEscape(*tgt)+"/"+url.PathEscape(*app), nil, true)
	if err != nil {
		return err
	}
	return c.printJSON(out)
}
