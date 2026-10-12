package target

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// Render exports runtime-native references. JSON is also valid YAML, so the
// stack and compose outputs can be passed as deployment configuration files.
// The deployment tool remains responsible for merging its application spec.
func Render(w io.Writer, p Preparation, format, service string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if format == "json" {
		return json.NewEncoder(w).Encode(p)
	}
	services := map[string]map[string]any{}
	keys := make([]string, 0, len(p.Items))
	for key := range p.Items {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	switch format {
	case "stack":
		if p.Kind != Swarm {
			return fmt.Errorf("%w: stack output needs a swarm preparation", ErrContract)
		}
		secrets := map[string]any{}
		for _, key := range keys {
			it := p.Items[key]
			secrets[it.ObjectName] = map[string]any{"external": true}
			for _, svc := range it.Spec.Services {
				if services[svc] == nil {
					services[svc] = map[string]any{"secrets": []any{}}
				}
				ref := map[string]any{"source": it.ObjectName, "target": it.Spec.Target, "uid": it.Spec.UID, "gid": it.Spec.GID, "mode": it.Spec.FileMode()}
				services[svc]["secrets"] = append(services[svc]["secrets"].([]any), ref)
			}
		}
		return json.NewEncoder(w).Encode(map[string]any{"services": services, "secrets": secrets})
	case "compose":
		if p.Kind != Docker {
			return fmt.Errorf("%w: compose output needs a docker preparation", ErrContract)
		}
		for svc, files := range p.Services {
			services[svc] = map[string]any{"volumes": []any{map[string]any{"type": "bind", "source": files.Directory, "target": "/run/secrets", "read_only": true}}}
		}
		return json.NewEncoder(w).Encode(map[string]any{"services": services})
	case "systemd":
		if p.Kind != SSH {
			return fmt.Errorf("%w: systemd output needs an ssh preparation", ErrContract)
		}
		files, ok := p.Services[service]
		if !ok {
			return fmt.Errorf("%w: select a manifest service with --service", ErrContract)
		}
		if _, err := fmt.Fprintln(w, "[Service]"); err != nil {
			return err
		}
		for _, key := range keys {
			if filename, ok := files.Credentials[key]; ok {
				// systemd-creds binds its ciphertext to app.KEY. Keep that
				// credential id when systemd decrypts the file at service start.
				if _, err := fmt.Fprintf(w, "LoadCredentialEncrypted=%s.%s:%s\n", p.App, key, filename); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: render format must be json, stack, compose or systemd", ErrContract)
	}
}
