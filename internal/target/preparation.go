package target

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

const PreparationVersion = "hv-preparation-1"

var preparationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var preparationEnvPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidPreparationID keeps generation identifiers out of filesystem paths.
func ValidPreparationID(id string) bool { return preparationPattern.MatchString(id) }

func NewPreparationID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// PreparedItem contains only coordinates and mount metadata, never a value.
type PreparedItem struct {
	Version    uint64   `json:"version"`
	Spec       ItemSpec `json:"spec"`
	ObjectName string   `json:"object_name,omitempty"`
	ObjectID   string   `json:"object_id,omitempty"`
}

// ServiceFiles locates an immutable host generation. Credentials contain
// encrypted file paths; Directory and Dotenv point to tmpfs copies.
type ServiceFiles struct {
	Directory   string            `json:"directory"`
	Dotenv      string            `json:"dotenv,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

type PreparedResources struct {
	Items    map[string]PreparedItem `json:"items"`
	Services map[string]ServiceFiles `json:"services,omitempty"`
}

// Preparation is an immutable deployment descriptor. Confirming a release
// records a separate publication; it never changes this snapshot.
type Preparation struct {
	Version string `json:"version"`
	ID      string `json:"id"`
	Target  string `json:"target"`
	Kind    Kind   `json:"kind"`
	Env     string `json:"env"`
	App     string `json:"app"`
	PreparedResources
	By string    `json:"by"`
	At time.Time `json:"at"`
}

func (p Preparation) Validate() error {
	if p.Version != PreparationVersion || !ValidPreparationID(p.ID) || !appPattern.MatchString(p.App) || !appPattern.MatchString(p.Target) || !preparationEnvPattern.MatchString(p.Env) || len(p.Items) == 0 {
		return fmt.Errorf("%w: invalid preparation", ErrContract)
	}
	if p.Kind != Swarm && p.Kind != Docker && p.Kind != SSH {
		return fmt.Errorf("%w: unsupported preparation kind", ErrContract)
	}
	d := Desired{App: p.App, Env: p.Env}
	for key, item := range p.Items {
		if p.Kind == Swarm && (item.ObjectName != fmt.Sprintf("hv_%s_%s_v%d", p.App, item.Spec.Target, item.Version) || len(item.ObjectName) > 64 || item.ObjectID == "") {
			return fmt.Errorf("%w: missing swarm object", ErrContract)
		}
		d.Items = append(d.Items, Item{Key: key, Version: item.Version, Spec: item.Spec})
		if p.Kind != Swarm {
			for _, svc := range item.Spec.Services {
				files, ok := p.Services[svc]
				if !ok || !safePreparedPath(files.Directory, p.ID) || !strings.HasSuffix(files.Directory, "/"+p.App+"/"+svc) || !safePreparedPath(files.Credentials[key], p.ID) || path.Base(files.Credentials[key]) != p.App+"."+key || (item.Spec.Expose == Env && files.Dotenv != files.Directory+"/.env") {
					return fmt.Errorf("%w: missing generation files", ErrContract)
				}
			}
		}
	}
	return d.Validate()
}

func safePreparedPath(value, id string) bool {
	return path.IsAbs(value) && path.Clean(value) == value && strings.Contains(value, "/.generations/"+id+"/") && !strings.ContainsAny(value, "\r\n\x00")
}

// Preparer installs resources without changing or restarting consumers.
type Preparer interface {
	Prepare(context.Context, Desired, string) (PreparedResources, error)
}
