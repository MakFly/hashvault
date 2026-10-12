package hostagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/dockerapi"
)

// Consumers restarts what reads the values once they are in place.
type Consumers interface {
	Run(ctx context.Context, b batch.Batch) error
}

// HostConsumers restarts compose services through the local Docker API
// (kind docker) and runs reload commands (kind ssh).
type HostConsumers struct {
	Docker *dockerapi.Client
	// StopTimeout is given to the container before it is killed.
	StopTimeout time.Duration
	// ReadyTimeout bounds the wait for a restarted container to run (and be
	// healthy, when it has a healthcheck), and each reload command.
	ReadyTimeout time.Duration
	// MinUptime is how long a restarted container without a healthcheck must
	// keep running, unrestarted, to count as ready: a process that dies a
	// second after start must not pass. Default 10 seconds.
	MinUptime time.Duration
	Poll      time.Duration
}

func (h HostConsumers) defaults() HostConsumers {
	if h.StopTimeout == 0 {
		h.StopTimeout = 10 * time.Second
	}
	if h.ReadyTimeout == 0 {
		h.ReadyTimeout = 2 * time.Minute
	}
	if h.Poll == 0 {
		h.Poll = time.Second
	}
	if h.MinUptime == 0 {
		h.MinUptime = 10 * time.Second
	}
	return h
}

// Run implements Consumers.
func (h HostConsumers) Run(ctx context.Context, b batch.Batch) error {
	h = h.defaults()
	if len(b.Consumers.Docker) > 0 {
		if h.Docker == nil {
			return errors.New("hostagent: docker consumers requested but no Docker socket is configured")
		}
		project := b.Consumers.ComposeProject
		if project == "" {
			project = b.App
		}
		for _, svc := range b.Consumers.Docker {
			if err := h.restartService(ctx, project, svc); err != nil {
				return err
			}
		}
	}
	for _, argv := range b.Consumers.Reload {
		if err := h.reload(ctx, argv); err != nil {
			return err
		}
	}
	return nil
}

func (h HostConsumers) restartService(ctx context.Context, project, svc string) error {
	containers, err := h.Docker.ContainerList(ctx, "com.docker.compose.project="+project, "com.docker.compose.service="+svc)
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return fmt.Errorf("hostagent: no container for compose service %s/%s", project, svc)
	}
	for _, c := range containers {
		before, err := h.Docker.ContainerInspect(ctx, c.ID)
		if err != nil {
			return err
		}
		if err := h.Docker.ContainerRestart(ctx, c.ID, h.StopTimeout); err != nil {
			return fmt.Errorf("hostagent: restart %s/%s: %w", project, svc, err)
		}
		if err := h.waitReady(ctx, c.ID, before.StartedAt); err != nil {
			return fmt.Errorf("hostagent: %s/%s: %w", project, svc, err)
		}
	}
	return nil
}

// waitReady waits for a container started after since to be ready: healthy
// when it has a healthcheck, otherwise running without a restart for
// MinUptime.
func (h HostConsumers) waitReady(ctx context.Context, id string, since time.Time) error {
	deadline := time.Now().Add(h.ReadyTimeout)
	var started time.Time
	for {
		st, err := h.Docker.ContainerInspect(ctx, id)
		if err != nil {
			return err
		}
		restarted := st.StartedAt.After(since)
		switch {
		case !restarted:
			// The restart has not taken effect yet.
		case st.Health != nil && st.Health.Status == "unhealthy":
			return errors.New("container is unhealthy after the restart")
		case !st.Running && !st.Restarting:
			return fmt.Errorf("container exited with code %d after the restart", st.ExitCode)
		case st.Restarting || (!started.IsZero() && !st.StartedAt.Equal(started)):
			return errors.New("container restarted again after the restart")
		case st.Health != nil:
			if st.Health.Status == "healthy" {
				return nil
			}
		default:
			if started.IsZero() {
				started = st.StartedAt
			}
			if time.Since(started) >= h.MinUptime {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("container not ready after %s", h.ReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(h.Poll):
		}
	}
}

func (h HostConsumers) reload(ctx context.Context, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, h.ReadyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv comes from a signed batch, absolute program, no shell
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		msg := errOut.Bytes()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("hostagent: reload %q: %w: %s", argv[0], err, bytes.TrimSpace(msg))
	}
	return nil
}
