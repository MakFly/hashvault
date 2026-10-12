// Package dindtest starts a throwaway Docker-in-Docker daemon for
// integration tests. Tests never talk to the host daemon, which may itself be
// a production-like swarm: the host is only asked to run, then remove, one
// privileged docker:dind container listening on a random loopback port.
//
// Without a docker CLI the tests are skipped, unless
// HASHVAULT_REQUIRE_INTEGRATION=1, which CI sets.
package dindtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/dockerapi"
)

// Mirror serves the Docker official images from AWS ECR Public, which does
// not apply Docker Hub's anonymous pull quota (CI runners share addresses).
const Mirror = "public.ecr.aws/docker/library/"

// Image is the dind image, pinned by major version.
const Image = Mirror + "docker:29-dind"

// TestImage is pulled inside the daemon for test services.
const (
	TestImage    = Mirror + "busybox"
	TestImageTag = "1.37"
)

// Daemon is a running dind container.
type Daemon struct {
	ID      string
	Address string
	Client  *dockerapi.Client
}

// Options tune Start.
type Options struct {
	// Swarm initialises a single-node swarm.
	Swarm bool
	// PullTestImage pulls TestImage inside the daemon.
	PullTestImage bool
}

// Available reports whether dind tests can run, and why not.
func Available() (bool, string) {
	if _, err := exec.LookPath("docker"); err != nil {
		return false, "docker CLI not found"
	}
	if err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Run(); err != nil { // #nosec G204 -- fixed arguments
		return false, "host docker daemon unreachable"
	}
	return true, ""
}

// Require skips (or, in CI, fails) the test when dind is unavailable.
func Require(t testing.TB) {
	t.Helper()
	if ok, why := Available(); !ok {
		if os.Getenv("HASHVAULT_REQUIRE_INTEGRATION") == "1" {
			t.Fatalf("dind integration tests required but unavailable: %s", why)
		}
		t.Skipf("dind integration tests skipped: %s", why)
	}
}

// Start runs a daemon. Stop must be called (tests use t.Cleanup or TestMain).
func Start(ctx context.Context, opts Options) (*Daemon, error) {
	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "--privileged", // #nosec G204 -- fixed arguments
		"--label", "hashvault.test=dind",
		"-e", "DOCKER_TLS_CERTDIR=",
		"-p", "127.0.0.1::2375",
		Image, "dockerd", "--host=tcp://0.0.0.0:2375").Output()
	if err != nil {
		return nil, fmt.Errorf("dindtest: docker run: %w", err)
	}
	d := &Daemon{ID: strings.TrimSpace(string(out))}
	port, err := exec.CommandContext(ctx, "docker", "port", d.ID, "2375/tcp").Output() // #nosec G204 -- ID from docker run
	if err != nil {
		d.Stop()
		return nil, fmt.Errorf("dindtest: docker port: %w", err)
	}
	addr := strings.TrimSpace(strings.Split(string(port), "\n")[0])
	d.Address = "tcp://" + addr
	d.Client, err = dockerapi.New(d.Address)
	if err != nil {
		d.Stop()
		return nil, err
	}
	deadline := time.Now().Add(60 * time.Second)
	for d.Client.Ping(ctx) != nil {
		if time.Now().After(deadline) {
			d.Stop()
			return nil, fmt.Errorf("dindtest: daemon did not answer within 60s")
		}
		time.Sleep(250 * time.Millisecond)
	}
	if opts.Swarm {
		if err := d.Client.SwarmInit(ctx); err != nil {
			d.Stop()
			return nil, fmt.Errorf("dindtest: swarm init: %w", err)
		}
	}
	if opts.PullTestImage {
		if err := d.Client.ImagePull(ctx, TestImage, TestImageTag); err != nil {
			d.Stop()
			return nil, err
		}
	}
	return d, nil
}

// Stop removes the container.
func (d *Daemon) Stop() {
	if d.ID != "" {
		_ = exec.Command("docker", "rm", "-f", d.ID).Run() // #nosec G204 -- ID from docker run
	}
}
