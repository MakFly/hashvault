package openbao

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// KVEntry is one version of a KV v2 entry.
type KVEntry struct {
	Data      map[string]string
	Version   int
	Destroyed bool
	Deleted   bool
}

type kvReadData struct {
	Data     map[string]string `json:"data"`
	Metadata struct {
		Version      int    `json:"version"`
		Destroyed    bool   `json:"destroyed"`
		DeletionTime string `json:"deletion_time"`
	} `json:"metadata"`
}

// KVPut writes a new version of mount/path. cas is the version the caller
// expects to be current (0: the entry must not exist yet); a mismatch returns
// ErrCASMismatch. It returns the version written.
func (c *Client) KVPut(ctx context.Context, mount, path string, data map[string]string, cas int) (int, error) {
	body := map[string]any{"options": map[string]int{"cas": cas}, "data": data}
	var out response[struct {
		Version int `json:"version"`
	}]
	if err := c.do(ctx, http.MethodPost, mount+"/data/"+path, nil, body, &out); err != nil {
		return 0, err
	}
	return out.Data.Version, nil
}

// KVGet reads a version of mount/path (0: the current one). A destroyed or
// deleted version comes back with no data and the matching flag set.
func (c *Client) KVGet(ctx context.Context, mount, path string, version int) (KVEntry, error) {
	q := url.Values{}
	if version > 0 {
		q.Set("version", strconv.Itoa(version))
	}
	var out response[*kvReadData]
	err := c.do(ctx, http.MethodGet, mount+"/data/"+path, q, nil, &out)
	// A destroyed or deleted version is a 404 that still carries metadata.
	if out.Data == nil || out.Data.Metadata.Version == 0 {
		if err == nil {
			err = ErrNotFound
		}
		return KVEntry{}, err
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return KVEntry{}, err
	}
	return KVEntry{
		Data:      out.Data.Data,
		Version:   out.Data.Metadata.Version,
		Destroyed: out.Data.Metadata.Destroyed,
		Deleted:   out.Data.Metadata.DeletionTime != "",
	}, nil
}

// KVMetadata is the subset of the KV v2 metadata hashvault reads.
type KVMetadata struct {
	CurrentVersion int
	// Live lists the versions that are neither destroyed nor deleted.
	Live []int
}

// KVMetadata reads the metadata of mount/path.
func (c *Client) KVMetadata(ctx context.Context, mount, path string) (KVMetadata, error) {
	var out response[struct {
		CurrentVersion int `json:"current_version"`
		Versions       map[string]struct {
			Destroyed    bool   `json:"destroyed"`
			DeletionTime string `json:"deletion_time"`
		} `json:"versions"`
	}]
	if err := c.do(ctx, http.MethodGet, mount+"/metadata/"+path, nil, nil, &out); err != nil {
		return KVMetadata{}, err
	}
	md := KVMetadata{CurrentVersion: out.Data.CurrentVersion}
	for v, info := range out.Data.Versions {
		n, err := strconv.Atoi(v)
		if err != nil {
			return KVMetadata{}, fmt.Errorf("openbao: unexpected version key %q", v)
		}
		if !info.Destroyed && info.DeletionTime == "" {
			md.Live = append(md.Live, n)
		}
	}
	return md, nil
}

// KVList lists the keys under mount/prefix. Sub-paths end with "/".
func (c *Client) KVList(ctx context.Context, mount, prefix string) ([]string, error) {
	var out response[struct {
		Keys []string `json:"keys"`
	}]
	err := c.do(ctx, "LIST", mount+"/metadata/"+strings.TrimSuffix(prefix, "/"), nil, nil, &out)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return out.Data.Keys, nil
}

// KVDestroy permanently removes the data of the given versions. Their
// metadata stays, so the entry and its version numbers remain visible.
func (c *Client) KVDestroy(ctx context.Context, mount, path string, versions []int) error {
	if len(versions) == 0 {
		return nil
	}
	return c.do(ctx, http.MethodPost, mount+"/destroy/"+path, nil, map[string]any{"versions": versions}, nil)
}
