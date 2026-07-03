// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: sys/edit.go

package sys

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

// EditKVEngine tunes an existing KV secrets engine mount (lease TTLs,
// listing visibility, etc.) at path. Fields left nil in opts are left
// unchanged on the mount.
func (c *Client) EditKVEngine(path string, opts EditKVOptions) error {
	return c.EditKVEngineContext(context.Background(), path, opts)
}

// EditKVEngineContext tunes an existing KV secrets engine mount using the
// supplied context.
func (c *Client) EditKVEngineContext(ctx context.Context, path string, opts EditKVOptions) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return fmt.Errorf("invalid mount path: path cannot be empty")
	}

	if err := c.requireKVMount(ctx, path, "edit kv engine"); err != nil {
		return err
	}

	tuneConfig := api.TuneMountConfigInput{
		Description:       opts.Description,
		DefaultLeaseTTL:   opts.DefaultLeaseTTL,
		MaxLeaseTTL:       opts.MaxLeaseTTL,
		ListingVisibility: opts.ListingVisibility,
	}

	if err := c.client.Sys().TuneMountAllowNilWithContext(ctx, path, tuneConfig); err != nil {
		return classifySysError(err, "edit kv engine")
	}
	return nil
}
