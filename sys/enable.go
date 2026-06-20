// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: sys/enable.go

package sys

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// EnableKVEngine creates a new KV secrets engine mount at path.
func (c *Client) EnableKVEngine(path string, opts EnableKVOptions) error {
	return c.EnableKVEngineContext(context.Background(), path, opts)
}

// EnableKVEngineContext creates a new KV secrets engine mount using the
// supplied context.
func (c *Client) EnableKVEngineContext(ctx context.Context, path string, opts EnableKVOptions) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return fmt.Errorf("invalid mount path: path cannot be empty")
	}

	version := opts.Version
	switch version {
	case 0:
		version = 2 // matches `vault secrets enable kv`'s own default
	case 1, 2:
		// explicit, valid choice
	default:
		return fmt.Errorf("invalid KV version: %d (must be 1 or 2)", opts.Version)
	}

	mountInput := &api.MountInput{
		Type:        "kv",
		Description: opts.Description,
		Local:       opts.Local,
		Options:     map[string]string{"version": strconv.Itoa(version)},
		Config: api.MountConfigInput{
			DefaultLeaseTTL: opts.DefaultLeaseTTL,
			MaxLeaseTTL:     opts.MaxLeaseTTL,
		},
	}

	if err := c.client.Sys().MountWithContext(ctx, path, mountInput); err != nil {
		return classifySysError(err, "enable kv engine")
	}
	return nil
}
