// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: sys/disable.go

package sys

import (
	"context"
	"fmt"
	"strings"
)

// DisableKVEngine removes a KV secrets engine mount at path. This is
// irreversible: every secret stored under the mount, across all versions,
// is destroyed along with it.
func (c *Client) DisableKVEngine(path string) error {
	return c.DisableKVEngineContext(context.Background(), path)
}

// DisableKVEngineContext removes a KV secrets engine mount using the
// supplied context.
func (c *Client) DisableKVEngineContext(ctx context.Context, path string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return fmt.Errorf("invalid mount path: path cannot be empty")
	}

	if err := c.requireKVMount(ctx, path, "disable kv engine"); err != nil {
		return err
	}

	if err := c.client.Sys().UnmountWithContext(ctx, path); err != nil {
		return classifySysError(err, "disable kv engine")
	}
	return nil
}
