// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: kv/list.go

package kv

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ListSecrets recursively lists all secrets below the configured mount.
func (c *Client) ListSecrets(includeVersion bool) ([]SecretInfo, error) {
	return c.ListSecretsContext(context.Background(), includeVersion)
}

// ListSecretsContext recursively lists all secrets below the configured mount.
func (c *Client) ListSecretsContext(ctx context.Context, includeVersion bool) ([]SecretInfo, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	var results []SecretInfo

	if err := c.walkSecrets(ctx, "", includeVersion, &results); err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Path < results[j].Path
	})

	return results, nil
}

func (c *Client) walkSecrets(ctx context.Context, prefix string, includeVersion bool, results *[]SecretInfo) error {
	var apiPath string

	if c.kvVersion == 1 {
		apiPath = fmt.Sprintf("%s/%s", c.cfg.MountPath, prefix)
	} else {
		apiPath = fmt.Sprintf("%s/metadata/%s", c.cfg.MountPath, prefix)
	}

	apiPath = strings.TrimRight(apiPath, "/")

	secret, err := c.client.Logical().ListWithContext(ctx, apiPath)
	if err != nil {
		return err
	}
	if secret == nil {
		return nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return fmt.Errorf("list secrets failed: unexpected Vault response")
	}

	for _, item := range keys {
		name, ok := item.(string)
		if !ok {
			continue
		}

		fullPath := prefix + name

		if strings.HasSuffix(name, "/") {
			if err := c.walkSecrets(ctx, fullPath, includeVersion, results); err != nil {
				return err
			}
			continue
		}

		entry := SecretInfo{Path: fullPath}

		if includeVersion && c.kvVersion == 2 {
			version, err := c.secretVersion(ctx, fullPath)
			if err != nil {
				return fmt.Errorf("get version for %q failed: %w", fullPath, err)
			}
			entry.Version = version
		}

		*results = append(*results, entry)
	}

	return nil
}

func (c *Client) secretVersion(ctx context.Context, path string) (int, error) {
	secret, err := c.client.Logical().ReadWithContext(
		ctx,
		fmt.Sprintf("%s/metadata/%s", c.cfg.MountPath, path),
	)
	if err != nil {
		return 0, err
	}
	if secret == nil {
		return 0, fmt.Errorf("metadata not found")
	}

	switch v := secret.Data["current_version"].(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	}

	return 0, fmt.Errorf("unknown version type")
}
