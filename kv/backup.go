// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: kv/backup.go

package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// BackupEngine dumps every secret reachable under the configured KV mount to
// the JSON file at destPath. The file is created (or truncated if it already
// exists). For KV v2 mounts only the latest non-deleted version of each secret
// is included.
func (c *Client) BackupEngine(destPath string) error {
	return c.BackupEngineContext(context.Background(), destPath)
}

// BackupEngineContext dumps every secret reachable under the configured KV
// mount to the JSON file at destPath, using the supplied context.
func (c *Client) BackupEngineContext(ctx context.Context, destPath string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}
	if destPath == "" {
		return fmt.Errorf("backup engine failed: destination path cannot be empty")
	}

	// List every secret path under the mount.
	entries, err := c.ListSecretsContext(ctx, c.kvVersion == 2)
	if err != nil {
		return fmt.Errorf("backup engine failed: list secrets: %w", err)
	}

	backup := BackupFile{
		MountPath: c.cfg.MountPath,
		KVVersion: c.kvVersion,
		Secrets:   make([]BackupEntry, 0, len(entries)),
	}

	for _, info := range entries {
		secret, err := c.ReadSecretContext(ctx, info.Path, ReadOptions{})
		if err != nil {
			return fmt.Errorf("backup engine failed: read secret %q: %w", info.Path, err)
		}

		backup.Secrets = append(backup.Secrets, BackupEntry{
			Path:    info.Path,
			Version: secret.Version,
			Data:    secret.Data,
		})
	}

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("backup engine failed: create file %q: %w", destPath, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(backup); err != nil {
		return fmt.Errorf("backup engine failed: write JSON to %q: %w", destPath, err)
	}

	return nil
}
