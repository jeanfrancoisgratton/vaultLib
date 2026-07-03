// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: kv/restore.go
// Original timestamp: 2026/06/27 16:19:41

package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// RestoreEngine reads a JSON backup file produced by BackupEngine and writes
// every secret back to the configured KV mount. Existing secrets at the same
// paths are overwritten; for KV v2 each write produces a new version. The
// mount path recorded in the file is informational only — secrets are always
// restored to the mount configured on the client.
func (c *Client) RestoreEngine(srcPath string) error {
	return c.RestoreEngineContext(context.Background(), srcPath)
}

// RestoreEngineContext reads a JSON backup file and restores every secret
// using the supplied context.
func (c *Client) RestoreEngineContext(ctx context.Context, srcPath string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}
	if srcPath == "" {
		return fmt.Errorf("restore engine failed: source path cannot be empty")
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("restore engine failed: open file %q: %w", srcPath, err)
	}
	defer f.Close()

	var backup BackupFile
	if err := json.NewDecoder(f).Decode(&backup); err != nil {
		return fmt.Errorf("restore engine failed: decode JSON from %q: %w", srcPath, err)
	}

	if len(backup.Secrets) == 0 {
		return nil
	}

	for _, entry := range backup.Secrets {
		if entry.Path == "" {
			return fmt.Errorf("restore engine failed: backup file contains an entry with an empty path")
		}
		if len(entry.Data) == 0 {
			// Skip secrets that carry no data (can happen if a version was
			// soft-deleted between a list and a read during backup — the entry
			// will have been omitted, but guard defensively here).
			continue
		}

		if _, err := c.WriteSecretContext(ctx, entry.Path, entry.Data, WriteOptions{}); err != nil {
			return fmt.Errorf("restore engine failed: write secret %q: %w", entry.Path, err)
		}
	}

	return nil
}

// -------------------------------------------------------------------------
// Package-level one-shot helpers
// -------------------------------------------------------------------------

// BackupEngine is a convenience helper for one-shot KV engine backups.
// It creates a client from cfg and writes every secret under the mount to
// the JSON file at destPath.
func BackupEngine(cfg Config, destPath string) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.BackupEngine(destPath)
}

// RestoreEngine is a convenience helper for one-shot KV engine restores.
// It creates a client from cfg and writes every secret from the JSON file
// at srcPath to the configured mount.
func RestoreEngine(cfg Config, srcPath string) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.RestoreEngine(srcPath)
}
