// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: admin/seal.go

package admin

import (
	"context"
	"fmt"
)

// Seal activates the Vault seal via the sys/seal endpoint. The vault will
// immediately stop serving requests for secrets once sealed. The operation
// requires a token with sudo capability on sys/seal.
//
// Seal is idempotent: calling it on an already-sealed vault returns nil.
func (c *Client) Seal() error {
	return c.SealContext(context.Background())
}

// SealContext activates the Vault seal using the supplied context.
func (c *Client) SealContext(ctx context.Context) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	if err := c.client.Sys().SealWithContext(ctx); err != nil {
		return classifyAdminError(err, "seal")
	}
	return nil
}
