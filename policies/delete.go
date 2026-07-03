// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/delete.go

package policies

import (
	"context"
	"fmt"
	"strings"
)

// DeletePolicy permanently removes an ACL policy by name.
//
// Vault itself refuses to delete the built-in "default" and "root" policies;
// DeletePolicy does not duplicate that guard client-side and simply
// surfaces Vault's rejection through classifyPolicyError.
func (c *Client) DeletePolicy(name string) error {
	return c.DeletePolicyContext(context.Background(), name)
}

// DeletePolicyContext deletes an ACL policy using the supplied context.
func (c *Client) DeletePolicyContext(ctx context.Context, name string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("invalid policy name: name cannot be empty")
	}

	if err := c.client.Sys().DeletePolicyWithContext(ctx, name); err != nil {
		return classifyPolicyError(err, "delete policy")
	}
	return nil
}
