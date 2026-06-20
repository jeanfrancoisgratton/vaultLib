// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/create.go

package policies

import (
	"context"
	"fmt"
	"strings"
)

// CreatePolicy writes an ACL policy document to Vault under the given name.
//
// Vault's sys/policies/acl endpoint has no separate create-vs-update verb —
// PUT either creates the policy if it does not exist or overwrites it in
// place if it does. CreatePolicy follows that same upsert behavior rather
// than inventing an artificial distinction the underlying API doesn't have.
// Callers that need strict create-only semantics should call ReadPolicy
// first and check for a not-found error.
func (c *Client) CreatePolicy(name, rules string) error {
	return c.CreatePolicyContext(context.Background(), name, rules)
}

// CreatePolicyContext writes an ACL policy document using the supplied context.
func (c *Client) CreatePolicyContext(ctx context.Context, name, rules string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("invalid policy name: name cannot be empty")
	}
	if strings.TrimSpace(rules) == "" {
		return fmt.Errorf("invalid policy rules: rules document cannot be empty")
	}

	if err := c.client.Sys().PutPolicyWithContext(ctx, name, rules); err != nil {
		return classifyPolicyError(err, "create policy")
	}
	return nil
}
