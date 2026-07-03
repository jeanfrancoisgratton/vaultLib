// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/list.go

package policies

import (
	"context"
	"fmt"
	"sort"
)

// ListPolicies returns the names of every ACL policy currently stored in
// Vault, including the built-in "default" and "root" policies.
func (c *Client) ListPolicies() ([]string, error) {
	return c.ListPoliciesContext(context.Background())
}

// ListPoliciesContext lists ACL policy names using the supplied context.
func (c *Client) ListPoliciesContext(ctx context.Context) ([]string, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	names, err := c.client.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		return nil, classifyPolicyError(err, "list policies")
	}

	sort.Strings(names)
	return names, nil
}
