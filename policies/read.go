// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/read.go

package policies

import (
	"context"
	"fmt"
	"strings"
)

// ReadPolicy reads a single ACL policy by name.
func (c *Client) ReadPolicy(name string) (*Policy, error) {
	return c.ReadPolicyContext(context.Background(), name)
}

// ReadPolicyContext reads a single ACL policy using the supplied context.
//
// Note: Vault's underlying GetPolicy call returns an empty string with a nil
// error when a policy does not exist, rather than a 404 error — this mirrors
// the same kind of non-obvious 404 behavior already handled specially for KV
// LIST calls. ReadPolicyContext turns that empty result into an explicit,
// descriptive error so callers don't have to special-case an empty Rules
// field themselves.
func (c *Client) ReadPolicyContext(ctx context.Context, name string) (*Policy, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("invalid policy name: name cannot be empty")
	}

	rules, err := c.client.Sys().GetPolicyWithContext(ctx, name)
	if err != nil {
		return nil, classifyPolicyError(err, "read policy")
	}
	if rules == "" {
		return nil, fmt.Errorf("read policy failed: policy %q does not exist", name)
	}

	return &Policy{Name: name, Rules: rules}, nil
}
