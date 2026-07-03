// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/accessors.go

package tokens

import (
	"context"
	"fmt"
	"sort"
)

// ListAccessors lists every token accessor known to Vault. There is no
// dedicated helper for this on the Vault SDK's TokenAuth type, so this calls
// the LIST auth/token/accessors endpoint directly through Logical(), the
// same approach kv/list.go uses for KV listings.
//
// As with KV listings, Vault returns a 404 (nil Secret, nil error from the
// SDK) when there are no accessors yet, rather than an empty list — that is
// treated as zero accessors, not an error, matching the lesson already
// applied to kv.ListSecrets.
func (c *Client) ListAccessors() ([]string, error) {
	return c.ListAccessorsContext(context.Background())
}

// ListAccessorsContext lists token accessors using the supplied context.
func (c *Client) ListAccessorsContext(ctx context.Context) ([]string, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	secret, err := c.client.Logical().ListWithContext(ctx, "auth/token/accessors")
	if err != nil {
		return nil, classifyTokenError(err, "list accessors")
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	accessors := dataStringSlice(secret.Data, "keys")
	sort.Strings(accessors)
	return accessors, nil
}
