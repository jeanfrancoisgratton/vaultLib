// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/revoke.go

package tokens

import (
	"context"
	"fmt"
	"strings"
)

// RevokeToken revokes a token by value, along with its entire lease/child
// token tree (Vault's RevokeTree, the standard full revoke). Revoking the
// token also revokes every token and dynamic secret lease created beneath
// it; that's normally the desired behavior, but means revoking a token
// near the root of a tree is broader than revoking the token alone.
func (c *Client) RevokeToken(token string) error {
	return c.RevokeTokenContext(context.Background(), token)
}

// RevokeTokenContext revokes a token using the supplied context.
func (c *Client) RevokeTokenContext(ctx context.Context, token string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("invalid token: token value cannot be empty")
	}

	if err := c.client.Auth().Token().RevokeTreeWithContext(ctx, token); err != nil {
		return classifyTokenError(err, "revoke token")
	}
	return nil
}
