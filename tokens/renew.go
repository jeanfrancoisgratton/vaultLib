// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/renew.go

package tokens

import (
	"context"
	"fmt"
	"strings"
)

// RenewToken renews a token by value. increment is the requested TTL
// increment in seconds; Vault treats it as advisory and may return a
// shorter lease than requested. A value of 0 lets Vault pick its own
// increment (typically the token's original TTL).
func (c *Client) RenewToken(token string, increment int) (*TokenAuth, error) {
	return c.RenewTokenContext(context.Background(), token, increment)
}

// RenewTokenContext renews a token using the supplied context.
func (c *Client) RenewTokenContext(ctx context.Context, token string, increment int) (*TokenAuth, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("invalid token: token value cannot be empty")
	}
	if increment < 0 {
		return nil, fmt.Errorf("invalid renewal increment: increment cannot be negative")
	}

	secret, err := c.client.Auth().Token().RenewWithContext(ctx, token, increment)
	if err != nil {
		return nil, classifyTokenError(err, "renew token")
	}

	result := parseTokenAuth(secret)
	if result == nil {
		return nil, fmt.Errorf("renew token failed: vault returned no auth block")
	}
	return result, nil
}
