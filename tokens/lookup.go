// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/lookup.go

package tokens

import (
	"context"
	"fmt"
	"strings"
)

// LookupToken looks up a token by its value, returning Vault's metadata
// about it, including the token ID itself.
func (c *Client) LookupToken(token string) (*TokenInfo, error) {
	return c.LookupTokenContext(context.Background(), token)
}

// LookupTokenContext looks up a token by value using the supplied context.
func (c *Client) LookupTokenContext(ctx context.Context, token string) (*TokenInfo, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("invalid token: token value cannot be empty")
	}

	secret, err := c.client.Auth().Token().LookupWithContext(ctx, token)
	if err != nil {
		return nil, classifyTokenError(err, "lookup token")
	}

	info := parseTokenInfo(secret)
	if info == nil {
		return nil, fmt.Errorf("lookup token failed: vault returned no token data")
	}
	return info, nil
}

// LookupSelf looks up metadata for the token currently configured on this
// client (i.e. the one passed in via Config.Token).
func (c *Client) LookupSelf() (*TokenInfo, error) {
	return c.LookupSelfContext(context.Background())
}

// LookupSelfContext looks up the calling token using the supplied context.
func (c *Client) LookupSelfContext(ctx context.Context) (*TokenInfo, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	secret, err := c.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, classifyTokenError(err, "lookup self")
	}

	info := parseTokenInfo(secret)
	if info == nil {
		return nil, fmt.Errorf("lookup self failed: vault returned no token data")
	}
	return info, nil
}
