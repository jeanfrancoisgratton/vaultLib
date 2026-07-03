// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/create.go

package tokens

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

// CreateToken creates a new Vault token according to opts.
//
// Routing: if opts.RoleName is set, the token is created against
// auth/token/create/<role>, which takes precedence over opts.Orphan since a
// role's own constraints (including whether it produces orphan tokens)
// govern the result. Otherwise, opts.Orphan selects between
// auth/token/create-orphan and auth/token/create.
func (c *Client) CreateToken(opts CreateOptions) (*TokenAuth, error) {
	return c.CreateTokenContext(context.Background(), opts)
}

// CreateTokenContext creates a new Vault token using the supplied context.
func (c *Client) CreateTokenContext(ctx context.Context, opts CreateOptions) (*TokenAuth, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	req := &api.TokenCreateRequest{
		ID:              strings.TrimSpace(opts.ID),
		Policies:        opts.Policies,
		Metadata:        opts.Metadata,
		TTL:             strings.TrimSpace(opts.TTL),
		ExplicitMaxTTL:  strings.TrimSpace(opts.ExplicitMaxTTL),
		Period:          strings.TrimSpace(opts.Period),
		NoDefaultPolicy: opts.NoDefaultPolicy,
		DisplayName:     strings.TrimSpace(opts.DisplayName),
		NumUses:         opts.NumUses,
		Renewable:       opts.Renewable,
		Type:            strings.TrimSpace(opts.Type),
		EntityAlias:     strings.TrimSpace(opts.EntityAlias),
	}

	var (
		secret *api.Secret
		err    error
	)

	roleName := strings.TrimSpace(opts.RoleName)
	switch {
	case roleName != "":
		secret, err = c.client.Auth().Token().CreateWithRoleWithContext(ctx, req, roleName)
	case opts.Orphan:
		secret, err = c.client.Auth().Token().CreateOrphanWithContext(ctx, req)
	default:
		secret, err = c.client.Auth().Token().CreateWithContext(ctx, req)
	}
	if err != nil {
		return nil, classifyTokenError(err, "create token")
	}

	result := parseTokenAuth(secret)
	if result == nil {
		return nil, fmt.Errorf("create token failed: vault returned no auth block")
	}
	return result, nil
}
