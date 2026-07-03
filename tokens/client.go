// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/client.go

package tokens

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a reusable Vault client scoped to token operations.
func NewClient(cfg Config) (*Client, error) {
	resolved, err := cfg.Resolved()
	if err != nil {
		return nil, err
	}

	apiConfig := api.DefaultConfig()
	apiConfig.Address = resolved.Address

	if resolved.TimeoutSeconds < 0 {
		return nil, fmt.Errorf("invalid Vault timeout: TimeoutSeconds cannot be negative")
	}
	if resolved.TimeoutSeconds > 0 {
		apiConfig.Timeout = time.Duration(resolved.TimeoutSeconds) * time.Second
	}

	if hasTLSSettings(resolved) {
		tlsConfig := &api.TLSConfig{
			CACert:        resolved.CACertPath,
			CAPath:        resolved.CAPath,
			ClientCert:    resolved.ClientCertPath,
			ClientKey:     resolved.ClientKeyPath,
			TLSServerName: resolved.TLSServerName,
			Insecure:      resolved.TLSSkipVerify,
		}
		if err := apiConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("vault TLS configuration failed: %w", err)
		}
	}

	apiClient, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("vault client creation failed: %w", err)
	}
	if resolved.Token != "" {
		apiClient.SetToken(resolved.Token)
	}
	if resolved.Namespace != "" {
		apiClient.SetNamespace(resolved.Namespace)
	}

	return &Client{cfg: resolved, client: apiClient}, nil
}

// CreateToken is a convenience helper for one-shot token creation. Reuse
// NewClient when performing multiple token operations.
func CreateToken(cfg Config, opts CreateOptions) (*TokenAuth, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.CreateToken(opts)
}

// LookupToken is a convenience helper for one-shot token lookups.
func LookupToken(cfg Config, token string) (*TokenInfo, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.LookupToken(token)
}

// LookupSelf is a convenience helper for one-shot self lookups.
func LookupSelf(cfg Config) (*TokenInfo, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.LookupSelf()
}

// RenewToken is a convenience helper for one-shot token renewals.
func RenewToken(cfg Config, token string, increment int) (*TokenAuth, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.RenewToken(token, increment)
}

// RevokeToken is a convenience helper for one-shot token revocation.
func RevokeToken(cfg Config, token string) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.RevokeToken(token)
}

// ListAccessors is a convenience helper for one-shot accessor listings.
func ListAccessors(cfg Config) ([]string, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ListAccessors()
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

func hasTLSSettings(cfg Config) bool {
	return cfg.CACertPath != "" ||
		cfg.CAPath != "" ||
		cfg.ClientCertPath != "" ||
		cfg.ClientKeyPath != "" ||
		cfg.TLSServerName != "" ||
		cfg.TLSSkipVerify
}
