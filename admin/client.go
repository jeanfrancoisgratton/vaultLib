// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: admin/client.go

package admin

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a reusable Vault administrative client. A token is not
// required for the unseal operation (Vault accepts unseal requests before a
// token exists), but it is resolved from the environment when present so the
// same AdminConfig can be used for future authenticated admin calls.
func NewClient(cfg AdminConfig) (*Client, error) {
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

// Unseal is a convenience helper for one-shot unseal operations. Reuse
// NewClient when performing multiple administrative operations.
func Unseal(cfg AdminConfig, keys []string) ([]UnsealResult, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.Unseal(keys)
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

func hasTLSSettings(cfg AdminConfig) bool {
	return cfg.CACertPath != "" ||
		cfg.CAPath != "" ||
		cfg.ClientCertPath != "" ||
		cfg.ClientKeyPath != "" ||
		cfg.TLSServerName != "" ||
		cfg.TLSSkipVerify
}
