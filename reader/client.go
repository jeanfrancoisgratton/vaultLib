// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: reader/client.go
// Original timestamp: 2026/04/23 14:32:33

package reader

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a reusable Vault KV v2 reader client.
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
	apiClient.SetToken(resolved.Token)
	if resolved.Namespace != "" {
		apiClient.SetNamespace(resolved.Namespace)
	}

	return &Client{cfg: resolved, client: apiClient}, nil
}

// ReadSecret is a convenience helper for one-shot reads. Reuse NewClient when
// reading more than once.
func ReadSecret(cfg Config, secretPath string, opts ReadOptions) (*Secret, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ReadSecret(secretPath, opts)
}

// ReadSecretField is a convenience helper for one-shot field reads. Version 0
// means latest.
func ReadSecretField(cfg Config, secretPath, field string, version int) (interface{}, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ReadSecretField(secretPath, field, version)
}

func hasTLSSettings(cfg Config) bool {
	return cfg.CACertPath != "" ||
		cfg.CAPath != "" ||
		cfg.ClientCertPath != "" ||
		cfg.ClientKeyPath != "" ||
		cfg.TLSServerName != "" ||
		cfg.TLSSkipVerify
}
