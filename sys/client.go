// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: sys/client.go

package sys

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a reusable Vault client scoped to system-level mount
// operations.
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

// ListMounts is a convenience helper for one-shot mount listings. Reuse
// NewClient when performing multiple sys operations.
func ListMounts(cfg Config) ([]MountInfo, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ListMounts()
}

// EnableKVEngine is a convenience helper for one-shot KV engine creation.
func EnableKVEngine(cfg Config, path string, opts EnableKVOptions) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.EnableKVEngine(path, opts)
}

// EditKVEngine is a convenience helper for one-shot KV engine tuning.
func EditKVEngine(cfg Config, path string, opts EditKVOptions) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.EditKVEngine(path, opts)
}

// DisableKVEngine is a convenience helper for one-shot KV engine removal.
func DisableKVEngine(cfg Config, path string) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.DisableKVEngine(path)
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
