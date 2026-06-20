// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/client.go

package policies

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a reusable Vault client scoped to ACL policy operations.
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

// ListPolicies is a convenience helper for one-shot listings. Reuse NewClient
// when performing multiple policy operations.
func ListPolicies(cfg Config) ([]string, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ListPolicies()
}

// ReadPolicy is a convenience helper for one-shot policy reads.
func ReadPolicy(cfg Config, name string) (*Policy, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ReadPolicy(name)
}

// CreatePolicy is a convenience helper for one-shot policy creation.
func CreatePolicy(cfg Config, name, rules string) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.CreatePolicy(name, rules)
}

// DeletePolicy is a convenience helper for one-shot policy deletion.
func DeletePolicy(cfg Config, name string) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.DeletePolicy(name)
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
