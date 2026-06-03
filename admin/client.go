// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: admin/client.go

package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a reusable Vault administrative client. A token is not
// required for the unseal operation (Vault accepts unseal requests before a
// token exists), but it is resolved from the environment when present so the
// same AdminConfig can be used for future authenticated admin calls.
func NewClient(cfg AdminConfig) (*Client, error) {
	resolved, err := cfg.resolved()
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

// resolved returns a copy of AdminConfig with connection fields filled in
// from environment variables when they were not set explicitly.
func (c AdminConfig) resolved() (AdminConfig, error) {
	r := c.trimmed()

	if r.Address == "" {
		r.Address = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if r.Address == "" {
		return AdminConfig{}, fmt.Errorf("vault address is missing: neither AdminConfig.Address nor VAULT_ADDR provided a usable address")
	}

	// Token is optional for unseal; attempt to resolve it anyway so the client
	// is ready for authenticated follow-up calls.
	if r.Token == "" {
		r.Token = strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	}
	if r.Token == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			data, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
			if err == nil {
				r.Token = strings.TrimSpace(string(data))
			}
		}
	}

	if r.Namespace == "" {
		r.Namespace = strings.TrimSpace(os.Getenv("VAULT_NAMESPACE"))
	}
	if r.CACertPath == "" {
		r.CACertPath = strings.TrimSpace(os.Getenv("VAULT_CACERT"))
	}
	if r.CAPath == "" {
		r.CAPath = strings.TrimSpace(os.Getenv("VAULT_CAPATH"))
	}
	if r.ClientCertPath == "" {
		r.ClientCertPath = strings.TrimSpace(os.Getenv("VAULT_CLIENT_CERT"))
	}
	if r.ClientKeyPath == "" {
		r.ClientKeyPath = strings.TrimSpace(os.Getenv("VAULT_CLIENT_KEY"))
	}
	if r.TLSServerName == "" {
		r.TLSServerName = strings.TrimSpace(os.Getenv("VAULT_TLS_SERVER_NAME"))
	}
	if !r.TLSSkipVerify {
		r.TLSSkipVerify = envBool("VAULT_SKIP_VERIFY")
	}

	return r, nil
}

func (c AdminConfig) trimmed() AdminConfig {
	c.Address = strings.TrimSpace(c.Address)
	c.Token = strings.TrimSpace(c.Token)
	c.Namespace = strings.Trim(strings.TrimSpace(c.Namespace), "/")
	c.CACertPath = strings.TrimSpace(c.CACertPath)
	c.CAPath = strings.TrimSpace(c.CAPath)
	c.ClientCertPath = strings.TrimSpace(c.ClientCertPath)
	c.ClientKeyPath = strings.TrimSpace(c.ClientKeyPath)
	c.TLSServerName = strings.TrimSpace(c.TLSServerName)
	return c
}

func hasTLSSettings(cfg AdminConfig) bool {
	return cfg.CACertPath != "" ||
		cfg.CAPath != "" ||
		cfg.ClientCertPath != "" ||
		cfg.ClientKeyPath != "" ||
		cfg.TLSServerName != "" ||
		cfg.TLSSkipVerify
}

func envBool(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false
	}
	parsed, err := strconv.ParseBool(raw)
	if err == nil {
		return parsed
	}
	switch strings.ToLower(raw) {
	case "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}
