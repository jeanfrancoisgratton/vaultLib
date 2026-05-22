// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: writer/client.go
// Original timestamp: 2026/05/22 09:00:00

package writer

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a reusable Vault KV writer client. It automatically
// detects whether the configured mount is KV v1 or KV v2 by querying
// sys/mounts. If detection fails (e.g. due to insufficient policy), it
// defaults to KV v2.
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

	kvVersion := detectKVVersion(apiClient, resolved.MountPath)

	return &Client{cfg: resolved, client: apiClient, kvVersion: kvVersion}, nil
}

// KVVersion returns the KV engine version (1 or 2) detected for the configured
// mount. The value is set once during NewClient and does not change.
func (c *Client) KVVersion() int {
	return c.kvVersion
}

// WriteSecret is a convenience helper for one-shot full-secret writes. Reuse
// NewClient when writing more than once to the same mount.
func WriteSecret(cfg Config, secretPath string, data map[string]interface{}, opts WriteOptions) (*WriteResult, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.WriteSecret(secretPath, data, opts)
}

// WriteSecretField is a convenience helper for one-shot field upserts.
func WriteSecretField(cfg Config, secretPath, field string, value interface{}) (*WriteResult, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.WriteSecretField(secretPath, field, value)
}

// DeleteSecretField is a convenience helper for one-shot field deletions.
func DeleteSecretField(cfg Config, secretPath, field string) (*WriteResult, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.DeleteSecretField(secretPath, field)
}

// DeleteSecret is a convenience helper for one-shot whole-secret deletions.
func DeleteSecret(cfg Config, secretPath string) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.DeleteSecret(secretPath)
}

// DestroySecret is a convenience helper for one-shot secret destruction.
func DestroySecret(cfg Config, secretPath string, opts DestroyOptions) error {
	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return client.DestroySecret(secretPath, opts)
}

// UpdateSecretField is a convenience helper for one-shot field updates that
// require the field to already exist.
func UpdateSecretField(cfg Config, secretPath, field string, value interface{}) (*WriteResult, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.UpdateSecretField(secretPath, field, value)
}

// detectKVVersion queries sys/mounts to determine whether the mount is KV v1
// or KV v2. It returns 2 if the version cannot be determined.
func detectKVVersion(client *api.Client, mount string) int {
	secret, err := client.Logical().Read("sys/mounts/" + strings.Trim(mount, "/"))
	if err != nil || secret == nil {
		return 2
	}
	opts, _ := secret.Data["options"].(map[string]interface{})
	if opts == nil {
		return 2
	}
	ver, _ := opts["version"].(string)
	if ver == "1" {
		return 1
	}
	return 2
}

func hasTLSSettings(cfg Config) bool {
	return cfg.CACertPath != "" ||
		cfg.CAPath != "" ||
		cfg.ClientCertPath != "" ||
		cfg.ClientKeyPath != "" ||
		cfg.TLSServerName != "" ||
		cfg.TLSSkipVerify
}
