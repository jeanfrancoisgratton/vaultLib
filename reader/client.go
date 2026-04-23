// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: reader/client.go
// Original timestamp: 2026/04/23 14:32:33

package reader

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"vaultreader/shared"
)

func NewClient(cfg shared.Config) (*Client, error) {
	resolved, err := cfg.Resolved()
	if err != nil {
		return nil, err
	}

	if resolved.MountPath == "" {
		return nil, fmt.Errorf("kv mount path is missing: Config.MountPath must point to a KV v2 mount")
	}

	apiClient, err := api.NewClient(&api.Config{Address: resolved.Address})
	if err != nil {
		return nil, fmt.Errorf("vault client creation failed: %w", err)
	}
	apiClient.SetToken(resolved.Token)

	return &Client{cfg: resolved, client: apiClient}, nil
}

func ReadSecret(cfg shared.Config, secretPath string, opts ReadOptions) (*Secret, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ReadSecret(secretPath, opts)
}

func ReadSecretField(cfg shared.Config, secretPath, field string, version int) (interface{}, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.ReadSecretField(secretPath, field, version)
}
