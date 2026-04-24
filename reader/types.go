// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: reader/types.go
// Original timestamp: 2026/04/23 14:34:48

package reader

import (
	"github.com/hashicorp/vault/api"
	"github.com/jeanfrancoisgratton/vaultLib/shared"
)

// Config is re-exported from shared so client applications can import only the
// reader package for common read-only use cases.
type Config = shared.Config

// ReadOptions controls KV v2 read behavior.
type ReadOptions struct {
	// Version selects a specific KV v2 version. Version 0 means "latest".
	Version int `json:"version,omitempty"`

	// FallbackToLatestAvailable makes a latest-version read recover from a nil
	// latest read by inspecting KV metadata and reading the newest version that is
	// neither soft-deleted nor destroyed. This requires read permission on the KV
	// metadata path. It is disabled by default to avoid surprising policy
	// requirements and silent fallback behavior.
	FallbackToLatestAvailable bool `json:"fallback_to_latest_available,omitempty"`
}

// Secret is the normalized representation of a Vault KV v2 secret read.
type Secret struct {
	MountPath        string                 `json:"mountPath"`
	Path             string                 `json:"path"`
	RequestedVersion int                    `json:"requestedVersion,omitempty"`
	Version          int                    `json:"version,omitempty"`
	Data             map[string]interface{} `json:"data"`
}

// Client is a small KV v2 reader around HashiCorp Vault's official API client.
type Client struct {
	cfg    shared.Config
	client *api.Client
}
