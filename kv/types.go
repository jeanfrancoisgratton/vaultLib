// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: kv/types.go

package kv

import (
	"github.com/hashicorp/vault/api"
	"github.com/jeanfrancoisgratton/vaultlib/v2/shared"
)

// Config is re-exported from shared so client applications can import only the
// kv package without an additional shared import.
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

// Secret is the normalized representation of a Vault KV secret read.
type Secret struct {
	MountPath        string                 `json:"mountPath"`
	Path             string                 `json:"path"`
	RequestedVersion int                    `json:"requestedVersion,omitempty"`
	Version          int                    `json:"version,omitempty"`
	Data             map[string]interface{} `json:"data"`
}

// SecretInfo represents a secret path returned by a recursive list operation.
type SecretInfo struct {
	Path string `json:"path"`

	// Version is only populated for KV v2 when requested.
	Version int `json:"version,omitempty"`
}

// WriteOptions controls KV secret write behavior.
type WriteOptions struct {
	// EnableCAS activates Check-And-Set for KV v2 writes. When true,
	// CASVersion must match the secret's current version number; set
	// CASVersion to 0 to require that the secret does not yet exist.
	// Ignored for KV v1.
	EnableCAS bool `json:"enable_cas,omitempty"`

	// CASVersion is the expected current version for a CAS write. Only
	// meaningful when EnableCAS is true. Ignored for KV v1.
	CASVersion int `json:"cas_version,omitempty"`
}

// DeleteOptions controls KV v2 soft-delete behavior.
type DeleteOptions struct {
	// Versions is the list of KV v2 versions to soft-delete. An empty or nil
	// slice soft-deletes the latest version. Ignored for KV v1.
	Versions []int `json:"versions,omitempty"`
}

// DestroyOptions controls destroy behavior.
type DestroyOptions struct {
	// Version is the KV v2 version to permanently destroy. A value of 0
	// destroys the latest version. For KV v1, destroy is equivalent to a
	// permanent delete and Version is ignored.
	Version int `json:"version,omitempty"`
}

// WriteResult is the normalized result of a successful write operation.
type WriteResult struct {
	MountPath string `json:"mountPath"`
	Path      string `json:"path"`

	// Version is the KV v2 version created by the write. It is always 0 for
	// KV v1, which does not track versions.
	Version int `json:"version,omitempty"`
}

// Client is a Vault KV client that supports both reading and writing. It
// handles KV v1 and KV v2 secret engines and selects the correct API paths
// automatically based on the mount's configuration detected at construction
// time.
type Client struct {
	cfg       shared.Config
	client    *api.Client
	kvVersion int // 1 or 2; detected from sys/mounts on NewClient
}

// BackupEntry represents one secret path and its data as captured at backup time.
// Version is populated for KV v2 mounts; it is informational only and is not
// used during a restore.
type BackupEntry struct {
	Path    string                 `json:"path"`
	Version int                    `json:"version,omitempty"`
	Data    map[string]interface{} `json:"data"`
}

// BackupFile is the top-level structure serialized to the JSON backup file.
type BackupFile struct {
	MountPath string        `json:"mountPath"`
	KVVersion int           `json:"kvVersion"`
	Secrets   []BackupEntry `json:"secrets"`
}
