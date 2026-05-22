// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: writer/types.go
// Original timestamp: 2026/05/22 09:00:00

package writer

import (
	"github.com/hashicorp/vault/api"
	"github.com/jeanfrancoisgratton/vaultLib/shared"
)

// Config is re-exported from shared so client applications can import only the
// writer package without an additional shared import.
type Config = shared.Config

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

// Client is a Vault KV writer. It supports both KV v1 and KV v2 secret engines
// and selects the correct API paths automatically based on the mount's
// configuration detected at construction time.
type Client struct {
	cfg       shared.Config
	client    *api.Client
	kvVersion int // 1 or 2; detected from sys/mounts on NewClient
}
