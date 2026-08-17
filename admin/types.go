// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: admin/types.go

package admin

import (
	"github.com/hashicorp/vault/api"
	"github.com/jeanfrancoisgratton/vaultlib/v2/shared"
)

// AdminConfig is a type alias for shared.SystemConfig. It holds the Vault
// connection settings needed for administrative operations. Unlike kv.Config
// it does not require a MountPath, since admin operations target the Vault
// system API rather than a KV engine.
//
// AdminConfig used to be its own struct with its own copy of the
// environment-resolution logic (token, address, namespace, TLS settings).
// That logic was promoted to shared.SystemConfig in v1.6.0 so the policies,
// tokens, and sys subpackages — which are all non-mount-scoped exactly like
// admin — can reuse it instead of duplicating it a third and fourth time.
// This is purely an internal change: AdminConfig's fields, JSON tags, and
// resolution behavior are unchanged, so existing callers are unaffected.
type AdminConfig = shared.SystemConfig

// UnsealResult is the normalized result of a single unseal key submission.
type UnsealResult struct {
	// KeyIndex is the zero-based index of the key within the slice provided to
	// Unseal that produced this result.
	KeyIndex int `json:"key_index"`

	// Sealed reports whether the vault is still sealed after this key was
	// applied. It will be false once the threshold is met.
	Sealed bool `json:"sealed"`

	// Progress is the number of unseal keys applied so far toward the threshold.
	Progress int `json:"progress"`

	// Threshold is the total number of key shares required to unseal.
	Threshold int `json:"threshold"`
}

// SealStatusResult holds the normalized response from the Vault seal-status
// endpoint (GET /v1/sys/seal-status). No token is required to call this
// endpoint.
type SealStatusResult struct {
	// Sealed reports whether the vault is currently sealed.
	Sealed bool `json:"sealed"`

	// TotalShares is the total number of Shamir key shares (n) that exist.
	TotalShares int `json:"total_shares"`

	// Threshold is the minimum number of key shares (t) required to unseal.
	Threshold int `json:"threshold"`

	// Progress is the number of unseal keys applied so far in an in-progress
	// unseal attempt. Resets to 0 once the vault is successfully unsealed or
	// when the attempt is abandoned.
	Progress int `json:"progress"`

	// Initialized reports whether the vault has been initialized.
	Initialized bool `json:"initialized"`

	// ClusterName is the human-readable name of the Vault cluster, if set.
	ClusterName string `json:"cluster_name,omitempty"`

	// ClusterID is the unique identifier of the Vault cluster.
	ClusterID string `json:"cluster_id,omitempty"`

	// RecoverySeal indicates whether recovery seals are enabled (e.g. when
	// using auto-unseal with a cloud KMS).
	RecoverySeal bool `json:"recovery_seal"`

	// StorageType reports the storage backend in use (e.g. "raft", "consul").
	StorageType string `json:"storage_type,omitempty"`

	// HCPLinkStatus is the status of the HCP Link integration, if configured.
	HCPLinkStatus string `json:"hcp_link_status,omitempty"`

	// HCPLinkResourceID is the HCP resource ID associated with the cluster.
	HCPLinkResourceID string `json:"hcp_link_resource_id,omitempty"`
}

// Client is a thin Vault administrative client scoped to system-level
// operations.
type Client struct {
	cfg    AdminConfig
	client *api.Client
}
