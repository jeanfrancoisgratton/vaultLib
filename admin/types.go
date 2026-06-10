// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: admin/types.go

package admin

import (
	"github.com/hashicorp/vault/api"
)

// AdminConfig holds the Vault connection settings needed for administrative
// operations. Unlike kv.Config it does not require a MountPath, since admin
// operations target the Vault system API rather than a KV engine.
type AdminConfig struct {
	Address   string `json:"address"`
	Token     string `json:"token,omitempty"`
	Namespace string `json:"namespace,omitempty"`

	// TLS options mirror the common Vault client environment variables.
	CACertPath     string `json:"ca_cert_path,omitempty"`
	CAPath         string `json:"ca_path,omitempty"`
	ClientCertPath string `json:"client_cert_path,omitempty"`
	ClientKeyPath  string `json:"client_key_path,omitempty"`
	TLSServerName  string `json:"tls_server_name,omitempty"`

	// TLSSkipVerify disables TLS certificate verification. Should not be used
	// in production.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`

	// TimeoutSeconds optionally overrides the Vault API client HTTP timeout.
	// A value of 0 keeps the Vault API client's default timeout.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

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
