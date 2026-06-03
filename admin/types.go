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

// Client is a thin Vault administrative client scoped to system-level
// operations.
type Client struct {
	cfg    AdminConfig
	client *api.Client
}
