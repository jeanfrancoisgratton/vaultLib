// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: shared/types.go
// Original timestamp: 2026/04/23 14:36:13

package shared

// Config holds the common Vault connection settings used by vaultLib packages.
//
// MountPath must be the KV v2 mount name, not a full Vault API path. For
// example, if the secret is available through containers/data/monitoring_apps,
// MountPath must be "containers".
type Config struct {
	Address   string `json:"address"`
	Token     string `json:"token"`
	MountPath string `json:"mount_path"`

	// Namespace is optional and is mostly relevant for Vault Enterprise.
	// When omitted, VAULT_NAMESPACE is used if present.
	Namespace string `json:"namespace,omitempty"`

	// TLS options mirror the common Vault client environment variables.
	// CACertPath maps to VAULT_CACERT, CAPath maps to VAULT_CAPATH,
	// ClientCertPath maps to VAULT_CLIENT_CERT, ClientKeyPath maps to
	// VAULT_CLIENT_KEY, and TLSServerName maps to VAULT_TLS_SERVER_NAME.
	CACertPath     string `json:"ca_cert_path,omitempty"`
	CAPath         string `json:"ca_path,omitempty"`
	ClientCertPath string `json:"client_cert_path,omitempty"`
	ClientKeyPath  string `json:"client_key_path,omitempty"`
	TLSServerName  string `json:"tls_server_name,omitempty"`

	// TLSSkipVerify disables TLS certificate verification. It exists for
	// compatibility with Vault's VAULT_SKIP_VERIFY behavior, but it should not be
	// used in production unless there is no sane alternative.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`

	// TimeoutSeconds optionally overrides the Vault API client's HTTP timeout.
	// A value of 0 keeps the Vault API client's default timeout.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}
