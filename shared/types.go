// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: shared/types.go
// Original timestamp: 2026/04/23 14:36:13

package shared

// Config holds the common Vault connection settings used by sibling packages.
// MountPath is kept here because the current library scope is centered on KV v2,
// and future KV-oriented packages will likely need the same mount reference.
type Config struct {
	Address   string `json:"address"`
	Token     string `json:"token"`
	MountPath string `json:"mount_path"`
}
