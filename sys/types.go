// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: sys/types.go

package sys

import (
	"github.com/hashicorp/vault/api"
	"github.com/jeanfrancoisgratton/vaultlib/v2/shared"
)

// Config is a type alias for shared.SystemConfig. Mount operations target
// Vault's sys/mounts API, which is not mount-scoped in the same sense as a
// KV engine itself, so — like admin.AdminConfig — Config has no MountPath
// field; each method takes the target mount path as an argument instead.
type Config = shared.SystemConfig

// MountInfo is the normalized representation of a single secret engine
// mount, as returned by ListMounts.
type MountInfo struct {
	Path            string            `json:"path"`
	Type            string            `json:"type"`
	Description     string            `json:"description,omitempty"`
	Accessor        string            `json:"accessor,omitempty"`
	Local           bool              `json:"local,omitempty"`
	SealWrap        bool              `json:"seal_wrap,omitempty"`
	Options         map[string]string `json:"options,omitempty"`
	DefaultLeaseTTL int               `json:"default_lease_ttl_seconds,omitempty"`
	MaxLeaseTTL     int               `json:"max_lease_ttl_seconds,omitempty"`

	// KVVersion is populated only when Type is "kv", parsed from
	// Options["version"]. It is empty for non-KV mounts.
	KVVersion string `json:"kv_version,omitempty"`
}

// EnableKVOptions controls creation of a new KV secrets engine mount via
// EnableKVEngine.
type EnableKVOptions struct {
	// Version selects the KV engine version: 1 or 2. A value of 0 defaults
	// to 2, matching Vault CLI's own default for `vault secrets enable kv`.
	Version int

	Description     string
	DefaultLeaseTTL string // duration string, e.g. "768h"; empty uses the system default.
	MaxLeaseTTL     string
	Local           bool
}

// EditKVOptions controls tuning of an existing KV secrets engine mount via
// EditKVEngine. Only non-nil fields are sent to Vault, so a field left nil
// leaves that setting unchanged on the mount — the same nil-means-unset
// preference already used in kv.WriteOptions (EnableCAS/CASVersion) rather
// than a sentinel value.
type EditKVOptions struct {
	Description       *string
	DefaultLeaseTTL   *string
	MaxLeaseTTL       *string
	ListingVisibility *string
}

// Client is a thin Vault client scoped to system-level mount operations.
type Client struct {
	cfg    Config
	client *api.Client
}
