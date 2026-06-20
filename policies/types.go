// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/types.go

package policies

import (
	"github.com/hashicorp/vault/api"
	"github.com/jeanfrancoisgratton/vaultLib/shared"
)

// Config is a type alias for shared.SystemConfig. Policy operations target
// Vault's sys/policies/acl API, which is not mount-scoped, so — like
// admin.AdminConfig — Config has no MountPath field.
type Config = shared.SystemConfig

// Policy is the normalized representation of a single Vault ACL policy, as
// returned by ReadPolicy.
type Policy struct {
	// Name is the policy name.
	Name string `json:"name"`

	// Rules is the raw policy document, in HCL or JSON, exactly as stored in
	// Vault.
	Rules string `json:"rules"`
}

// Client is a thin Vault client scoped to ACL policy operations.
type Client struct {
	cfg    Config
	client *api.Client
}
