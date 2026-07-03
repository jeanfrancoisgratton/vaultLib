// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/types.go

package tokens

import (
	"github.com/hashicorp/vault/api"
	"github.com/jeanfrancoisgratton/vaultLib/shared"
)

// Config is a type alias for shared.SystemConfig. Token operations target
// Vault's auth/token API, which is not mount-scoped, so — like
// admin.AdminConfig — Config has no MountPath field.
type Config = shared.SystemConfig

// CreateOptions controls token creation behavior.
type CreateOptions struct {
	// ID optionally sets a specific token value (e.g. for predictable test
	// tokens). Requires the "sudo" capability. Leave empty to let Vault
	// generate one.
	ID string `json:"id,omitempty"`

	// Policies lists the policies to attach to the new token.
	Policies []string `json:"policies,omitempty"`

	// Metadata is arbitrary key/value data attached to the token, surfaced in
	// the audit log.
	Metadata map[string]string `json:"metadata,omitempty"`

	// TTL is the initial TTL of the token, as a duration string (e.g. "1h").
	// Empty uses the system or mount default.
	TTL string `json:"ttl,omitempty"`

	// ExplicitMaxTTL, if set, hard-caps the token's TTL regardless of
	// renewals, as a duration string.
	ExplicitMaxTTL string `json:"explicit_max_ttl,omitempty"`

	// Period, if set, makes the token periodic: each renewal resets the TTL
	// to this duration instead of decaying the remaining time.
	Period string `json:"period,omitempty"`

	// DisplayName is a human-friendly name surfaced in Vault's token store
	// and audit log.
	DisplayName string `json:"display_name,omitempty"`

	// NumUses limits the token to a fixed number of uses before it is
	// automatically revoked. 0 means unlimited.
	NumUses int `json:"num_uses,omitempty"`

	// Renewable controls whether the token can be renewed. A nil value lets
	// Vault apply its own default (renewable) rather than forcing a value;
	// this follows the same pointer-over-sentinel preference used elsewhere
	// in this library (see kv.WriteOptions.EnableCAS for the analogous
	// reasoning for booleans that have a meaningful "unset" state).
	Renewable *bool `json:"renewable,omitempty"`

	// Type selects "service" (default) or "batch" tokens. Empty uses Vault's
	// default ("service").
	Type string `json:"type,omitempty"`

	// EntityAlias associates the token with an existing identity entity
	// alias. Requires the token to be created against a role that allows it.
	EntityAlias string `json:"entity_alias,omitempty"`

	// NoDefaultPolicy excludes the "default" policy from the new token.
	NoDefaultPolicy bool `json:"no_default_policy,omitempty"`

	// Orphan creates the token without a parent, so it survives revocation of
	// the calling token's tree. Calls auth/token/create-orphan instead of
	// auth/token/create. Ignored when RoleName is set.
	Orphan bool `json:"orphan,omitempty"`

	// RoleName, if set, creates the token against auth/token/create/<role>
	// instead of the generic create endpoint, applying that role's
	// constraints. Takes precedence over Orphan.
	RoleName string `json:"role_name,omitempty"`
}

// TokenAuth is the normalized auth block returned by a token create or renew
// operation. It mirrors the fields Vault actually returns under "auth" in
// those responses.
type TokenAuth struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies,omitempty"`
	TokenPolicies []string          `json:"token_policies,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	LeaseDuration int               `json:"lease_duration,omitempty"`
	Renewable     bool              `json:"renewable,omitempty"`
	EntityID      string            `json:"entity_id,omitempty"`
	Orphan        bool              `json:"orphan,omitempty"`
}

// TokenInfo is the normalized result of a token lookup, whether by token
// value (LookupToken) or for the calling token itself (LookupSelf).
type TokenInfo struct {
	// ID is the token value itself. It is only populated by LookupToken and
	// LookupSelf — Vault never returns the token value for an
	// accessor-scoped lookup, by design, since the accessor exists precisely
	// so token identity can be referenced without exposing the secret.
	ID string `json:"id,omitempty"`

	Accessor       string            `json:"accessor"`
	CreationTime   int64             `json:"creation_time,omitempty"`
	CreationTTL    int64             `json:"creation_ttl,omitempty"`
	TTL            int64             `json:"ttl,omitempty"`
	ExplicitMaxTTL int64             `json:"explicit_max_ttl,omitempty"`
	ExpireTime     string            `json:"expire_time,omitempty"`
	IssueTime      string            `json:"issue_time,omitempty"`
	DisplayName    string            `json:"display_name,omitempty"`
	EntityID       string            `json:"entity_id,omitempty"`
	Policies       []string          `json:"policies,omitempty"`
	Meta           map[string]string `json:"meta,omitempty"`
	NumUses        int               `json:"num_uses,omitempty"`
	Orphan         bool              `json:"orphan,omitempty"`
	Renewable      bool              `json:"renewable,omitempty"`
	Path           string            `json:"path,omitempty"`
	Type           string            `json:"type,omitempty"`
}

// Client is a thin Vault client scoped to token operations.
type Client struct {
	cfg    Config
	client *api.Client
}
