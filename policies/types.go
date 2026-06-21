// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/types.go

package policies

import (
	"strings"

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

// RuleLines splits Rules into individual lines for display purposes — e.g.
// table cells, log output, or anywhere a single embedded-newline string
// renders poorly.
//
// This is a display convenience only. It does no HCL/JSON parsing and has
// no notion of path blocks, capabilities, or Vault's policy grammar; it
// does not tell you what a policy grants, only how to lay its raw text out
// one line at a time. Rules remains the canonical, wire-faithful
// representation (and the one CreatePolicy expects back). Callers needing
// real structural or access-decision information should treat Rules as the
// source of truth and consult Vault itself rather than this method.
//
// RuleLines returns nil if Rules is empty. A single trailing newline (or
// CRLF) is trimmed so callers don't get a spurious empty final line; any
// CR left at the end of interior lines (CRLF-authored documents) is also
// stripped.
func (p *Policy) RuleLines() []string {
	if p == nil || p.Rules == "" {
		return nil
	}

	trimmed := strings.TrimRight(p.Rules, "\r\n")
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// Client is a thin Vault client scoped to ACL policy operations.
type Client struct {
	cfg    Config
	client *api.Client
}
